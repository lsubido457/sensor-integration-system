require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3001;

// ========== MAILER SETUP ==========
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// ========== UTILITY FUNCTIONS ==========

const normalizePhone = (value = '') => {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length === 11 && digits.startsWith('1')) return digits.slice(1);
  return digits;
};

const normalizeEmail = (value = '') => String(value).trim().toLowerCase();

const toClientEmail = (email) => {
  if (!email) return null;
  return email.endsWith('@local.invalid') ? null : email;
};

const validatePassword = (p) =>
  p.length >= 8 &&
  /[A-Z]/.test(p) &&
  /[a-z]/.test(p) &&
  /[0-9]/.test(p) &&
  /[^A-Za-z0-9]/.test(p);

const MAX_ATTEMPTS = 5;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ========== AUTHENTICATION MIDDLEWARE ==========

const baseAuthenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const authenticateToken = (req, res, next) => {
  baseAuthenticateToken(req, res, () => {
    db.get('SELECT is_active FROM users WHERE id = ?', [req.user.id], (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user || user.is_active === 0) {
        return res.status(403).json({
          error: 'Your account has been deactivated. Please contact the administrator.',
          disabled: true
        });
      }
      next();
    });
  });
};

const requireAdmin = (req, res, next) => {
  db.get('SELECT is_admin FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user || user.is_admin !== 1) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
};

const logAdminAction = (adminId, action, targetUserId, details, ipAddress) => {
  db.run(
    'INSERT INTO activity_logs (user_id, action, target_user_id, details, ip_address) VALUES (?, ?, ?, ?, ?)',
    [adminId, action, targetUserId, details, ipAddress],
    (err) => { if (err) console.error('Error logging admin action:', err); }
  );
};

// ========== AUTHENTICATION ROUTES ==========

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const identifier = String(req.body.identifier || req.body.email || req.body.phone || '').trim();
  const identifierType = req.body.identifierType;

  if (!username || !identifier || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Password does not meet requirements.' });
  }

  const resolvedType = identifierType || (identifier.includes('@') ? 'email' : (/^\d{10}$/.test(identifier) ? 'phone' : null));
  if (!resolvedType || !['email', 'phone'].includes(resolvedType)) {
    return res.status(400).json({ error: 'Identifier must be a 10-digit phone number or an email address.' });
  }

  let email = null;
  let normalizedPhone = null;

  if (resolvedType === 'phone') {
    normalizedPhone = normalizePhone(identifier);
    if (!/^\d{10}$/.test(normalizedPhone)) return res.status(400).json({ error: 'Phone number must be exactly 10 digits.' });
    email = `phone-${normalizedPhone}@local.invalid`;
  } else {
    email = normalizeEmail(identifier);
    if (!email.includes('@')) return res.status(400).json({ error: 'Email must include @.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)',
      [username, email, normalizedPhone, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username, email, or phone already exists' });
          return res.status(500).json({ error: 'Error creating user' });
        }
        const token = jwt.sign({ id: this.lastID, username }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({
          message: 'User created successfully',
          token,
          user: { id: this.lastID, username, email: resolvedType === 'email' ? email : null, phone: normalizedPhone || null, is_admin: 0, must_change_password: 0 }
        });
      }
    );
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// Login handler
const handleLogin = async (req, res, user) => {
  const { password } = req.body;

  if (user.is_active === 0) {
    return res.status(403).json({
      error: 'Your account has been deactivated. Please contact the administrator to reactivate.',
      disabled: true
    });
  }

  if (user.is_locked === 1) {
    return res.status(403).json({
      error: `Account locked after ${MAX_ATTEMPTS} failed attempts. Use "Forgot Password" or contact admin.`,
      locked: true
    });
  }

  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    const newAttempts = (user.failed_attempts || 0) + 1;
    if (newAttempts >= MAX_ATTEMPTS) {
      db.run('UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE id = ?', [newAttempts, user.id]);
      return res.status(403).json({
        error: `Account locked after ${MAX_ATTEMPTS} failed attempts. Use "Forgot Password" or contact admin.`,
        locked: true
      });
    } else {
      db.run('UPDATE users SET failed_attempts = ? WHERE id = ?', [newAttempts, user.id]);
      const left = MAX_ATTEMPTS - newAttempts;
      return res.status(401).json({ error: `Invalid credentials. ${left} attempt${left === 1 ? '' : 's'} left before lockout.` });
    }
  }

  db.run('UPDATE users SET failed_attempts = 0, is_locked = 0, last_login = ? WHERE id = ?', [new Date().toISOString(), user.id]);

  const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

  res.json({
    message: 'Login successful',
    token,
    user: {
      id: user.id,
      username: user.username,
      email: toClientEmail(user.email),
      phone: user.phone || null,
      is_admin: user.is_admin || 0,
      must_change_password: user.must_change_password || 0
    }
  });
};

// Login
app.post('/api/auth/login', (req, res) => {
  const identifier = (req.body.identifier || req.body.phone || req.body.email || '').trim();
  const identifierType = req.body.identifierType;
  const { password } = req.body;

  if (!identifier || !password) return res.status(400).json({ error: 'Identifier and password required' });

  const normalized = normalizePhone(identifier);
  const inferredType = identifier.includes('@') ? 'email' : (normalized.length === 10 ? 'phone' : null);
  const resolvedType = identifierType || inferredType;
  const isPhone = resolvedType === 'phone';

  if (!resolvedType) return res.status(400).json({ error: 'Identifier must be a 10-digit phone number or an email address.' });

  if (!isPhone) {
    const normalizedEmail = normalizeEmail(identifier);
    return db.get('SELECT * FROM users WHERE LOWER(email) = ?', [normalizedEmail], async (err, user) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
      return handleLogin(req, res, user);
    });
  }

  db.get('SELECT * FROM users WHERE phone = ?', [normalized], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (user) return handleLogin(req, res, user);
    const strippedExpr = "REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(phone, '-', ''), '(', ''), ')', ''), ' ', ''), '+', ''), '.', '')";
    db.get(`SELECT * FROM users WHERE ${strippedExpr} IN (?, ?)`, [normalized, `1${normalized}`], async (fallbackErr, fallbackUser) => {
      if (fallbackErr) return res.status(500).json({ error: 'Server error' });
      if (!fallbackUser) return res.status(401).json({ error: 'Invalid credentials' });
      return handleLogin(req, res, fallbackUser);
    });
  });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get('SELECT id, username, email, phone, is_admin, must_change_password FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json({ ...user, email: toClientEmail(user.email) });
  });
});

// ========== FORGOT PASSWORD ==========

app.post('/api/auth/forgot-password', (req, res) => {
  const identifier = (req.body.identifier || '').trim();
  if (!identifier) return res.status(400).json({ error: 'Email or phone required' });

  const isEmail = identifier.includes('@');
  const query = isEmail ? 'SELECT * FROM users WHERE LOWER(email) = ?' : 'SELECT * FROM users WHERE phone = ?';
  const param = isEmail ? identifier.toLowerCase() : normalizePhone(identifier);

  db.get(query, [param], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!user) return res.status(404).json({ error: 'No account found with that email or phone.' });
    if (user.is_active === 0) return res.status(403).json({ error: 'This account has been deactivated. Contact the administrator.' });

    try {
      const tempPassword = 'Temp' + Math.random().toString(36).substring(2, 10) + '!';
      const hashedPassword = await bcrypt.hash(tempPassword, 10);

      db.run(
        'UPDATE users SET password = ?, must_change_password = 1, is_locked = 0, failed_attempts = 0 WHERE id = ?',
        [hashedPassword, user.id],
        async (err) => {
          if (err) return res.status(500).json({ error: 'Error resetting password' });

          const displayContact = toClientEmail(user.email) || (user.phone ? `Phone: ${user.phone}` : 'N/A');

          try {
            await mailer.sendMail({
              from: `"Sensor System" <${process.env.GMAIL_USER}>`,
              to: process.env.GMAIL_USER,
              subject: `🔑 Password Reset Request — ${user.username}`,
              html: `
                <div style="font-family:sans-serif;max-width:520px;margin:auto;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
                  <div style="background:#667eea;padding:20px;color:white;">
                    <h2 style="margin:0">🔑 Password Reset Request</h2>
                  </div>
                  <div style="padding:24px;">
                    <p><strong>Username:</strong> ${user.username}</p>
                    <p><strong>Contact:</strong> ${displayContact}</p>
                    <p style="margin-top:16px;"><strong>Temporary Password:</strong></p>
                    <div style="font-size:26px;font-family:monospace;background:#f0f0f0;padding:14px;border-radius:6px;letter-spacing:4px;text-align:center;margin:10px 0;">${tempPassword}</div>
                    <p style="color:#cc0000;font-size:13px;">⚠️ Share this securely with the user. They will be required to set a new password on next login.</p>
                    <p style="color:#888;font-size:12px;margin-top:20px;">Requested at: ${new Date().toLocaleString()}</p>
                  </div>
                </div>
              `
            });
            res.json({ message: 'A password reset request has been sent to the administrator. Please contact them to get your temporary password, then log in to set a new one.' });
          } catch (emailErr) {
            console.error('Email send error:', emailErr);
            res.status(500).json({ error: 'Password was reset but the notification email failed. Please contact the administrator directly at truhoang1711@gmail.com' });
          }
        }
      );
    } catch { res.status(500).json({ error: 'Server error' }); }
  });
});

// ========== CHANGE PASSWORD ==========

app.post('/api/account/change-password', authenticateToken, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ error: 'New password required' });
  if (!validatePassword(newPassword)) return res.status(400).json({ error: 'Password does not meet all requirements.' });

  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?', [hashed, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Error changing password' });
      res.json({ message: 'Password changed successfully.' });
    });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ========== SELF DEACTIVATE ==========

app.post('/api/account/deactivate', authenticateToken, (req, res) => {
  db.run(
    'UPDATE users SET is_active = 0, disabled_at = ?, disabled_by = NULL WHERE id = ?',
    [new Date().toISOString(), req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Error deactivating account' });
      res.json({ message: 'Account deactivated. It will be permanently deleted after 2 months unless reactivated by an admin.' });
    }
  );
});

// ========== DEVICE ROUTES ==========

app.get('/api/devices', authenticateToken, (req, res) => {
  db.all('SELECT * FROM devices WHERE user_id = ?', [req.user.id], (err, devices) => {
    if (err) return res.status(500).json({ error: 'Error fetching devices' });
    res.json(devices);
  });
});

app.post('/api/devices', authenticateToken, (req, res) => {
  const { device_name, device_type, device_id } = req.body;
  if (!device_name || !device_type || !device_id) return res.status(400).json({ error: 'All fields are required' });
  db.run(
    'INSERT INTO devices (user_id, device_name, device_type, device_id, status) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, device_name, device_type, device_id, 'online'],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Device ID already exists' });
        return res.status(500).json({ error: 'Error adding device' });
      }
      res.status(201).json({ message: 'Device added successfully', device: { id: this.lastID, device_name, device_type, device_id, status: 'online' } });
    }
  );
});

app.delete('/api/devices/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM devices WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'Error deleting device' });
    if (this.changes === 0) return res.status(404).json({ error: 'Device not found' });
    res.json({ message: 'Device deleted successfully' });
  });
});

// ========== SENSOR DATA ROUTES ==========

app.get('/api/sensor-data/:deviceId', authenticateToken, (req, res) => {
  const { deviceId } = req.params;
  const limit = req.query.limit || 50;
  db.get('SELECT * FROM devices WHERE device_id = ? AND user_id = ?', [deviceId, req.user.id], (err, device) => {
    if (err || !device) return res.status(404).json({ error: 'Device not found' });
    db.all('SELECT * FROM sensor_data WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?', [deviceId, limit], (err, data) => {
      if (err) return res.status(500).json({ error: 'Error fetching sensor data' });
      res.json(data);
    });
  });
});

app.post('/api/demo/generate-data/:deviceId', authenticateToken, (req, res) => {
  const { deviceId } = req.params;
  const temperature = (Math.random() * 15 + 18).toFixed(2);
  const humidity = (Math.random() * 30 + 40).toFixed(2);
  const pressure = (Math.random() * 50 + 980).toFixed(2);
  db.run('INSERT INTO sensor_data (device_id, temperature, humidity, pressure) VALUES (?, ?, ?, ?)', [deviceId, temperature, humidity, pressure], function(err) {
    if (err) return res.status(500).json({ error: 'Error generating data' });
    res.json({ temperature, humidity, pressure });
  });
});

// ========== ADMIN ROUTES ==========

app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  db.all(`
    SELECT u.id, u.username, u.email, u.phone,
      u.is_admin, u.is_active, u.is_locked, u.created_at,
      COUNT(d.id) as device_count
    FROM users u
    LEFT JOIN devices d ON u.id = d.user_id
    GROUP BY u.id ORDER BY u.created_at DESC
  `, (err, users) => {
    if (err) return res.status(500).json({ error: 'Error fetching users' });
    res.json(users.map(u => ({ ...u, email: toClientEmail(u.email) })));
  });
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
  const stats = {};
  db.get('SELECT COUNT(*) as count FROM users', (err, r) => {
    stats.totalUsers = r ? r.count : 0;
    db.get('SELECT COUNT(*) as count FROM devices', (err, r) => {
      stats.totalDevices = r ? r.count : 0;
      db.get('SELECT COUNT(*) as count FROM sensor_data', (err, r) => {
        stats.totalReadings = r ? r.count : 0;
        db.get("SELECT COUNT(*) as count FROM users WHERE DATE(created_at) = DATE('now')", (err, r) => {
          stats.newUsersToday = r ? r.count : 0;
          db.get("SELECT COUNT(*) as count FROM users WHERE is_locked = 1", (err, r) => {
            stats.lockedAccounts = r ? r.count : 0;
            db.get("SELECT COUNT(*) as count FROM users WHERE is_active = 0 AND disabled_by IS NULL", (err, r) => {
              stats.deactivatedAccounts = r ? r.count : 0;
              res.json(stats);
            });
          });
        });
      });
    });
  });
});

app.get('/api/admin/users/:id/details', authenticateToken, requireAdmin, (req, res) => {
  db.get(`
    SELECT u.id, u.username, u.email, u.phone, u.is_admin, u.is_active, u.is_locked,
      u.failed_attempts, u.created_at, u.last_login, u.disabled_at, u.must_change_password,
      disabler.username as disabled_by_username,
      COUNT(DISTINCT d.id) as device_count,
      COUNT(DISTINCT sd.id) as reading_count
    FROM users u
    LEFT JOIN devices d ON u.id = d.user_id
    LEFT JOIN sensor_data sd ON d.device_id = sd.device_id
    LEFT JOIN users disabler ON u.disabled_by = disabler.id
    WHERE u.id = ? GROUP BY u.id
  `, [req.params.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Error fetching user details' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ ...user, email: toClientEmail(user.email) });
  });
});

app.patch('/api/admin/users/:id/toggle-active', authenticateToken, requireAdmin, (req, res) => {
  const targetUserId = req.params.id;
  const adminId = req.user.id;
  if (parseInt(targetUserId) === adminId) return res.status(400).json({ error: 'Cannot disable your own account' });
  db.get('SELECT is_active, username, email FROM users WHERE id = ?', [targetUserId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    const newStatus = user.is_active === 1 ? 0 : 1;
    db.run(
      'UPDATE users SET is_active = ?, disabled_at = ?, disabled_by = ? WHERE id = ?',
      [newStatus, newStatus === 0 ? new Date().toISOString() : null, newStatus === 0 ? adminId : null, targetUserId],
      function(err) {
        if (err) return res.status(500).json({ error: 'Error updating user status' });
        logAdminAction(adminId, newStatus === 0 ? 'DISABLED_USER' : 'ENABLED_USER', targetUserId, JSON.stringify({ username: user.username }), req.ip);
        res.json({ message: `User ${newStatus === 0 ? 'disabled' : 'enabled'} successfully`, is_active: newStatus });
      }
    );
  });
});

app.patch('/api/admin/users/:id/unlock', authenticateToken, requireAdmin, (req, res) => {
  db.run('UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Error unlocking account' });
    logAdminAction(req.user.id, 'UNLOCKED_USER', req.params.id, null, req.ip);
    res.json({ message: 'Account unlocked successfully' });
  });
});

app.post('/api/admin/users/:id/reset-password', authenticateToken, requireAdmin, async (req, res) => {
  const targetUserId = req.params.id;
  const adminId = req.user.id;
  if (parseInt(targetUserId) === adminId) return res.status(400).json({ error: 'Use profile settings to change your own password' });
  db.get('SELECT username, email FROM users WHERE id = ?', [targetUserId], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    try {
      const tempPassword = 'Temp' + Math.random().toString(36).substring(2, 10) + '!';
      const hashedPassword = await bcrypt.hash(tempPassword, 10);
      db.run('UPDATE users SET password = ?, must_change_password = 1, is_locked = 0, failed_attempts = 0 WHERE id = ?', [hashedPassword, targetUserId], function(err) {
        if (err) return res.status(500).json({ error: 'Error resetting password' });
        logAdminAction(adminId, 'RESET_PASSWORD', targetUserId, JSON.stringify({ username: user.username }), req.ip);
        res.json({ message: 'Password reset successfully', tempPassword, username: user.username, email: toClientEmail(user.email), note: 'Share this securely. User must set a new password on next login.' });
      });
    } catch { res.status(500).json({ error: 'Error resetting password' }); }
  });
});

app.delete('/api/admin/users/:id/permanent-delete', authenticateToken, requireAdmin, (req, res) => {
  const targetUserId = req.params.id;
  const adminId = req.user.id;
  if (parseInt(targetUserId) === adminId) return res.status(400).json({ error: 'Cannot delete your own account' });
  db.get('SELECT username, email FROM users WHERE id = ?', [targetUserId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    db.run('DELETE FROM users WHERE id = ?', [targetUserId], function(err) {
      if (err) return res.status(500).json({ error: 'Error deleting user' });
      logAdminAction(adminId, 'PERMANENT_DELETE', targetUserId, JSON.stringify({ username: user.username }), req.ip);
      res.json({ message: 'User and all data deleted permanently' });
    });
  });
});

app.get('/api/admin/activity-logs', authenticateToken, requireAdmin, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  db.all(`
    SELECT al.*, u1.username as admin_username, u2.username as target_username
    FROM activity_logs al
    LEFT JOIN users u1 ON al.user_id = u1.id
    LEFT JOIN users u2 ON al.target_user_id = u2.id
    ORDER BY al.timestamp DESC LIMIT ?
  `, [limit], (err, logs) => {
    if (err) return res.status(500).json({ error: 'Error fetching logs' });
    res.json(logs);
  });
});

// ========== SETUP ==========

app.post('/api/setup-admin', async (req, res) => {
  const { email, secret } = req.body;
  if (secret !== 'MAKE_ME_ADMIN_2024') return res.status(403).json({ error: 'Invalid secret' });
  db.run('UPDATE users SET is_admin = 1 WHERE email = ?', [email], function(err) {
    if (err) return res.status(500).json({ error: 'Error' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'You are now an ADMIN!' });
  });
});

// ========== 2-MONTH CLEANUP JOB ==========

function runCleanupJob() {
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - 2);
  db.run(
    "DELETE FROM users WHERE is_active = 0 AND disabled_by IS NULL AND disabled_at < ?",
    [cutoff.toISOString()],
    function(err) {
      if (err) console.error('Cleanup job error:', err);
      else if (this.changes > 0) console.log(`[Cleanup] Deleted ${this.changes} self-deactivated account(s) older than 2 months`);
    }
  );
}
runCleanupJob();
setInterval(runCleanupJob, 24 * 60 * 60 * 1000);

// ========== START ==========

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop');
});