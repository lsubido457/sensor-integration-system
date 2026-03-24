require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('./database');
const path = require('path');
const crypto = require('crypto');

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

// ✅ Always serve homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =================== STRONG PASSWORD POLICY ===================
const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>_\-+=~`[\]\\\/])[^\s]{12,64}$/;

function isStrongPassword(password) {
  return PASSWORD_REGEX.test(password);
}
// =============================================================

// =================== EMAIL / DEVICE HELPERS ===================

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 587),
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || req.ip || 'unknown';
}

function buildDeviceFingerprint(req) {
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'unknown';

  return crypto
    .createHash('sha256')
    .update(`${ip}|${userAgent}`)
    .digest('hex');
}

function recordLoginAttempt({
  userId,
  identifier,
  ipAddress,
  userAgent,
  fingerprint,
  wasSuccessful,
  isNewDevice
}) {
  db.run(
    `INSERT INTO login_attempts
    (user_id, identifier, ip_address, user_agent, device_fingerprint, was_successful, is_new_device)
    VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      userId,
      identifier,
      ipAddress,
      userAgent,
      fingerprint,
      wasSuccessful ? 1 : 0,
      isNewDevice ? 1 : 0
    ],
    (err) => {
      if (err) {
        console.error('Error recording login attempt:', err.message);
      }
    }
  );
}

async function sendFailedLoginAlertEmail({ to, username, ipAddress, userAgent }) {
  if (!to || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.log('Email credentials missing or recipient unavailable. Skipping email alert.');
    return;
  }

  const message = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to,
    subject: 'Security Alert: Failed Login Attempt from a New Device',
    text: `Hello ${username},

We detected a failed login attempt to your account from a new device.

Details:
IP Address: ${ipAddress}
Device / Browser: ${userAgent}
Time: ${new Date().toLocaleString()}

If this was not you, please reset your password immediately.

- Sensor Integration System`
  };

  await transporter.sendMail(message);
}

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
    (err) => {
      if (err) console.error('Error logging admin action:', err);
    }
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

  if (!validatePassword(password) || !isStrongPassword(password)) {
    return res.status(400).json({
      error:
        'Password must be strong and meet all requirements.'
    });
  }

  const resolvedType =
    identifierType ||
    (identifier.includes('@') ? 'email' : /^\d{10}$/.test(identifier) ? 'phone' : null);

  if (!resolvedType || !['email', 'phone'].includes(resolvedType)) {
    return res.status(400).json({
      error: 'Identifier must be a 10-digit phone number or an email address.'
    });
  }

  let email = null;
  let normalizedPhone = null;

  if (resolvedType === 'phone') {
    normalizedPhone = normalizePhone(identifier);
    if (!/^\d{10}$/.test(normalizedPhone)) {
      return res.status(400).json({ error: 'Phone number must be exactly 10 digits.' });
    }
    email = `phone-${normalizedPhone}@local.invalid`;
  } else {
    email = normalizeEmail(identifier);
    if (!email.includes('@')) {
      return res.status(400).json({ error: 'Email must include @.' });
    }
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'Username, email, or phone already exists' });
          }
          return res.status(500).json({ error: 'Error creating user' });
        }

        const token = jwt.sign(
          { id: this.lastID, username },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );

        res.status(201).json({
          message: 'User created successfully',
          token,
          user: {
            id: this.lastID,
            username,
            email: resolvedType === 'email' ? email : null,
            phone: normalizedPhone || null,
            is_admin: 0,
            must_change_password: 0
          }
        });
      }
    );
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const ipAddress = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'unknown';
  const fingerprint = buildDeviceFingerprint(req);

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    db.get(
      'SELECT id FROM login_attempts WHERE user_id = ? AND device_fingerprint = ? LIMIT 1',
      [user.id, fingerprint],
      async (deviceErr, existingDevice) => {
        if (deviceErr) {
          console.error('Error checking device history:', deviceErr.message);
          return res.status(500).json({ error: 'Server error' });
        }

        const isNewDevice = !existingDevice;

        if (user.is_locked === 1) {
          recordLoginAttempt({
            userId: user.id,
            identifier: email,
            ipAddress,
            userAgent,
            fingerprint,
            wasSuccessful: false,
            isNewDevice
          });

          if (isNewDevice) {
            try {
              await sendFailedLoginAlertEmail({
                to: user.email,
                username: user.username,
                ipAddress,
                userAgent
              });
            } catch (mailErr) {
              console.error('Error sending failed login alert:', mailErr.message);
            }
          }

          return res.status(403).json({
            error: 'Account locked due to too many failed attempts.'
          });
        }

        try {
          const validPassword = await bcrypt.compare(password, user.password);

          if (!validPassword) {
            const newAttempts = (user.failed_attempts || 0) + 1;

            recordLoginAttempt({
              userId: user.id,
              identifier: email,
              ipAddress,
              userAgent,
              fingerprint,
              wasSuccessful: false,
              isNewDevice
            });

            if (isNewDevice) {
              try {
                await sendFailedLoginAlertEmail({
                  to: user.email,
                  username: user.username,
                  ipAddress,
                  userAgent
                });
              } catch (mailErr) {
                console.error('Error sending failed login alert:', mailErr.message);
              }
            }

            if (newAttempts >= 3) {
              db.run(
                'UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE id = ?',
                [newAttempts, user.id],
                (updateErr) => {
                  if (updateErr) {
                    console.error('Error locking account:', updateErr);
                  }
                }
              );

              return res.status(403).json({
                error: 'Account locked after 3 failed attempts.'
              });
            }

            db.run(
              'UPDATE users SET failed_attempts = ? WHERE id = ?',
              [newAttempts, user.id],
              (updateErr) => {
                if (updateErr) {
                  console.error('Error updating failed attempts:', updateErr);
                }
              }
            );

            return res.status(401).json({
              error: `Invalid credentials. ${3 - newAttempts} attempts left.`
            });
          }

          db.run(
            'UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE id = ?',
            [user.id],
            (updateErr) => {
              if (updateErr) {
                console.error('Error resetting failed attempts:', updateErr);
              }
            }
          );

          recordLoginAttempt({
            userId: user.id,
            identifier: email,
            ipAddress,
            userAgent,
            fingerprint,
            wasSuccessful: true,
            isNewDevice
          });

          const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
          );

          res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, username: user.username, email: user.email }
          });
        } catch (error) {
          console.error('Login error:', error);
          res.status(500).json({ error: 'Server error' });
        }
      }
    );
  });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, email, phone, is_admin, must_change_password FROM users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      res.json({ ...user, email: toClientEmail(user.email) });
    }
  );
});

// ========== FORGOT PASSWORD ==========

app.post('/api/auth/forgot-password', (req, res) => {
  const identifier = (req.body.identifier || '').trim();
  if (!identifier) return res.status(400).json({ error: 'Email or phone required' });

  const isEmail = identifier.includes('@');
  const query = isEmail
    ? 'SELECT * FROM users WHERE LOWER(email) = ?'
    : 'SELECT * FROM users WHERE phone = ?';
  const param = isEmail ? identifier.toLowerCase() : normalizePhone(identifier);

  db.get(query, [param], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!user) return res.status(404).json({ error: 'No account found with that email or phone.' });
    if (user.is_active === 0) {
      return res.status(403).json({ error: 'This account has been deactivated. Contact the administrator.' });
    }

    try {
      const tempPassword = 'Temp' + Math.random().toString(36).substring(2, 10) + '!';
      const hashedPassword = await bcrypt.hash(tempPassword, 10);

      db.run(
        'UPDATE users SET password = ?, must_change_password = 1, is_locked = 0, failed_attempts = 0 WHERE id = ?',
        [hashedPassword, user.id],
        async (updateErr) => {
          if (updateErr) return res.status(500).json({ error: 'Error resetting password' });

          const displayContact =
            toClientEmail(user.email) || (user.phone ? `Phone: ${user.phone}` : 'N/A');

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

            res.json({
              message:
                'A password reset request has been sent to the administrator. Please contact them to get your temporary password, then log in to set a new one.'
            });
          } catch (emailErr) {
            console.error('Email send error:', emailErr);
            res.status(500).json({
              error:
                'Password was reset but the notification email failed. Please contact the administrator directly at truhoang1711@gmail.com'
            });
          }
        }
      );
    } catch {
      res.status(500).json({ error: 'Server error' });
    }
  });
});

// ========== CHANGE PASSWORD ==========

app.post('/api/account/change-password', authenticateToken, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ error: 'New password required' });
  if (!validatePassword(newPassword) || !isStrongPassword(newPassword)) {
    return res.status(400).json({ error: 'Password does not meet all requirements.' });
  }

  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    db.run(
      'UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?',
      [hashed, req.user.id],
      function (err) {
        if (err) return res.status(500).json({ error: 'Error changing password' });
        res.json({ message: 'Password changed successfully.' });
      }
    );
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// ========== SELF DEACTIVATE ==========

app.post('/api/account/deactivate', authenticateToken, (req, res) => {
  db.run(
    'UPDATE users SET is_active = 0, disabled_at = ?, disabled_by = NULL WHERE id = ?',
    [new Date().toISOString(), req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Error deactivating account' });
      res.json({
        message:
          'Account deactivated. It will be permanently deleted after 2 months unless reactivated by an admin.'
      });
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
  if (!device_name || !device_type || !device_id) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  db.run(
    'INSERT INTO devices (user_id, device_name, device_type, device_id, status) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, device_name, device_type, device_id, 'online'],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(409).json({ error: 'Device ID already exists' });
        }
        return res.status(500).json({ error: 'Error adding device' });
      }

      res.status(201).json({
        message: 'Device added successfully',
        device: {
          id: this.lastID,
          device_name,
          device_type,
          device_id,
          status: 'online'
        }
      });
    }
  );
});

app.delete('/api/devices/:id', authenticateToken, (req, res) => {
  const deviceId = req.params.id;

  db.run(
    'DELETE FROM devices WHERE id = ? AND user_id = ?',
    [deviceId, req.user.id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Error deleting device' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Device not found' });
      }

      res.json({ message: 'Device deleted successfully' });
    }
  );
});

// ========== SENSOR DATA ROUTES ==========

app.get('/api/sensor-data/:deviceId', authenticateToken, (req, res) => {
  const { deviceId } = req.params;
  const limit = parseInt(req.query.limit, 10) || 50;

  db.get(
    'SELECT * FROM devices WHERE device_id = ? AND user_id = ?',
    [deviceId, req.user.id],
    (err, device) => {
      if (err || !device) {
        return res.status(404).json({ error: 'Device not found' });
      }

      db.all(
        'SELECT * FROM sensor_data WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?',
        [deviceId, limit],
        (dataErr, data) => {
          if (dataErr) {
            return res.status(500).json({ error: 'Error fetching sensor data' });
          }
          res.json(data);
        }
      );
    }
  );
});

app.post('/api/demo/generate-data/:deviceId', authenticateToken, (req, res) => {
  const { deviceId } = req.params;

  const temperature = (Math.random() * 15 + 18).toFixed(2);
  const humidity = (Math.random() * 30 + 40).toFixed(2);
  const pressure = (Math.random() * 50 + 980).toFixed(2);

  db.run(
    'INSERT INTO sensor_data (device_id, temperature, humidity, pressure) VALUES (?, ?, ?, ?)',
    [deviceId, temperature, humidity, pressure],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Error generating data' });
      }
      res.json({ temperature, humidity, pressure });
    }
  );
});

// ========== START ==========

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop');
});