require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const winston = require('winston');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('Set SESSION_SECRET in your .env file (at least 32 characters).');
  process.exit(1);
}

fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
fs.mkdirSync(path.join(__dirname, 'logs'), { recursive: true });

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'security.log') }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

const db = new sqlite3.Database(path.join(__dirname, 'data', 'users.db'));
const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (error) {
    if (error) return reject(error);
    resolve({ id: this.lastID, changes: this.changes });
  });
});
const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (error, row) => error ? reject(error) : resolve(row));
});

async function initializeDatabase() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      ...(isProduction ? { upgradeInsecureRequests: [] } : {})
    }
  }
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
if (isProduction) app.set('trust proxy', 1);

app.use(session({
  name: 'secure_login.sid',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.join(__dirname, 'data') }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 30
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait 15 minutes and try again.' }
});
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/verify-2fa', authLimiter);

const registerSchema = Joi.object({
  name: Joi.string().trim().min(2).max(60).required(),
  email: Joi.string().trim().lowercase().email().max(254).required(),
  password: Joi.string().min(8).max(72)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$/)
    .required()
    .messages({ 'string.pattern.base': 'Use uppercase, lowercase, a number and a special character.' })
});
const loginSchema = Joi.object({
  email: Joi.string().trim().lowercase().email().max(254).required(),
  password: Joi.string().min(8).max(72).required()
});
const codeSchema = Joi.object({ code: Joi.string().pattern(/^\d{6}$/).required() });

function validate(schema, data) {
  return schema.validate(data, { abortEarly: true, stripUnknown: true });
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Please log in to continue.' });
  next();
}
function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, twoFactorEnabled: Boolean(user.two_factor_enabled) };
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
}

app.post('/api/register', async (req, res, next) => {
  try {
    const { error, value } = validate(registerSchema, req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });
    const passwordHash = await bcrypt.hash(value.password, 12);
    try {
      const result = await run(
        'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
        [value.name, value.email, passwordHash]
      );
      logger.info('User registered', { userId: result.id });
      res.status(201).json({ message: 'Account created successfully. You can now log in.' });
    } catch (dbError) {
      if (dbError.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ error: 'An account with this email already exists.' });
      throw dbError;
    }
  } catch (error) { next(error); }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const { error, value } = validate(loginSchema, req.body);
    if (error) return res.status(400).json({ error: 'Enter a valid email and password.' });
    const user = await get('SELECT * FROM users WHERE email = ?', [value.email]);
    const passwordMatches = user ? await bcrypt.compare(value.password, user.password_hash) : false;
    if (!passwordMatches) {
      logger.warn('Failed login attempt', { email: value.email });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    if (user.two_factor_enabled) {
      req.session.pending2FAUserId = user.id;
      return res.json({ requires2FA: true, message: 'Enter the 6-digit code from your authenticator app.' });
    }
    await regenerateSession(req);
    req.session.userId = user.id;
    logger.info('User logged in', { userId: user.id });
    res.json({ message: 'Login successful.', user: publicUser(user) });
  } catch (error) { next(error); }
});

app.post('/api/verify-2fa', async (req, res, next) => {
  try {
    const { error, value } = validate(codeSchema, req.body);
    if (error) return res.status(400).json({ error: 'Enter a valid 6-digit code.' });
    const pendingId = req.session.pending2FAUserId;
    if (!pendingId) return res.status(401).json({ error: 'Your verification session expired. Please log in again.' });
    const user = await get('SELECT * FROM users WHERE id = ?', [pendingId]);
    if (!user || !user.two_factor_enabled || !authenticator.check(value.code, user.totp_secret)) {
      logger.warn('Failed 2FA attempt', { userId: pendingId });
      return res.status(401).json({ error: 'Incorrect verification code.' });
    }
    await regenerateSession(req);
    req.session.userId = user.id;
    logger.info('User completed 2FA login', { userId: user.id });
    res.json({ message: 'Login successful.', user: publicUser(user) });
  } catch (error) { next(error); }
});

app.get('/api/me', requireAuth, async (req, res, next) => {
  try {
    const user = await get('SELECT id, name, email, two_factor_enabled FROM users WHERE id = ?', [req.session.userId]);
    if (!user) return req.session.destroy(() => res.status(401).json({ error: 'Session is no longer valid.' }));
    res.json({ user: publicUser(user) });
  } catch (error) { next(error); }
});

app.post('/api/2fa/setup', requireAuth, async (req, res, next) => {
  try {
    const user = await get('SELECT id, email, two_factor_enabled FROM users WHERE id = ?', [req.session.userId]);
    if (user.two_factor_enabled) return res.status(409).json({ error: 'Two-factor authentication is already enabled.' });
    const secret = authenticator.generateSecret();
    req.session.pendingTotpSecret = secret;
    const otpauth = authenticator.keyuri(user.email, 'Secure Login System', secret);
    const qrCode = await QRCode.toDataURL(otpauth);
    res.json({ secret, qrCode, message: 'Scan the QR code, then enter the 6-digit code to enable 2FA.' });
  } catch (error) { next(error); }
});

app.post('/api/2fa/enable', requireAuth, async (req, res, next) => {
  try {
    const { error, value } = validate(codeSchema, req.body);
    if (error || !req.session.pendingTotpSecret) return res.status(400).json({ error: 'Start 2FA setup and enter a valid 6-digit code.' });
    if (!authenticator.check(value.code, req.session.pendingTotpSecret)) return res.status(400).json({ error: 'That code is incorrect. Try again.' });
    await run('UPDATE users SET two_factor_enabled = 1, totp_secret = ? WHERE id = ?', [req.session.pendingTotpSecret, req.session.userId]);
    delete req.session.pendingTotpSecret;
    logger.info('2FA enabled', { userId: req.session.userId });
    res.json({ message: 'Two-factor authentication is now enabled.' });
  } catch (error) { next(error); }
});

app.post('/api/2fa/disable', requireAuth, async (req, res, next) => {
  try {
    const { error, value } = validate(codeSchema, req.body);
    if (error) return res.status(400).json({ error: 'Enter a valid 6-digit code.' });
    const user = await get('SELECT totp_secret, two_factor_enabled FROM users WHERE id = ?', [req.session.userId]);
    if (!user.two_factor_enabled || !authenticator.check(value.code, user.totp_secret)) return res.status(400).json({ error: 'Incorrect code or 2FA is not enabled.' });
    await run('UPDATE users SET two_factor_enabled = 0, totp_secret = NULL WHERE id = ?', [req.session.userId]);
    logger.info('2FA disabled', { userId: req.session.userId });
    res.json({ message: 'Two-factor authentication has been disabled.' });
  } catch (error) { next(error); }
});

app.post('/api/logout', requireAuth, (req, res) => {
  const userId = req.session.userId;
  req.session.destroy(error => {
    if (error) return res.status(500).json({ error: 'Could not log out. Please try again.' });
    res.clearCookie('secure_login.sid', { httpOnly: true, sameSite: 'strict', secure: isProduction });
    logger.info('User logged out', { userId });
    res.json({ message: 'You have been logged out.' });
  });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res) => res.status(404).json({ error: 'Page not found.' }));
app.use((error, req, res, next) => {
  logger.error('Application error', { message: error.message, stack: error.stack });
  res.status(500).json({ error: isProduction ? 'Something went wrong. Please try again later.' : error.message });
});

initializeDatabase().then(() => {
  app.listen(PORT, () => logger.info(`Secure Login System running at http://localhost:${PORT}`));
}).catch(error => {
  logger.error('Database initialization failed', { message: error.message });
  process.exit(1);
});
