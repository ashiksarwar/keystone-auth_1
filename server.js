// Keystone auth server: Express + SQLite + bcrypt + server-side sessions.
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22.13+, no native add-on to compile

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'keystone.db');
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_DAYS = 30;
const COOKIE = 'ks_session';

// ---------- database ----------
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    login_count   INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
`);

const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'),
  markLogin: db.prepare('UPDATE users SET last_login_at = ?, login_count = login_count + 1 WHERE id = ?'),
  insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'),
  sessionByHash: db.prepare('SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  purgeExpired: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
};

// ---------- helpers ----------
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const newId = () => 'ks_' + crypto.randomBytes(9).toString('base64url');
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// A real hash to compare against when the email is unknown, so timing doesn't reveal which emails exist.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, createdAt: u.created_at, lastLoginAt: u.last_login_at, loginCount: u.login_count };
}

function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  const expires = now + SESSION_DAYS * 864e5;
  q.insertSession.run(sha256(token), userId, now, expires); // only the hash is stored
  res.cookie(COOKIE, token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', expires: new Date(expires), path: '/' });
}

// Simple in-memory limiter: max N attempts per key per window.
function limiter(max, windowMs) {
  const hits = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, windowMs).unref();
  return (req, res, next) => {
    const key = req.ip + ':' + req.path;
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.reset < now) { h = { count: 0, reset: now + windowMs }; hits.set(key, h); }
    if (++h.count > max) {
      res.set('Retry-After', Math.ceil((h.reset - now) / 1000));
      return res.status(429).json({ error: 'Too many attempts. Wait a few minutes and try again.' });
    }
    next();
  };
}
const authLimiter = limiter(10, 15 * 60 * 1000);

// ---------- app ----------
const app = express();
if (IS_PROD) app.set('trust proxy', 1); // Render/Railway sit behind a proxy
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'",
  });
  next();
});

// CSRF guard: state-changing API calls must be JSON (browsers can't send that cross-site without CORS).
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && !req.is('application/json')) return res.status(415).json({ error: 'Send requests as JSON.' });
  next();
});

function auth(req, res, next) {
  const token = req.cookies[COOKIE];
  if (!token) return res.status(401).json({ error: 'Not signed in.' });
  const s = q.sessionByHash.get(sha256(token), Date.now());
  if (!s) { res.clearCookie(COOKIE, { path: '/' }); return res.status(401).json({ error: 'Your session expired. Sign in again.' }); }
  req.user = q.userById.get(s.user_id);
  req.tokenHash = s.token_hash;
  if (!req.user) return res.status(401).json({ error: 'Not signed in.' });
  next();
}

app.post('/api/signup', authLimiter, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const errors = {};
  if (name.length < 2 || name.length > 80) errors.name = 'Enter your full name.';
  if (!EMAIL_RE.test(email) || email.length > 254) errors.email = 'Enter a valid email, like name@example.com.';
  if (password.length < 8 || password.length > 72 || !/[a-z]/i.test(password) || !/\d/.test(password))
    errors.password = 'Use 8–72 characters, including a letter and a number.';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'Check the highlighted fields.', fields: errors });
  if (q.userByEmail.get(email))
    return res.status(409).json({ error: 'An account with this email already exists.', fields: { email: 'An account with this email already exists. Sign in instead.' } });

  const hash = await bcrypt.hash(password, 12);
  const id = newId();
  try {
    q.insertUser.run(id, name, email, hash, Date.now());
  } catch (e) {
    if (/UNIQUE constraint/i.test(String(e.message))) return res.status(409).json({ error: 'An account with this email already exists.' });
    throw e;
  }
  q.markLogin.run(Date.now(), id);
  startSession(res, id);
  res.status(201).json({ user: publicUser(q.userById.get(id)) });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = q.userByEmail.get(email);
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'That email and password don’t match an account. Check both and try again.' });
  const previousLogin = user.last_login_at;
  q.markLogin.run(Date.now(), user.id);
  startSession(res, user.id);
  res.json({ user: { ...publicUser(q.userById.get(user.id)), previousLoginAt: previousLogin } });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies[COOKIE];
  if (token) q.deleteSession.run(sha256(token));
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/logout-all', auth, (req, res) => {
  q.deleteUserSessions.run(req.user.id);
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.post('/api/delete-account', authLimiter, auth, async (req, res) => {
  const ok = await bcrypt.compare(String(req.body.password || ''), req.user.password_hash);
  if (!ok) return res.status(401).json({ error: 'That password is incorrect.' });
  q.deleteUser.run(req.user.id); // sessions cascade
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.get('/healthz', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our side. Try again.' });
});

setInterval(() => q.purgeExpired.run(Date.now()), 60 * 60 * 1000).unref();
app.listen(PORT, () => console.log(`Keystone running on http://localhost:${PORT}`));
