const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PORT = process.env.PORT || 3000;
fs.mkdirSync(path.join(DATA_DIR, 'backups'), { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'app.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, hash TEXT, role TEXT DEFAULT 'user');
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, exp INTEGER);
CREATE TABLE IF NOT EXISTS books(id INTEGER PRIMARY KEY CHECK(id=1), state TEXT, ts INTEGER);
`);

const hashPw = p => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const checkPw = (p, h) => { const [s, k] = h.split(':'); const x = crypto.scryptSync(p, s, 64); return crypto.timingSafeEqual(x, Buffer.from(k, 'hex')); };

// First run: create admin
if (!db.prepare('SELECT 1 FROM users').get()) {
  const u = process.env.ADMIN_USER || 'admin', p = process.env.ADMIN_PASS || 'ChangeMe123';
  db.prepare('INSERT INTO users(username,hash,role) VALUES(?,?,?)').run(u, hashPw(p), 'admin');
  console.log(`Admin created: ${u} (change the password after first login)`);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '25mb' }));

const cookie = (req, n) => (req.headers.cookie || '').split(';').map(c => c.trim().split('=')).find(c => c[0] === n)?.[1];
const attempts = {};
function auth(req, res, next) {
  const t = cookie(req, 'sid');
  const row = t && db.prepare('SELECT u.id,u.username,u.role,s.exp FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(t);
  if (!row || row.exp < Date.now()) return req.path.startsWith('/api') ? res.status(401).json({ error: 'auth' }) : res.redirect('/login');
  req.user = row; next();
}
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'admin only' });

app.post('/api/login', (req, res) => {
  const ip = req.ip, a = attempts[ip] || { n: 0, t: Date.now() };
  if (Date.now() - a.t > 15 * 60e3) { a.n = 0; a.t = Date.now(); }
  if (a.n >= 10) return res.status(429).json({ error: 'Too many attempts. Try later.' });
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || ''));
  if (!u || !checkPw(String(password || ''), u.hash)) { a.n++; attempts[ip] = a; return res.status(401).json({ error: 'Wrong username or password' }); }
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(token, u.id, Date.now() + 30 * 864e5);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${req.secure ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.post('/api/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token=?').run(cookie(req, 'sid'));
  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0'); res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json({ username: req.user.username, role: req.user.role }));
app.post('/api/password', auth, (req, res) => {
  const { old, pass } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!pass || pass.length < 6 || !checkPw(String(old || ''), u.hash)) return res.status(400).json({ error: 'bad' });
  db.prepare('UPDATE users SET hash=? WHERE id=?').run(hashPw(pass), u.id); res.json({ ok: true });
});

// Data
app.get('/api/state', auth, (req, res) => res.json(db.prepare('SELECT state,ts FROM books WHERE id=1').get() || { state: null, ts: 0 }));
app.put('/api/state', auth, (req, res) => {
  const { state, base } = req.body || {};
  if (typeof state !== 'string') return res.status(400).json({ error: 'bad' });
  const cur = db.prepare('SELECT ts FROM books WHERE id=1').get();
  if (cur && base !== cur.ts) return res.status(409).json({ error: 'conflict', ts: cur.ts });
  const ts = Date.now();
  db.prepare('INSERT INTO books(id,state,ts) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, ts=excluded.ts').run(state, ts);
  res.json({ ts });
});

// Admin: users and backup
app.get('/api/users', auth, admin, (req, res) => res.json(db.prepare('SELECT id,username,role FROM users').all()));
app.post('/api/users', auth, admin, (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password || password.length < 6) return res.status(400).json({ error: 'Username and password (min 6) required' });
  try { db.prepare('INSERT INTO users(username,hash,role) VALUES(?,?,?)').run(username.trim(), hashPw(password), role === 'admin' ? 'admin' : 'user'); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: 'Username already exists' }); }
});
app.post('/api/users/:id/password', auth, admin, (req, res) => {
  if (!req.body.password || req.body.password.length < 6) return res.status(400).json({ error: 'min 6' });
  db.prepare('UPDATE users SET hash=? WHERE id=?').run(hashPw(req.body.password), req.params.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.params.id); res.json({ ok: true });
});
app.delete('/api/users/:id', auth, admin, (req, res) => {
  if (+req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.params.id); res.json({ ok: true });
});

// Daily backup (keeps last 30)
function backup() {
  const row = db.prepare('SELECT state FROM books WHERE id=1').get(); if (!row) return;
  const f = path.join(DATA_DIR, 'backups', `backup-${new Date().toISOString().slice(0, 10)}.json`);
  fs.writeFileSync(f, row.state);
  const all = fs.readdirSync(path.join(DATA_DIR, 'backups')).sort();
  all.slice(0, Math.max(0, all.length - 30)).forEach(x => fs.unlinkSync(path.join(DATA_DIR, 'backups', x)));
}
backup(); setInterval(backup, 6 * 3600e3);
setInterval(() => db.prepare('DELETE FROM sessions WHERE exp<?').run(Date.now()), 3600e3);

// Pages
const pub = n => (req, res) => res.sendFile(path.join(__dirname, 'public', n));
app.get('/login', pub('login.html'));
app.get('/admin', auth, admin, pub('admin.html'));
app.get('/', auth, pub('app.html'));
app.listen(PORT, () => console.log('Running on port ' + PORT));
