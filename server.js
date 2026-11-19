'use strict';
const path = require('path');
const fs = require('fs');
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

/* ---------- Config ---------- */
const PROD = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || (PROD ? null : 'dev-only-secret');
if (!SECRET) { console.error('JWT_SECRET must be set in production.'); process.exit(1); }
const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'data', 'hayati.db');
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

/* ---------- Database ---------- */
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  pass TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

// One table per feature. Column names match the front-end fields exactly.
const SCHEMA = {
  tasks:    { name: 'text', code: 'text', desc: 'text', due: 'text', done: 'bool' },
  classes:  { code: 'text', day: 'text', start: 'text', end: 'text', room: 'text', inst: 'text' },
  water:    { ml: 'num', date: 'text', time: 'text' },
  sleep:    { bed: 'text', wake: 'text' },
  routines: { name: 'text', when: 'text', doneOn: 'text' },
  tx:       { type: 'text', cat: 'text', amt: 'num', date: 'text' }
};
const SQLTYPE = { text: "TEXT NOT NULL DEFAULT ''", num: 'REAL NOT NULL DEFAULT 0', bool: 'INTEGER NOT NULL DEFAULT 0' };
for (const [t, cols] of Object.entries(SCHEMA)) {
  const defs = Object.entries(cols).map(([c, k]) => `"${c}" ${SQLTYPE[k]}`).join(', ');
  db.exec(`CREATE TABLE IF NOT EXISTS "${t}" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, ${defs});
    CREATE INDEX IF NOT EXISTS "idx_${t}_uid" ON "${t}"(uid);`);
}

/* ---------- Helpers ---------- */
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Keep only known columns and check their types.
function clean(store, body, partial) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw httpErr(400, 'Invalid request.');
  const out = {};
  for (const [c, kind] of Object.entries(SCHEMA[store])) {
    if (!Object.hasOwn(body, c)) continue;
    const v = body[c];
    if (kind === 'text' && typeof v === 'string' && v.length <= 500) out[c] = v;
    else if (kind === 'num' && typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1e12) out[c] = v;
    else if (kind === 'bool' && typeof v === 'boolean') out[c] = v ? 1 : 0;
    else throw httpErr(400, `Invalid value for "${c}".`);
  }
  if (!partial && !Object.keys(out).length) throw httpErr(400, 'Nothing to save.');
  return out;
}
function toClient(store, row) {
  for (const [c, kind] of Object.entries(SCHEMA[store])) if (kind === 'bool') row[c] = !!row[c];
  return row;
}
const rowId = req => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) throw httpErr(404, 'Not found.');
  return id;
};

/* Simple in-memory rate limit for login/signup */
const hits = new Map();
setInterval(() => hits.clear(), 15 * 60e3).unref();
const limiter = (max, windowMs) => (req, res, next) => {
  const key = req.ip + req.path, now = Date.now();
  const recent = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (recent.length >= max) return next(httpErr(429, 'Too many attempts. Try again in a few minutes.'));
  recent.push(now); hits.set(key, recent); next();
};

/* ---------- Auth ---------- */
const COOKIE = 'hayati_token';
const COOKIE_OPTS = { httpOnly: true, sameSite: 'lax', secure: PROD };
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);
const EMAIL = /^\S+@\S+\.\S+$/;

const setSession = (res, uid) =>
  res.cookie(COOKIE, jwt.sign({ uid }, SECRET, { expiresIn: '7d' }), { ...COOKIE_OPTS, maxAge: 7 * 864e5 });
const auth = (req, res, next) => {
  try { req.uid = jwt.verify(req.cookies[COOKIE] || '', SECRET, { algorithms: ['HS256'] }).uid; next(); }
  catch { next(httpErr(401, 'Please log in.')); }
};

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const authLimit = limiter(10, 15 * 60e3);

app.post('/api/signup', authLimit, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  if (!name || !email || !pw) throw httpErr(400, 'Fill in every field.');
  if (!EMAIL.test(email) || email.length > 254) throw httpErr(400, 'Enter a valid email, like name@example.com.');
  if (pw.length < 6 || pw.length > 72) throw httpErr(400, 'Use a password with 6 to 72 characters.');
  const hash = await bcrypt.hash(pw, 10);
  let id;
  try {
    id = db.prepare('INSERT INTO users (email, name, pass) VALUES (?, ?, ?)').run(email, name, hash).lastInsertRowid;
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) throw httpErr(409, 'That email already has an account. Log in instead.');
    throw e;
  }
  setSession(res, Number(id));
  res.status(201).json({ email, name });
}));

app.post('/api/login', authLimit, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  const ok = await bcrypt.compare(pw, user ? user.pass : DUMMY_HASH);
  if (!user || !ok) throw httpErr(401, 'Invalid email or password.');
  setSession(res, user.id);
  res.json({ email: user.email, name: user.name });
}));

app.post('/api/logout', (req, res) => { res.clearCookie(COOKIE, COOKIE_OPTS); res.json({ ok: true }); });

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT email, name FROM users WHERE id = ?').get(req.uid);
  if (!user) throw httpErr(401, 'Please log in.');
  res.json(user);
});

/* ---------- Data API: /api/<store> ---------- */
const api = express.Router();
api.use(auth);
api.param('store', (req, res, next, store) =>
  Object.hasOwn(SCHEMA, store) ? next() : next(httpErr(404, 'Not found.')));

api.get('/:store', (req, res) => {
  const s = req.params.store;
  res.json(db.prepare(`SELECT * FROM "${s}" WHERE uid = ? ORDER BY id`).all(req.uid).map(r => toClient(s, r)));
});

api.get('/:store/:id', (req, res) => {
  const s = req.params.store;
  const row = db.prepare(`SELECT * FROM "${s}" WHERE id = ? AND uid = ?`).get(rowId(req), req.uid);
  if (!row) throw httpErr(404, 'Not found.');
  res.json(toClient(s, row));
});

api.post('/:store', (req, res) => {
  const s = req.params.store, data = clean(s, req.body, false), cols = Object.keys(data);
  const sql = `INSERT INTO "${s}" (uid${cols.map(c => `, "${c}"`).join('')}) VALUES (?${cols.map(() => ', ?').join('')})`;
  const info = db.prepare(sql).run(req.uid, ...cols.map(c => data[c]));
  res.status(201).json(toClient(s, db.prepare(`SELECT * FROM "${s}" WHERE id = ?`).get(info.lastInsertRowid)));
});

api.put('/:store/:id', (req, res) => {
  const s = req.params.store, id = rowId(req), data = clean(s, req.body, true), cols = Object.keys(data);
  if (cols.length) {
    const sql = `UPDATE "${s}" SET ${cols.map(c => `"${c}" = ?`).join(', ')} WHERE id = ? AND uid = ?`;
    if (!db.prepare(sql).run(...cols.map(c => data[c]), id, req.uid).changes) throw httpErr(404, 'Not found.');
  }
  const row = db.prepare(`SELECT * FROM "${s}" WHERE id = ? AND uid = ?`).get(id, req.uid);
  if (!row) throw httpErr(404, 'Not found.');
  res.json(toClient(s, row));
});

api.delete('/:store/:id', (req, res) => {
  const s = req.params.store;
  if (!db.prepare(`DELETE FROM "${s}" WHERE id = ? AND uid = ?`).run(rowId(req), req.uid).changes) throw httpErr(404, 'Not found.');
  res.json({ ok: true });
});

app.use('/api', api);
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'Server error. Please try again.' : err.message });
});

app.listen(PORT, () => console.log(`Hayati running on http://localhost:${PORT}`));
