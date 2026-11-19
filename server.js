'use strict';
const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

/* ---------- Config ---------- */
const PROD = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || (PROD ? null : 'dev-only-secret');
if (!SECRET) { console.error('JWT_SECRET must be set in production.'); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set. Paste your Neon (PostgreSQL) connection string into it.'); process.exit(1); }

/* ---------- Database (PostgreSQL) ---------- */
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
pool.on('error', e => console.error('Database connection error:', e.message));
const q = (text, params) => pool.query(text, params);

// One table per feature. Column names match the front-end fields exactly.
const SCHEMA = {
  tasks:    { name: 'text', code: 'text', desc: 'text', due: 'text', done: 'bool' },
  classes:  { code: 'text', day: 'text', start: 'text', end: 'text', room: 'text', inst: 'text' },
  water:    { ml: 'num', date: 'text', time: 'text' },
  sleep:    { bed: 'text', wake: 'text' },
  routines: { name: 'text', when: 'text', doneOn: 'text' },
  tx:       { type: 'text', cat: 'text', amt: 'num', date: 'text' }
};
const SQLTYPE = { text: "TEXT NOT NULL DEFAULT ''", num: 'DOUBLE PRECISION NOT NULL DEFAULT 0', bool: 'BOOLEAN NOT NULL DEFAULT FALSE' };

async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    pass TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  for (const [t, cols] of Object.entries(SCHEMA)) {
    const defs = Object.entries(cols).map(([c, k]) => `"${c}" ${SQLTYPE[k]}`).join(', ');
    await q(`CREATE TABLE IF NOT EXISTS "${t}" (
      id SERIAL PRIMARY KEY,
      uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, ${defs})`);
    await q(`CREATE INDEX IF NOT EXISTS "idx_${t}_uid" ON "${t}"(uid)`);
  }
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
    else if (kind === 'bool' && typeof v === 'boolean') out[c] = v;
    else throw httpErr(400, `Invalid value for "${c}".`);
  }
  if (!partial && !Object.keys(out).length) throw httpErr(400, 'Nothing to save.');
  return out;
}
const rowId = req => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1 || id > 2147483646) throw httpErr(404, 'Not found.');
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
  res.cookie(COOKIE, jwt.sign({ uid }, SECRET, { expiresIn: '30d' }), { ...COOKIE_OPTS, maxAge: 30 * 864e5 });
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
    id = (await q('INSERT INTO users (email, name, pass) VALUES ($1, $2, $3) RETURNING id', [email, name, hash])).rows[0].id;
  } catch (e) {
    if (e.code === '23505') throw httpErr(409, 'That email already has an account. Log in instead.');
    throw e;
  }
  setSession(res, id);
  res.status(201).json({ email, name });
}));

app.post('/api/login', authLimit, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  const user = (await q('SELECT * FROM users WHERE email = $1', [email])).rows[0];
  const ok = await bcrypt.compare(pw, user ? user.pass : DUMMY_HASH);
  if (!user || !ok) throw httpErr(401, 'Invalid email or password.');
  setSession(res, user.id);
  res.json({ email: user.email, name: user.name });
}));

app.post('/api/logout', (req, res) => { res.clearCookie(COOKIE, COOKIE_OPTS); res.json({ ok: true }); });

app.get('/api/me', auth, wrap(async (req, res) => {
  const user = (await q('SELECT email, name FROM users WHERE id = $1', [req.uid])).rows[0];
  if (!user) throw httpErr(401, 'Please log in.');
  res.json(user);
}));

/* ---------- Data API: /api/<store> ---------- */
const api = express.Router();
api.use(auth);
api.param('store', (req, res, next, store) =>
  Object.hasOwn(SCHEMA, store) ? next() : next(httpErr(404, 'Not found.')));

api.get('/:store', wrap(async (req, res) => {
  res.json((await q(`SELECT * FROM "${req.params.store}" WHERE uid = $1 ORDER BY id`, [req.uid])).rows);
}));

api.get('/:store/:id', wrap(async (req, res) => {
  const row = (await q(`SELECT * FROM "${req.params.store}" WHERE id = $1 AND uid = $2`, [rowId(req), req.uid])).rows[0];
  if (!row) throw httpErr(404, 'Not found.');
  res.json(row);
}));

api.post('/:store', wrap(async (req, res) => {
  const s = req.params.store, data = clean(s, req.body, false), cols = Object.keys(data);
  const sql = `INSERT INTO "${s}" (uid${cols.map(c => `, "${c}"`).join('')}) VALUES ($1${cols.map((_, i) => `, $${i + 2}`).join('')}) RETURNING *`;
  res.status(201).json((await q(sql, [req.uid, ...cols.map(c => data[c])])).rows[0]);
}));

api.put('/:store/:id', wrap(async (req, res) => {
  const s = req.params.store, id = rowId(req), data = clean(s, req.body, true), cols = Object.keys(data);
  const result = cols.length
    ? await q(`UPDATE "${s}" SET ${cols.map((c, i) => `"${c}" = $${i + 1}`).join(', ')} WHERE id = $${cols.length + 1} AND uid = $${cols.length + 2} RETURNING *`,
              [...cols.map(c => data[c]), id, req.uid])
    : await q(`SELECT * FROM "${s}" WHERE id = $1 AND uid = $2`, [id, req.uid]);
  if (!result.rows[0]) throw httpErr(404, 'Not found.');
  res.json(result.rows[0]);
}));

api.delete('/:store/:id', wrap(async (req, res) => {
  const r = await q(`DELETE FROM "${req.params.store}" WHERE id = $1 AND uid = $2`, [rowId(req), req.uid]);
  if (!r.rowCount) throw httpErr(404, 'Not found.');
  res.json({ ok: true });
}));

app.use('/api', api);
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'Server error. Please try again.' : err.message });
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`Hayati running on http://localhost:${PORT}`)))
  .catch(e => { console.error('Could not set up the database:', e.message); process.exit(1); });
