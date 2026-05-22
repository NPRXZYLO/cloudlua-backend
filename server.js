
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.options('*', cors());
app.use(express.json({ limit: '50mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── DB INIT ────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      api_key    TEXT PRIMARY KEY,
      name       TEXT,
      email      TEXT,
      password   TEXT,
      trial_end  TIMESTAMP,
      key_limit  INTEGER DEFAULT 10,
      is_admin   BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scripts (
      id              SERIAL PRIMARY KEY,
      user_api_key    TEXT REFERENCES users(api_key) ON DELETE CASCADE,
      name            TEXT,
      original_code   TEXT,
      obfuscated_code TEXT,
      created_at      TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS license_keys (
      id           TEXT PRIMARY KEY,
      user_api_key TEXT REFERENCES users(api_key) ON DELETE CASCADE,
      script_id    INTEGER REFERENCES scripts(id) ON DELETE CASCADE,
      key          TEXT,
      url_id       TEXT UNIQUE,
      active       BOOLEAN DEFAULT true,
      created_at   TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS executions (
      id           TEXT PRIMARY KEY,
      key_id       TEXT REFERENCES license_keys(id) ON DELETE CASCADE,
      user_api_key TEXT,
      script_id    INTEGER,
      hwid         TEXT,
      ip           TEXT,
      timestamp    TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS blacklist (
      id           TEXT PRIMARY KEY,
      user_api_key TEXT REFERENCES users(api_key) ON DELETE CASCADE,
      target       TEXT,
      reason       TEXT,
      created_at   TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS support (
      id           SERIAL PRIMARY KEY,
      user_api_key TEXT,
      user_name    TEXT,
      user_email   TEXT,
      subject      TEXT,
      message      TEXT,
      reply        TEXT,
      created_at   TIMESTAMP DEFAULT NOW()
    );
  `);

  // Ensure admin exists
  const admin = await pool.query('SELECT * FROM users WHERE api_key = $1', ['CL-QZepomYJcINJY3XA']);
  if (admin.rows.length === 0) {
    await pool.query(
      'INSERT INTO users (api_key, name, email, password, trial_end, key_limit, is_admin) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      ['CL-QZepomYJcINJY3XA', 'CloudLua Owner', 'owner@cloudlua.dev', 'admin123', null, 999999, true]
    );
  } else {
    // Make sure admin stays admin if row already existed
    await pool.query('UPDATE users SET is_admin=true, key_limit=999999 WHERE api_key=$1', ['CL-QZepomYJcINJY3XA']);
  }
  console.log('[CloudLua] Database ready');
}
initDB().catch(console.error);

// ─── HELPERS ────────────────────────────────────────────────────────────────
function uid(len) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let r = '';
  for (let i = 0; i < len; i++) r += chars[Math.floor(Math.random() * chars.length)];
  return r;
}

function execId() {
  return 'exec-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7);
}

// ─── AUTH ROUTES ────────────────────────────────────────────────────────────

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short (min 6)' });
  try {
    const exists = await pool.query('SELECT api_key FROM users WHERE email=$1', [email.toLowerCase()]);
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Email already registered' });
    const apiKey = 'CL-' + uid(16);
    const trialEnd = new Date(Date.now() + 7 * 86400 * 1000);
    await pool.query(
      'INSERT INTO users (api_key,name,email,password,trial_end,key_limit) VALUES ($1,$2,$3,$4,$5,$6)',
      [apiKey, name, email.toLowerCase(), password, trialEnd, 10]
    );
    const user = await pool.query('SELECT * FROM users WHERE api_key=$1', [apiKey]);
    res.json(user.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'API key required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE api_key=$1', [apiKey]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'API key not found' });
    const user = result.rows[0];
    if (!user.is_admin && user.trial_end && new Date(user.trial_end) < new Date()) {
      return res.status(403).json({ error: 'Your free trial has expired. Contact support to renew.' });
    }
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/forgot-key
app.post('/api/forgot-key', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const result = await pool.query('SELECT api_key FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'No account with that email' });
    res.json({ apiKey: result.rows[0].api_key });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── SCRIPTS ────────────────────────────────────────────────────────────────

app.post('/api/scripts', async (req, res) => {
  const { apiKey, name, originalCode, obfuscatedCode } = req.body;
  if (!apiKey || !name || !originalCode || !obfuscatedCode)
    return res.status(400).json({ error: 'Missing fields' });
  try {
    const u = await pool.query('SELECT * FROM users WHERE api_key=$1', [apiKey]);
    if (!u.rows.length) return res.status(401).json({ error: 'Invalid API key' });
    const user = u.rows[0];
    if (!user.is_admin && user.trial_end && new Date(user.trial_end) < new Date())
      return res.status(403).json({ error: 'Trial expired' });
    const result = await pool.query(
      'INSERT INTO scripts (user_api_key,name,original_code,obfuscated_code) VALUES ($1,$2,$3,$4) RETURNING id,created_at',
      [apiKey, name, originalCode, obfuscatedCode]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/scripts', async (req, res) => {
  const { apiKey } = req.query;
  if (!apiKey) return res.status(400).json({ error: 'apiKey required' });
  try {
    const result = await pool.query(
      'SELECT * FROM scripts WHERE user_api_key=$1 ORDER BY created_at DESC', [apiKey]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/scripts/:id', async (req, res) => {
  const { apiKey, name, originalCode, obfuscatedCode } = req.body;
  try {
    const result = await pool.query(
      'UPDATE scripts SET name=$1,original_code=$2,obfuscated_code=$3 WHERE id=$4 AND user_api_key=$5 RETURNING id',
      [name, originalCode, obfuscatedCode, req.params.id, apiKey]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Script not found' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/scripts/:id', async (req, res) => {
  const { apiKey } = req.query;
  try {
    // Cascade: delete executions → keys → script
    const keys = await pool.query('SELECT id FROM license_keys WHERE script_id=$1 AND user_api_key=$2', [req.params.id, apiKey]);
    for (const k of keys.rows) {
      await pool.query('DELETE FROM executions WHERE key_id=$1', [k.id]);
    }
    await pool.query('DELETE FROM license_keys WHERE script_id=$1 AND user_api_key=$2', [req.params.id, apiKey]);
    await pool.query('DELETE FROM scripts WHERE id=$1 AND user_api_key=$2', [req.params.id, apiKey]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── LICENSE KEYS ───────────────────────────────────────────────────────────

app.post('/api/keys', async (req, res) => {
  const { apiKey, scriptId } = req.body;
  if (!apiKey || !scriptId) return res.status(400).json({ error: 'apiKey and scriptId required' });
  try {
    const u = await pool.query('SELECT * FROM users WHERE api_key=$1', [apiKey]);
    if (!u.rows.length) return res.status(401).json({ error: 'Invalid API key' });
    const user = u.rows[0];
    if (!user.is_admin && user.trial_end && new Date(user.trial_end) < new Date())
      return res.status(403).json({ error: 'Trial expired' });

    // Check script belongs to user
    const sc = await pool.query('SELECT id FROM scripts WHERE id=$1 AND user_api_key=$2', [scriptId, apiKey]);
    if (!sc.rows.length) return res.status(404).json({ error: 'Script not found' });

    const limit = user.key_limit || 10;
    const cnt = await pool.query('SELECT COUNT(*) FROM license_keys WHERE user_api_key=$1', [apiKey]);
    if (parseInt(cnt.rows[0].count) >= limit && limit !== 999999)
      return res.status(400).json({ error: `Key limit reached (${limit})` });

    const keyId   = 'key-' + Date.now() + '-' + uid(4);
    const keyStr  = 'CLK-' + uid(20);
    const urlId   = uid(10);

    await pool.query(
      'INSERT INTO license_keys (id,user_api_key,script_id,key,url_id) VALUES ($1,$2,$3,$4,$5)',
      [keyId, apiKey, scriptId, keyStr, urlId]
    );
    res.json({ id: keyId, key: keyStr, urlId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/keys', async (req, res) => {
  const { apiKey } = req.query;
  if (!apiKey) return res.status(400).json({ error: 'apiKey required' });
  try {
    const result = await pool.query(
      'SELECT lk.*, (SELECT COUNT(*) FROM executions e WHERE e.key_id=lk.id) as exec_count FROM license_keys lk WHERE lk.user_api_key=$1 ORDER BY lk.created_at DESC',
      [apiKey]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/keys/:id/toggle', async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE license_keys SET active=NOT active WHERE id=$1 RETURNING active', [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Key not found' });
    res.json({ active: result.rows[0].active });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/keys/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM executions WHERE key_id=$1', [req.params.id]);
    await pool.query('DELETE FROM license_keys WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── BLACKLIST ──────────────────────────────────────────────────────────────

app.post('/api/blacklist', async (req, res) => {
  const { apiKey, target, reason } = req.body;
  if (!apiKey || !target || !reason) return res.status(400).json({ error: 'Missing fields' });
  try {
    // Check if already blacklisted
    const ex = await pool.query('SELECT id FROM blacklist WHERE user_api_key=$1 AND target=$2', [apiKey, target]);
    if (ex.rows.length) return res.status(400).json({ error: 'Already blacklisted' });
    await pool.query(
      'INSERT INTO blacklist (id,user_api_key,target,reason) VALUES ($1,$2,$3,$4)',
      ['bl-' + Date.now(), apiKey, target, reason]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/blacklist', async (req, res) => {
  const { apiKey } = req.query;
  if (!apiKey) return res.status(400).json({ error: 'apiKey required' });
  try {
    const result = await pool.query(
      'SELECT * FROM blacklist WHERE user_api_key=$1 ORDER BY created_at DESC', [apiKey]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/blacklist/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM blacklist WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── EXECUTIONS ─────────────────────────────────────────────────────────────

app.get('/api/executions', async (req, res) => {
  const { apiKey, limit } = req.query;
  if (!apiKey) return res.status(400).json({ error: 'apiKey required' });
  try {
    const lim = Math.min(parseInt(limit) || 100, 500);
    const result = await pool.query(
      `SELECT e.*, lk.key as key_string, s.name as script_name
       FROM executions e
       JOIN license_keys lk ON e.key_id = lk.id
       JOIN scripts s ON e.script_id = s.id
       WHERE e.user_api_key=$1
       ORDER BY e.timestamp DESC LIMIT $2`,
      [apiKey, lim]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── LOADSTRING ENDPOINT ─────────────────────────────────────────────────────
// Called from Roblox: game:HttpGet("https://yourbackend.com/s/URLID?key=KEY&hwid=HWID")

app.get('/s/:urlId', async (req, res) => {
  const { urlId } = req.params;
  const { key, hwid } = req.query;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  try {
    // 1. Find key
    const keyRes = await pool.query('SELECT * FROM license_keys WHERE url_id=$1', [urlId]);
    if (!keyRes.rows.length) {
      return res.status(404).type('text/plain').send('-- CloudLua: Script not found');
    }
    const license = keyRes.rows[0];

    // 2. Check revoked
    if (!license.active) {
      return res.status(403).type('text/plain').send('-- CloudLua: Key has been revoked');
    }

    // 3. Validate key string
    if (!key || key !== license.key) {
      return res.status(401).type('text/plain').send('-- CloudLua: Unauthorized – invalid key');
    }

    // 4. Check HWID blacklist
    const hwidVal = hwid || 'unknown';
    const bl = await pool.query(
      'SELECT * FROM blacklist WHERE user_api_key=$1 AND target=$2',
      [license.user_api_key, hwidVal]
    );
    if (bl.rows.length > 0) {
      return res.status(403).type('text/plain').send('-- CloudLua: Your HWID is blacklisted');
    }

    // 5. Log execution (use unique ID to avoid collision)
    const eid = execId();
    await pool.query(
      'INSERT INTO executions (id,key_id,user_api_key,script_id,hwid,ip) VALUES ($1,$2,$3,$4,$5,$6)',
      [eid, license.id, license.user_api_key, license.script_id, hwidVal, clientIp]
    );

    // 6. Fetch obfuscated script
    const scriptRes = await pool.query(
      'SELECT obfuscated_code FROM scripts WHERE id=$1', [license.script_id]
    );
    if (!scriptRes.rows.length) {
      return res.status(404).type('text/plain').send('-- CloudLua: Script data missing');
    }

    res.type('text/plain; charset=utf-8').send(scriptRes.rows[0].obfuscated_code);
  } catch (err) {
    console.error('[/s/:urlId]', err.message);
    res.status(500).type('text/plain').send('-- CloudLua: Internal server error');
  }
});

// ─── SUPPORT ────────────────────────────────────────────────────────────────

app.post('/api/support', async (req, res) => {
  const { apiKey, subject, message } = req.body;
  if (!apiKey || !subject || !message) return res.status(400).json({ error: 'Missing fields' });
  try {
    const u = await pool.query('SELECT name,email FROM users WHERE api_key=$1', [apiKey]);
    const user = u.rows[0] || {};
    await pool.query(
      'INSERT INTO support (user_api_key,user_name,user_email,subject,message) VALUES ($1,$2,$3,$4,$5)',
      [apiKey, user.name || '', user.email || '', subject, message]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/support', async (req, res) => {
  const { apiKey } = req.query;
  if (!apiKey) return res.status(400).json({ error: 'apiKey required' });
  try {
    const result = await pool.query(
      'SELECT * FROM support WHERE user_api_key=$1 ORDER BY created_at DESC', [apiKey]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ADMIN ──────────────────────────────────────────────────────────────────

async function requireAdmin(apiKey, res) {
  const a = await pool.query('SELECT is_admin FROM users WHERE api_key=$1', [apiKey]);
  if (!a.rows.length || !a.rows[0].is_admin) {
    res.status(403).json({ error: 'Admin only' });
    return false;
  }
  return true;
}

app.get('/api/admin/users', async (req, res) => {
  if (!await requireAdmin(req.query.apiKey, res)) return;
  try {
    const users = await pool.query(
      'SELECT api_key,name,email,trial_end,key_limit,is_admin,created_at FROM users ORDER BY created_at DESC'
    );
    res.json(users.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Extend / shrink trial
app.put('/api/admin/users/:userKey', async (req, res) => {
  const { apiKey, days } = req.body;
  if (!await requireAdmin(apiKey, res)) return;
  try {
    await pool.query(
      `UPDATE users SET trial_end = COALESCE(GREATEST(trial_end, NOW()), NOW()) + ($1 || ' days')::INTERVAL WHERE api_key=$2`,
      [days, req.params.userKey]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Change key limit
app.put('/api/admin/users/:userKey/limit', async (req, res) => {
  const { apiKey, limit } = req.body;
  if (!await requireAdmin(apiKey, res)) return;
  try {
    await pool.query('UPDATE users SET key_limit=$1 WHERE api_key=$2', [limit, req.params.userKey]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/users/:userKey', async (req, res) => {
  if (!await requireAdmin(req.query.apiKey, res)) return;
  const userKey = req.params.userKey;
  try {
    await pool.query('DELETE FROM support WHERE user_api_key=$1', [userKey]);
    await pool.query('DELETE FROM blacklist WHERE user_api_key=$1', [userKey]);
    // Get all key IDs first
    const ks = await pool.query('SELECT id FROM license_keys WHERE user_api_key=$1', [userKey]);
    for (const k of ks.rows) await pool.query('DELETE FROM executions WHERE key_id=$1', [k.id]);
    await pool.query('DELETE FROM license_keys WHERE user_api_key=$1', [userKey]);
    await pool.query('DELETE FROM scripts WHERE user_api_key=$1', [userKey]);
    await pool.query('DELETE FROM users WHERE api_key=$1', [userKey]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin view all support tickets
app.get('/api/admin/support', async (req, res) => {
  if (!await requireAdmin(req.query.apiKey, res)) return;
  try {
    const result = await pool.query('SELECT * FROM support ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin reply to ticket
app.put('/api/admin/support/:id', async (req, res) => {
  const { apiKey, reply } = req.body;
  if (!await requireAdmin(apiKey, res)) return;
  try {
    await pool.query('UPDATE support SET reply=$1 WHERE id=$2', [reply, req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin stats overview
app.get('/api/admin/stats', async (req, res) => {
  if (!await requireAdmin(req.query.apiKey, res)) return;
  try {
    const [users, scripts, keys, execs] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM scripts'),
      pool.query('SELECT COUNT(*) FROM license_keys'),
      pool.query('SELECT COUNT(*) FROM executions')
    ]);
    res.json({
      users:   parseInt(users.rows[0].count),
      scripts: parseInt(scripts.rows[0].count),
      keys:    parseInt(keys.rows[0].count),
      execs:   parseInt(execs.rows[0].count)
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Full reset (admin)
app.post('/api/admin/reset', async (req, res) => {
  const { apiKey } = req.body;
  if (!await requireAdmin(apiKey, res)) return;
  try {
    await pool.query('DROP TABLE IF EXISTS executions, license_keys, blacklist, scripts, support, users CASCADE');
    await initDB();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── START ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[CloudLua] Backend running on port ${PORT}`));
SERVEREOF
