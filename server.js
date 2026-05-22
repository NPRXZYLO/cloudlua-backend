require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      api_key TEXT PRIMARY KEY,
      name TEXT,
      email TEXT,
      password TEXT,
      trial_end TIMESTAMP,
      key_limit INTEGER DEFAULT 10,
      is_admin BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scripts (
      id SERIAL PRIMARY KEY,
      user_api_key TEXT REFERENCES users(api_key),
      name TEXT,
      original_code TEXT,
      obfuscated_code TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS license_keys (
      id TEXT PRIMARY KEY,
      user_api_key TEXT REFERENCES users(api_key),
      script_id INTEGER REFERENCES scripts(id),
      key TEXT,
      url_id TEXT UNIQUE,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS executions (
      id TEXT PRIMARY KEY,
      key_id TEXT REFERENCES license_keys(id),
      user_api_key TEXT,
      script_id INTEGER,
      hwid TEXT,
      timestamp TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS blacklist (
      id TEXT PRIMARY KEY,
      user_api_key TEXT REFERENCES users(api_key),
      target TEXT,
      reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS support (
      id SERIAL PRIMARY KEY,
      user_api_key TEXT,
      subject TEXT,
      message TEXT,
      reply TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  const admin = await pool.query('SELECT * FROM users WHERE api_key = $1', ['CL-QZepomYJcINJY3XA']);
  if (admin.rows.length === 0) {
    await pool.query(
      'INSERT INTO users (api_key, name, email, password, trial_end, key_limit, is_admin) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      ['CL-QZepomYJcINJY3XA', 'CloudLua Owner', 'owner@cloudlua.dev', 'admin123', null, 999999, true]
    );
  }
  console.log('Database ready');
}
initDB();

function generateKey(prefix, length) {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var result = prefix;
  for (var i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
  return result;
}

// Register
app.post('/api/register', async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  try {
    var apiKey = generateKey('CL-', 16);
    var trialEnd = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO users (api_key, name, email, password, trial_end, key_limit) VALUES ($1,$2,$3,$4,$5,$6)',
      [apiKey, name, email, password, trialEnd, 10]
    );
    var user = await pool.query('SELECT * FROM users WHERE api_key = $1', [apiKey]);
    res.json(user.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Login
app.post('/api/login', async (req, res) => {
  var apiKey = req.body.apiKey;
  try {
    var result = await pool.query('SELECT * FROM users WHERE api_key = $1', [apiKey]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'API key not found' });
    var user = result.rows[0];
    if (!user.is_admin && user.trial_end && new Date(user.trial_end) < new Date()) {
      return res.status(403).json({ error: 'Trial expired' });
    }
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Forgot key
app.post('/api/forgot-key', async (req, res) => {
  var email = req.body.email;
  try {
    var result = await pool.query('SELECT api_key FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Email not found' });
    res.json({ apiKey: result.rows[0].api_key });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Scripts CRUD
app.post('/api/scripts', async (req, res) => {
  var apiKey = req.body.apiKey;
  var name = req.body.name;
  var originalCode = req.body.originalCode;
  var obfuscatedCode = req.body.obfuscatedCode;
  try {
    var result = await pool.query(
      'INSERT INTO scripts (user_api_key, name, original_code, obfuscated_code) VALUES ($1,$2,$3,$4) RETURNING id',
      [apiKey, name, originalCode, obfuscatedCode]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/scripts', async (req, res) => {
  var apiKey = req.query.apiKey;
  try {
    var result = await pool.query('SELECT * FROM scripts WHERE user_api_key = $1 ORDER BY created_at DESC', [apiKey]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/scripts/:id', async (req, res) => {
  var id = req.params.id;
  var apiKey = req.body.apiKey;
  var name = req.body.name;
  var originalCode = req.body.originalCode;
  var obfuscatedCode = req.body.obfuscatedCode;
  try {
    await pool.query(
      'UPDATE scripts SET name=$1, original_code=$2, obfuscated_code=$3 WHERE id=$4 AND user_api_key=$5',
      [name, originalCode, obfuscatedCode, id, apiKey]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/scripts/:id', async (req, res) => {
  var id = req.params.id;
  var apiKey = req.query.apiKey;
  try {
    await pool.query('DELETE FROM scripts WHERE id=$1 AND user_api_key=$2', [id, apiKey]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Keys
app.post('/api/keys', async (req, res) => {
  var apiKey = req.body.apiKey;
  var scriptId = req.body.scriptId;
  try {
    var user = await pool.query('SELECT * FROM users WHERE api_key = $1', [apiKey]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'Invalid API key' });
    var currentKeys = await pool.query('SELECT COUNT(*) FROM license_keys WHERE user_api_key = $1', [apiKey]);
    var limit = user.rows[0].key_limit || 10;
    if (currentKeys.rows[0].count >= limit) return res.status(400).json({ error: 'Key limit reached' });
    var keyId = 'key-' + Date.now();
    var keyString = generateKey('CLK-', 20);
    var urlId = Math.random().toString(36).substring(2, 10);
    await pool.query(
      'INSERT INTO license_keys (id, user_api_key, script_id, key, url_id) VALUES ($1,$2,$3,$4,$5)',
      [keyId, apiKey, scriptId, keyString, urlId]
    );
    res.json({ id: keyId, key: keyString, urlId: urlId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/keys', async (req, res) => {
  var apiKey = req.query.apiKey;
  try {
    var result = await pool.query('SELECT * FROM license_keys WHERE user_api_key = $1 ORDER BY created_at DESC', [apiKey]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/keys/:id/toggle', async (req, res) => {
  var id = req.params.id;
  try {
    await pool.query('UPDATE license_keys SET active = NOT active WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/keys/:id', async (req, res) => {
  var id = req.params.id;
  try {
    await pool.query('DELETE FROM license_keys WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Blacklist
app.post('/api/blacklist', async (req, res) => {
  var apiKey = req.body.apiKey;
  var target = req.body.target;
  var reason = req.body.reason;
  try {
    await pool.query(
      'INSERT INTO blacklist (id, user_api_key, target, reason) VALUES ($1,$2,$3,$4)',
      ['bl-' + Date.now(), apiKey, target, reason]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/blacklist', async (req, res) => {
  var apiKey = req.query.apiKey;
  try {
    var result = await pool.query('SELECT * FROM blacklist WHERE user_api_key = $1', [apiKey]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/blacklist/:id', async (req, res) => {
  var id = req.params.id;
  try {
    await pool.query('DELETE FROM blacklist WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Executions
app.get('/api/executions', async (req, res) => {
  var apiKey = req.query.apiKey;
  try {
    var result = await pool.query(
      'SELECT e.*, lk.key as key_string FROM executions e JOIN license_keys lk ON e.key_id = lk.id WHERE e.user_api_key = $1 ORDER BY e.timestamp DESC LIMIT 50',
      [apiKey]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ★★★ LOADSTRING ENDPOINT ★★★
app.get('/s/:urlId', async (req, res) => {
  var urlId = req.params.urlId;
  var key = req.query.key;
  var hwid = req.query.hwid || 'unknown';
  try {
    var keyResult = await pool.query('SELECT * FROM license_keys WHERE url_id = $1', [urlId]);
    if (keyResult.rows.length === 0) return res.status(404).send('-- CloudLua: Script not found');
    var license = keyResult.rows[0];
    if (!license.active) return res.status(403).send('-- CloudLua: Key revoked');
    if (key !== license.key) return res.status(401).send('-- CloudLua: Unauthorized - invalid key');

    var bl = await pool.query('SELECT * FROM blacklist WHERE user_api_key = $1 AND target = $2', [license.user_api_key, hwid]);
    if (bl.rows.length > 0) return res.status(403).send('-- CloudLua: HWID blacklisted');

    await pool.query(
      'INSERT INTO executions (id, key_id, user_api_key, script_id, hwid) VALUES ($1,$2,$3,$4,$5)',
      ['exec-' + Date.now(), license.id, license.user_api_key, license.script_id, hwid]
    );

    var script = await pool.query('SELECT obfuscated_code FROM scripts WHERE id = $1', [license.script_id]);
    if (script.rows.length === 0) return res.status(404).send('-- CloudLua: Script missing');
    
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(script.rows[0].obfuscated_code);
  } catch (err) { res.status(500).send('-- CloudLua: Server error'); }
});

// Support
app.post('/api/support', async (req, res) => {
  var apiKey = req.body.apiKey;
  var subject = req.body.subject;
  var message = req.body.message;
  try {
    await pool.query('INSERT INTO support (user_api_key, subject, message) VALUES ($1,$2,$3)', [apiKey, subject, message]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/support', async (req, res) => {
  var apiKey = req.query.apiKey;
  try {
    var result = await pool.query('SELECT * FROM support WHERE user_api_key = $1 ORDER BY created_at DESC', [apiKey]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin
app.get('/api/admin/users', async (req, res) => {
  var apiKey = req.query.apiKey;
  try {
    var admin = await pool.query('SELECT is_admin FROM users WHERE api_key = $1', [apiKey]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    var users = await pool.query('SELECT api_key, name, email, trial_end, key_limit, created_at FROM users');
    res.json(users.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:userKey', async (req, res) => {
  var apiKey = req.body.apiKey;
  var days = req.body.days;
  var userKey = req.params.userKey;
  try {
    var admin = await pool.query('SELECT is_admin FROM users WHERE api_key = $1', [apiKey]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    await pool.query('UPDATE users SET trial_end = NOW() + INTERVAL \'' + days + ' days\' WHERE api_key = $1', [userKey]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/users/:userKey', async (req, res) => {
  var apiKey = req.query.apiKey;
  var userKey = req.params.userKey;
  try {
    var admin = await pool.query('SELECT is_admin FROM users WHERE api_key = $1', [apiKey]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    await pool.query('DELETE FROM executions WHERE user_api_key = $1', [userKey]);
    await pool.query('DELETE FROM license_keys WHERE user_api_key = $1', [userKey]);
    await pool.query('DELETE FROM blacklist WHERE user_api_key = $1', [userKey]);
    await pool.query('DELETE FROM support WHERE user_api_key = $1', [userKey]);
    await pool.query('DELETE FROM scripts WHERE user_api_key = $1', [userKey]);
    await pool.query('DELETE FROM users WHERE api_key = $1', [userKey]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/reset', async (req, res) => {
  var apiKey = req.body.apiKey;
  try {
    var admin = await pool.query('SELECT is_admin FROM users WHERE api_key = $1', [apiKey]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    await pool.query('DROP TABLE IF EXISTS executions, license_keys, blacklist, scripts, support, users CASCADE');
    await initDB();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/support', async (req, res) => {
  var apiKey = req.query.apiKey;
  try {
    var admin = await pool.query('SELECT is_admin FROM users WHERE api_key = $1', [apiKey]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    var result = await pool.query('SELECT * FROM support ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/support/:id', async (req, res) => {
  var apiKey = req.body.apiKey;
  var reply = req.body.reply;
  var ticketId = req.params.id;
  try {
    var admin = await pool.query('SELECT is_admin FROM users WHERE api_key = $1', [apiKey]);
    if (!admin.rows[0] || !admin.rows[0].is_admin) return res.status(403).json({ error: 'Admin only' });
    await pool.query('UPDATE support SET reply = $1 WHERE id = $2', [reply, ticketId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() { console.log('CloudLua backend running on port ' + PORT); });
