const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');

// ---------- GLOBAL CRASH LOGGING ----------
// So Render logs show the real error if anything crashes
process.on('uncaughtException', (err) => {
  console.error('💥 UNCAUGHT EXCEPTION:', err);
});
process.on('unhandledRejection', (err) => {
  console.error('💥 UNHANDLED REJECTION:', err);
});

console.log('🚀 Starting server...');
console.log('Node version:', process.version);

// ---------- DATABASE ----------
let db;
try {
  db = new DatabaseSync('chat.db');
  console.log('✅ Database opened');
} catch (e) {
  console.error('❌ Database failed:', e.message);
  process.exit(1);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);
db.prepare(`INSERT OR IGNORE INTO groups (id, name) VALUES (1, 'general')`).run();
console.log('✅ Tables ready');

// ---------- HELPERS ----------
function readJSON(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { resolve({}); }
    });
  });
}

function sendJSON(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

// ---------- HTTP SERVER (also serves the HTML) ----------
const server = http.createServer(async (req, res) => {
  console.log(`${req.method} ${req.url}`);

  // ---- API ROUTES ----
  if (req.url.startsWith('/api/')) {
    if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Method not allowed' });

    const body = await readJSON(req);

    // REGISTER
    if (req.url === '/api/register') {
      const { username, password } = body;
      if (!username || !password) return sendJSON(res, 400, { error: 'Missing fields' });
      if (username.length < 3) return sendJSON(res, 400, { error: 'Username must be 3+ characters' });
      if (password.length < 4) return sendJSON(res, 400, { error: 'Password must be 4+ characters' });

      try {
        const hash = bcrypt.hashSync(password, 10);
        const info = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hash);
        const token = crypto.randomBytes(24).toString('hex');
        db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, info.lastInsertRowid);
        console.log(`✅ Registered user: ${username}`);
        return sendJSON(res, 200, { token, username, message: 'Account created!' });
      } catch (e) {
        console.error('Register error:', e.message);
        return sendJSON(res, 400, { error: 'Username already taken' });
      }
    }

    // LOGIN
    if (req.url === '/api/login') {
      const { username, password } = body;
      if (!username || !password) return sendJSON(res, 400, { error: 'Missing fields' });

      try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user) return sendJSON(res, 401, { error: 'User not found' });
        if (!bcrypt.compareSync(password, user.password)) return sendJSON(res, 401, { error: 'Wrong password' });

        const token = crypto.randomBytes(24).toString('hex');
        db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
        console.log(`✅ Logged in: ${username}`);
        return sendJSON(res, 200, { token, username: user.username, message: 'Logged in!' });
      } catch (e) {
        console.error('Login error:', e.message);
        return sendJSON(res, 500, { error: 'Server error' });
      }
    }

    return sendJSON(res, 404, { error: 'Unknown endpoint' });
  }

  // ---- SERVE FRONTEND ----
  if (req.url === '/__version') {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    version: 'v3-with-upgrade',
    node: process.version,
    hasUpgradeHandler: true
  }));
  return;
}
  if (req.url === '/' || req.url === '/index.html') {
    const filePath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(filePath, (err, data) => {
      if (err) {
        console.error('File read error:', err.message);
        res.writeHead(500);
        res.end('Error loading page');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

// ---------- WEBSOCKET SERVER ----------
// noServer: true means we manually handle the upgrade event so we can log every step
const wss = new WebSocketServer({ noServer: true });
const clients = new Map(); // ws -> { userId, username, groupId }

// Manual upgrade handling — this is what makes WebSocket work on Render
server.on('upgrade', (req, socket, head) => {
  console.log('🔄 Upgrade request:', req.url, 'from', req.headers.host);
  wss.handleUpgrade(req, socket, head, (ws) => {
    console.log('✅ WebSocket upgraded');
    wss.emit('connection', ws, req);
  });
});

function broadcastToGroup(groupId, payload) {
  const data = JSON.stringify(payload);
  for (const [ws, info] of clients.entries()) {
    if (info.groupId === groupId && ws.readyState === 1) ws.send(data);
  }
}

wss.on('connection', (ws) => {
  console.log('👤 New WebSocket connection');

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    // ---- AUTH ----
    if (msg.type === 'auth') {
      const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(msg.token);
      if (!session) {
        console.log('❌ Invalid token');
        return ws.send(JSON.stringify({ type: 'auth_error', error: 'Invalid token' }));
      }

      const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(session.user_id);
      clients.set(ws, { userId: user.id, username: user.username, groupId: 1 });

      const groups = db.prepare('SELECT id, name FROM groups').all();
      const history = db.prepare(`
        SELECT m.content, m.created_at, u.username
        FROM messages m JOIN users u ON u.id = m.user_id
        WHERE m.group_id = 1 ORDER BY m.id ASC LIMIT 100
      `).all();

      ws.send(JSON.stringify({ type: 'ready', username: user.username, groups, history, groupId: 1 }));
      broadcastToGroup(1, { type: 'system', text: `${user.username} joined` });
      console.log(`✅ Authenticated: ${user.username}`);
      return;
    }

    const info = clients.get(ws);
    if (!info) return; // not authenticated yet

    // ---- JOIN GROUP ----
    if (msg.type === 'join_group') {
      info.groupId = msg.groupId;
      const history = db.prepare(`
        SELECT m.content, m.created_at, u.username
        FROM messages m JOIN users u ON u.id = m.user_id
        WHERE m.group_id = ? ORDER BY m.id ASC LIMIT 100
      `).all(msg.groupId);
      ws.send(JSON.stringify({ type: 'history', history, groupId: msg.groupId }));
      return;
    }

    // ---- CREATE GROUP ----
    if (msg.type === 'create_group') {
      const name = (msg.name || '').trim().toLowerCase().replace(/\s+/g, '-');
      if (!name) return;
      try { db.prepare('INSERT INTO groups (name) VALUES (?)').run(name); } catch {}
      const groups = db.prepare('SELECT id, name FROM groups').all();
      for (const [client] of clients.entries()) {
        if (client.readyState === 1) client.send(JSON.stringify({ type: 'groups', groups }));
      }
      console.log(`✅ Group created: ${name}`);
      return;
    }

    // ---- SEND MESSAGE ----
    if (msg.type === 'message') {
      const text = (msg.text || '').trim();
      if (!text) return;
      const now = Date.now();
      db.prepare('INSERT INTO messages (group_id, user_id, content, created_at) VALUES (?, ?, ?, ?)')
        .run(info.groupId, info.userId, text, now);
      broadcastToGroup(info.groupId, {
        type: 'message',
        username: info.username,
        text,
        createdAt: now
      });
    }
  });

  ws.on('close', () => {
    const info = clients.get(ws);
    if (info) {
      broadcastToGroup(info.groupId, { type: 'system', text: `${info.username} left` });
      clients.delete(ws);
      console.log(`👋 Disconnected: ${info.username}`);
    }
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err.message);
  });
});

// ---------- START ----------
// Render provides PORT via env; must bind to 0.0.0.0 (not localhost)
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🎉 Server listening on 0.0.0.0:${PORT}`);
});
