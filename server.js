const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

// ---------- DATABASE ----------
const db = new Database('chat.db');
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
// Default group so there's always somewhere to chat
db.prepare(`INSERT OR IGNORE INTO groups (id, name) VALUES (1, 'general')`).run();

// ---------- HTTP SERVER ----------
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    const filePath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(500); res.end('Error'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }
  res.writeHead(404);
  res.end('Not found');
});

// ---------- AUTH ENDPOINTS (simple JSON API) ----------
// We need to parse JSON bodies for POST requests
function readJSON(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); }
    });
  });
}

// Wrap the server so we can intercept POST /api/* before the static handler
const originalHandler = server.listeners('request')[0];
server.removeAllListeners('request');
server.on('request', async (req, res) => {
  if (req.method === 'POST' && req.url.startsWith('/api/')) {
    const body = await readJSON(req);
    res.setHeader('Content-Type', 'application/json');

    // --- REGISTER ---
    if (req.url === '/api/register') {
      const { username, password } = body;
      if (!username || !password) {
        res.writeHead(400); return res.end(JSON.stringify({ error: 'Missing fields' }));
      }
      try {
        const hash = bcrypt.hashSync(password, 10);
        const info = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hash);
        const token = crypto.randomBytes(24).toString('hex');
        db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, info.lastInsertRowid);
        res.writeHead(200);
        return res.end(JSON.stringify({ token, username }));
      } catch (e) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: 'Username already taken' }));
      }
    }

    // --- LOGIN ---
    if (req.url === '/api/login') {
      const { username, password } = body;
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        res.writeHead(401);
        return res.end(JSON.stringify({ error: 'Invalid credentials' }));
      }
      const token = crypto.randomBytes(24).toString('hex');
      db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
      res.writeHead(200);
      return res.end(JSON.stringify({ token, username: user.username }));
    }

    res.writeHead(404);
    return res.end(JSON.stringify({ error: 'Unknown endpoint' }));
  }

  // Fall back to static file handler
  originalHandler(req, res);
});

// ---------- WEBSOCKET ----------
const wss = new WebSocketServer({ server });
const clients = new Map(); // ws -> { userId, username, groupId }

function broadcastToGroup(groupId, payload) {
  const data = JSON.stringify(payload);
  for (const [ws, info] of clients.entries()) {
    if (info.groupId === groupId && ws.readyState === 1) ws.send(data);
  }
}

wss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    // --- AUTHENTICATE ---
    if (msg.type === 'auth') {
      const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(msg.token);
      if (!session) {
        ws.send(JSON.stringify({ type: 'auth_error', error: 'Invalid token' }));
        return;
      }
      const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(session.user_id);
      clients.set(ws, { userId: user.id, username: user.username, groupId: 1 });

      // Send group list + history of default group
      const groups = db.prepare('SELECT id, name FROM groups').all();
      const history = db.prepare(`
        SELECT m.content, m.created_at, u.username
        FROM messages m JOIN users u ON u.id = m.user_id
        WHERE m.group_id = 1 ORDER BY m.id ASC LIMIT 100
      `).all();

      ws.send(JSON.stringify({ type: 'ready', username: user.username, groups, history, groupId: 1 }));

      // Notify others in the group
      broadcastToGroup(1, { type: 'system', text: `${user.username} joined` });
      return;
    }

    const info = clients.get(ws);
    if (!info) return; // not logged in

    // --- SWITCH GROUP ---
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

    // --- CREATE GROUP ---
    if (msg.type === 'create_group') {
      const name = (msg.name || '').trim().toLowerCase().replace(/\s+/g, '-');
      if (!name) return;
      try {
        db.prepare('INSERT INTO groups (name) VALUES (?)').run(name);
      } catch { /* exists */ }
      const groups = db.prepare('SELECT id, name FROM groups').all();
      // Tell everyone the group list changed
      for (const [client] of clients.entries()) {
        if (client.readyState === 1) client.send(JSON.stringify({ type: 'groups', groups }));
      }
      return;
    }

    // --- CHAT MESSAGE ---
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
    }
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server on port ${PORT}`));
