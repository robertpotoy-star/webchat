const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

// --- 1. Serve the HTML file over HTTP ---
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    const filePath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading page');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

// --- 2. WebSocket chat logic ---
const wss = new WebSocketServer({ server });

wss.on('connection', ws => {
  console.log('A user connected');

  ws.on('message', msg => {
    // Broadcast message to everyone connected
    wss.clients.forEach(client => {
      if (client.readyState === 1) {
        client.send(msg.toString());
      }
    });
  });

  ws.on('close', () => console.log('A user disconnected'));
});

// --- 3. Use the port Render provides ---
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});