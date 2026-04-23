const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const USERS_FILE = path.join(ROOT, 'users.json');
const SESSIONS_FILE = path.join(ROOT, 'sessions.json');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8'
};

function loadJson(file, fallback) {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function ensureStore(file, fallback) {
  if (!fs.existsSync(file)) saveJson(file, fallback);
}

ensureStore(USERS_FILE, []);
ensureStore(SESSIONS_FILE, {});

function readUsers() {
  return loadJson(USERS_FILE, []);
}

function writeUsers(users) {
  saveJson(USERS_FILE, users);
}

function readSessions() {
  return loadJson(SESSIONS_FILE, {});
}

function writeSessions(sessions) {
  saveJson(SESSIONS_FILE, sessions);
}

function send(res, statusCode, payload, headers = {}) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': typeof payload === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(body);
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null
  };
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) {
        req.destroy();
        reject(new Error('Payload terlalu besar.'));
      }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('JSON tidak valid.'));
      }
    });
    req.on('error', reject);
  });
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeUsername(value) {
  return String(value || '').trim();
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const test = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256');
  const ref = Buffer.from(hash, 'hex');
  if (ref.length !== test.length) return false;
  return crypto.timingSafeEqual(ref, test);
}

function createToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return '';
  return header.slice(7).trim();
}

function getAuthedUser(req) {
  const token = getBearerToken(req);
  if (!token) return null;

  const sessions = readSessions();
  const session = sessions[token];
  if (!session) return null;

  const users = readUsers();
  const user = users.find((u) => u.id === session.userId);
  if (!user) return null;

  return { token, user };
}

function safePath(urlPath) {
  const decoded = decodeURIComponent(urlPath);
  const normalized = path.normalize(decoded).replace(/^(\.\.(\/|\\|$))+/, '');
  return normalized.startsWith(path.sep) ? normalized.slice(1) : normalized;
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? '/index.real-auth.html' : pathname;
  const filePath = path.join(ROOT, safePath(rel));
  if (!filePath.startsWith(ROOT)) {
    send(res, 403, 'Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      const fallback = path.join(ROOT, 'index.real-auth.html');
      fs.readFile(fallback, (fallbackErr, data) => {
        if (fallbackErr) {
          send(res, 404, 'Not found');
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store'
        });
        res.end(data);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const type = MIME[ext] || 'application/octet-stream';
    fs.readFile(filePath, (readErr, data) => {
      if (readErr) {
        send(res, 500, 'Gagal membaca file');
        return;
      }
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
      res.end(data);
    });
  });
}

async function handleRegister(req, res) {
  const body = await parseBody(req);
  const email = normalizeEmail(body.email);
  const username = normalizeUsername(body.username);
  const password = String(body.password || '');

  if (!email || !username || !password) {
    send(res, 400, { error: 'Email, username, dan password wajib diisi.' });
    return;
  }
  if (!isEmail(email)) {
    send(res, 400, { error: 'Format email tidak valid.' });
    return;
  }
  if (password.length < 6) {
    send(res, 400, { error: 'Password minimal 6 karakter.' });
    return;
  }

  const users = readUsers();
  const emailExists = users.some((u) => u.email === email);
  const usernameExists = users.some((u) => u.username.toLowerCase() === username.toLowerCase());

  if (emailExists) {
    send(res, 409, { error: 'Email sudah terdaftar.' });
    return;
  }
  if (usernameExists) {
    send(res, 409, { error: 'Username sudah dipakai.' });
    return;
  }

  const { salt, hash } = hashPassword(password);
  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    email,
    username,
    passwordSalt: salt,
    passwordHash: hash,
    createdAt: now,
    lastLoginAt: now
  };
  users.push(user);
  writeUsers(users);

  const token = createToken();
  const sessions = readSessions();
  sessions[token] = { userId: user.id, createdAt: now };
  writeSessions(sessions);

  send(res, 201, { token, user: publicUser(user) });
}

async function handleLogin(req, res) {
  const body = await parseBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');

  if (!email || !password) {
    send(res, 400, { error: 'Email dan password wajib diisi.' });
    return;
  }

  const users = readUsers();
  const user = users.find((u) => u.email === email);
  if (!user) {
    send(res, 401, { error: 'Email atau password salah.' });
    return;
  }

  if (!verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    send(res, 401, { error: 'Email atau password salah.' });
    return;
  }

  user.lastLoginAt = new Date().toISOString();
  writeUsers(users);

  const token = createToken();
  const sessions = readSessions();
  sessions[token] = { userId: user.id, createdAt: new Date().toISOString() };
  writeSessions(sessions);

  send(res, 200, { token, user: publicUser(user) });
}

async function handleMe(req, res) {
  const session = getAuthedUser(req);
  if (!session) {
    send(res, 401, { error: 'Sesi tidak valid.' });
    return;
  }

  send(res, 200, { token: session.token, user: publicUser(session.user) });
}

async function handleLogout(req, res) {
  const token = getBearerToken(req);
  if (token) {
    const sessions = readSessions();
    if (sessions[token]) {
      delete sessions[token];
      writeSessions(sessions);
    }
  }
  send(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const { pathname } = url;

  if (pathname === '/api/auth/register' && req.method === 'POST') {
    try { await handleRegister(req, res); } catch (err) { send(res, 500, { error: err.message || 'Gagal daftar.' }); }
    return;
  }

  if (pathname === '/api/auth/login' && req.method === 'POST') {
    try { await handleLogin(req, res); } catch (err) { send(res, 500, { error: err.message || 'Gagal login.' }); }
    return;
  }

  if (pathname === '/api/auth/me' && req.method === 'GET') {
    try { await handleMe(req, res); } catch (err) { send(res, 500, { error: err.message || 'Gagal cek sesi.' }); }
    return;
  }

  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    try { await handleLogout(req, res); } catch (err) { send(res, 500, { error: err.message || 'Gagal logout.' }); }
    return;
  }

  if (pathname === '/api/health' && req.method === 'GET') {
    send(res, 200, { ok: true });
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    serveStatic(req, res, pathname);
    return;
  }

  send(res, 405, { error: 'Method not allowed' });
});

server.listen(PORT, HOST, () => {
  console.log(`Server berjalan di http://${HOST}:${PORT}`);
});
