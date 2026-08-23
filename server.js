const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const pty = require('node-pty');
const os = require('os');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

let dynamicOwnerUsername = null;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'rahasia-terminal-koyeb-2026',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(obj, done));

// GitHub Strategy untuk Owner Terminal
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL || 'https://koyeb-web-terminal.koyeb.app/auth/github/callback',
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    if (!dynamicOwnerUsername) {
      dynamicOwnerUsername = profile.username.toLowerCase();
    }
    
    if (profile.username.toLowerCase() === dynamicOwnerUsername) {
      return done(null, profile);
    } else {
      return done(null, false, { message: 'Akses ditolak: Anda bukan owner.' });
    }
  }
));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/auth/github');
}

// Routes Autentikasi GitHub untuk Terminal
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email', 'repo'] }));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.get('/logout', (req, res) => {
  dynamicOwnerUsername = null; 
  req.logout(() => {
    res.redirect('/');
  });
});

// Endpoint untuk Bot Uptime Ping
app.get('/ping', (req, res) => {
  res.status(200).send('OK - Server is Alive');
});

// =========================================================================
// CHATGPT OAUTH CONNECTOR CALLBACK & MCP HANDLERS
// =========================================================================

// 1. Metadata Resource Server (Standar MCP/ChatGPT OAuth)
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    resource: baseUrl,
    authorization_servers: [`${baseUrl}/oauth/auth`]
  });
});

// 2. Authorization Endpoint (Menerima permintaan sambung dari ChatGPT)
app.get('/oauth/auth', (req, res) => {
  const { client_id, redirect_uri, state, response_type } = req.query;
  
  // Jika ChatGPT mengirimkan callback URL custom (seperti https://chatgpt.com/connector/oauth/M5NWKmu0hXIX)
  // Kita simpan di session/query untuk diredirect setelah user menyetujui
  res.send(`
    <div style="font-family: sans-serif; text-align: center; margin-top: 80px; background: #0d1117; color: #c9d1d9; padding: 40px; border-radius: 10px; max-width: 400px; margin-left: auto; margin-right: auto; border: 1px solid #30363d;">
      <h2>ChatGPT Connector Authentication</h2>
      <p style="font-size: 14px; color: #8b949e;">Hubungkan Plugin / MCP Anda ke ChatGPT</p>
      <form action="/oauth/approve" method="POST">
        <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}" />
        <input type="hidden" name="state" value="${state || ''}" />
        <button type="submit" style="display: inline-block; padding: 12px 24px; background: #10a37f; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px; margin-top: 20px;">
          Setujui & Hubungkan
        </button>
      </form>
    </div>
  `);
});

// 3. Proses Persetujuan & Redirect otomatis ke URL Callback ChatGPT
app.post('/oauth/approve', (req, res) => {
  const { redirect_uri, state } = req.body;
  const authCode = "chatgpt_oauth_auth_code_secure_" + Date.now();
  
  if (redirect_uri) {
    // Redirect langsung kembali ke callback ChatGPT (cth: https://chatgpt.com/connector/oauth/M5NWKmu0hXIX?code=...&state=...)
    const separator = redirect_uri.includes('?') ? '&' : '?';
    return res.redirect(`${redirect_uri}${separator}code=${authCode}&state=${state || ''}`);
  }
  
  res.send("Autentikasi berhasil, silakan kembali ke ChatGPT.");
});

// 4. Token Exchange Endpoint (Ditanyai oleh ChatGPT setelah mendapatkan authorization code)
app.post('/oauth/token', (req, res) => {
  res.json({
    access_token: "chatgpt_mcp_access_token_active_" + Date.now(),
    token_type: "Bearer",
    expires_in: 86400,
    refresh_token: "chatgpt_mcp_refresh_token_xyz"
  });
});

// 5. SSE / Endpoint komunikasi MCP Plugin dengan ChatGPT
app.get('/mcp/sse', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.write(`data: ${JSON.stringify({ type: 'connected', message: 'MCP Server siap dan terhubung dengan ChatGPT' })}\n\n`);
});
// =========================================================================

// Proteksi Tampilan UI Terminal (Hanya untuk Owner yang login GitHub)
app.use('/', ensureAuthenticated, express.static('public'));

// Terminal WebSocket Setup (node-pty)
const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';

io.on('connection', (socket) => {
  const ptyProcess = pty.spawn(shell, [], {
    name: 'xterm-color',
    cols: 80,
    rows: 30,
    cwd: process.env.HOME || '/app',
    env: process.env
  });

  ptyProcess.onData((data) => socket.emit('output', data));
  socket.on('input', (data) => ptyProcess.write(data));
  socket.on('resize', (size) => ptyProcess.resize(size.cols, size.rows));
  socket.on('disconnect', () => ptyProcess.kill());
});

// 3 Robot Uptime Ping (Agar server Koyeb aktif terus 24/7)
function startUptimeBots() {
  const appUrl = process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || process.env.KOYEB_PUBLIC_URL || 'http://localhost:8000';
  
  setInterval(() => {
    const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
    const client = target.startsWith('https') ? https : http;
    client.get(target, (res) => {}).on('error', () => {});
  }, 3 * 60 * 1000);

  setInterval(() => {
    const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
    const client = target.startsWith('https') ? https : http;
    client.get(target, (res) => {}).on('error', () => {});
  }, 4 * 60 * 1000);

  setInterval(() => {
    const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
    const client = target.startsWith('https') ? https : http;
    client.get(target, (res) => {}).on('error', () => {});
  }, 5 * 60 * 1000);
  
  console.log('🤖 3 Robot Uptime Ping aktif!');
}

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
  startUptimeBots();
});
