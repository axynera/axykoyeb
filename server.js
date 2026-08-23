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

// Middleware parsing body untuk menerima JSON dari ChatGPT
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

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL || 'https://koyeb-web-terminal.koyeb.app/auth/github/callback',
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    if (!dynamicOwnerUsername) dynamicOwnerUsername = profile.username.toLowerCase();
    if (profile.username.toLowerCase() === dynamicOwnerUsername) return done(null, profile);
    return done(null, false, { message: 'Akses ditolak.' });
  }
));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/auth/github');
}

// Routes Auth Web Terminal
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email', 'repo'] }));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/' }), (req, res) => res.redirect('/'));
app.get('/logout', (req, res) => { dynamicOwnerUsername = null; req.logout(() => res.redirect('/')); });
app.get('/ping', (req, res) => res.status(200).send('OK'));

// =========================================================================
// CHATGPT DCR (Dynamic Client Registration) & OAUTH FIX
// =========================================================================

// 1. Metadata Server (Diperbarui agar ChatGPT mengenali fitur DCR)
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    resource: baseUrl,
    authorization_servers: [`${baseUrl}/oauth/auth`],
    registration_endpoint: `${baseUrl}/oauth/register`, // FIX: ChatGPT akan membaca ini untuk DCR
    token_endpoint: `${baseUrl}/oauth/token`
  });
});

// 2. DCR Registration Endpoint (ChatGPT akan hit ini untuk meminta Client ID)
app.post('/oauth/register', (req, res) => {
  // Memberikan Client ID dan Secret dinamis agar ChatGPT tidak error
  res.status(201).json({
    client_id: "chatgpt_mcp_client_" + Date.now(),
    client_secret: "secret_mcp_koyeb_" + Math.random().toString(36).substring(2),
    client_name: "ChatGPT Terminal Connector",
    redirect_uris: req.body.redirect_uris || ["https://chatgpt.com/connector/oauth/M5NWKmu0hXIX"]
  });
});

// 3. Authorization Endpoint
app.get('/oauth/auth', (req, res) => {
  const { redirect_uri, state } = req.query;
  res.send(`
    <div style="font-family: sans-serif; text-align: center; margin-top: 80px; background: #0d1117; color: #c9d1d9; padding: 40px; border-radius: 10px; max-width: 400px; margin: 80px auto; border: 1px solid #30363d;">
      <h2>Koneksi MCP Terminal</h2>
      <p style="color: #8b949e;">Izinkan ChatGPT mengakses Terminal Server Anda.</p>
      <form action="/oauth/approve" method="POST">
        <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}" />
        <input type="hidden" name="state" value="${state || ''}" />
        <button type="submit" style="padding: 12px 24px; background: #10a37f; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 15px; margin-top: 20px;">
          Setujui Koneksi
        </button>
      </form>
    </div>
  `);
});

// 4. Approval Redirect
app.post('/oauth/approve', (req, res) => {
  const { redirect_uri, state } = req.body;
  if (redirect_uri) {
    const separator = redirect_uri.includes('?') ? '&' : '?';
    return res.redirect(`${redirect_uri}${separator}code=auth_code_${Date.now()}&state=${state || ''}`);
  }
  res.send("Gagal mengalihkan. Redirect URI tidak ditemukan.");
});

// 5. Token Endpoint
app.post('/oauth/token', (req, res) => {
  res.json({
    access_token: "access_token_" + Date.now(),
    token_type: "Bearer",
    expires_in: 86400,
    refresh_token: "refresh_token_" + Date.now()
  });
});

// 6. SSE MCP Endpoint
app.get('/mcp/sse', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Koneksi ke ChatGPT berhasil!' })}\n\n`);
});

// =========================================================================

// Terminal UI & WebSocket
app.use('/', ensureAuthenticated, express.static('public'));
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

function startUptimeBots() {
  const appUrl = process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || process.env.KOYEB_PUBLIC_URL || 'http://localhost:8000';
  [3, 4, 5].forEach(minutes => {
    setInterval(() => {
      const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
      const client = target.startsWith('https') ? https : http;
      client.get(target, () => {}).on('error', () => {});
    }, minutes * 60 * 1000);
  });
}

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`Server port ${PORT}`);
  startUptimeBots();
});
