const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const pty = require('node-pty');
const os = require('os');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

let dynamicOwnerUsername = null;
const oauthClients = new Map();
const authorizationCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL || 'https://koyeb-web-terminal.koyeb.app/auth/github/callback',
  passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
  if (!dynamicOwnerUsername) {
    dynamicOwnerUsername = profile.username.toLowerCase();
    console.log(`[AUTH] Owner di-set ke: ${dynamicOwnerUsername}`);
  }
  if (profile.username.toLowerCase() === dynamicOwnerUsername) return done(null, profile);
  console.log(`[AUTH] Akses ditolak untuk user: ${profile.username}`);
  return done(null, false, { message: 'Akses ditolak: Anda bukan owner dari terminal ini.' });
}));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/auth/github');
}

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email', 'repo'] }));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/' }), (req, res) => res.redirect('/'));
app.get('/logout', (req, res) => {
  dynamicOwnerUsername = null;
  req.logout(() => res.redirect('/'));
});

app.get('/ping', (req, res) => res.status(200).send('OK - Server is Alive'));

// -----------------------------------------------------------------
// OAuth 2.0 / DCR FOR CHATGPT MCP CONNECTOR
// -----------------------------------------------------------------

function baseUrl(req) {
  const forwardedProto = req.get('x-forwarded-proto');
  const proto = forwardedProto ? forwardedProto.split(',')[0].trim() : req.protocol;
  return `${proto}://${req.get('host')}`;
}

function randomToken(prefix) {
  return `${prefix}_${crypto.randomBytes(32).toString('hex')}`;
}

function cleanupOAuthState() {
  const now = Date.now();
  for (const [key, value] of authorizationCodes) if (value.expiresAt <= now) authorizationCodes.delete(key);
  for (const [key, value] of accessTokens) if (value.expiresAt <= now) accessTokens.delete(key);
  for (const [key, value] of refreshTokens) if (value.expiresAt <= now) refreshTokens.delete(key);
}
setInterval(cleanupOAuthState, 60 * 1000).unref();

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const base = baseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/auth`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['terminal']
  });
});

app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const base = baseUrl(req);
  res.json({
    resource: `${base}/mcp`,
    authorization_servers: [base]
  });
});

app.post('/oauth/register', (req, res) => {
  const redirectUris = Array.isArray(req.body.redirect_uris) ? req.body.redirect_uris : [];
  if (!redirectUris.length) return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' });

  const clientId = `client_${crypto.randomBytes(16).toString('hex')}`;
  const clientSecret = randomToken('secret');
  oauthClients.set(clientId, {
    clientId,
    clientSecret,
    redirectUris,
    clientName: req.body.client_name || 'ChatGPT Terminal Connector',
    tokenEndpointAuthMethod: req.body.token_endpoint_auth_method || 'client_secret_post'
  });

  console.log(`[DCR] Registered client: ${clientId}`);
  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name: req.body.client_name || 'ChatGPT Terminal Connector',
    redirect_uris: redirectUris,
    token_endpoint_auth_method: 'client_secret_post',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code']
  });
});

function getClient(req) {
  const auth = req.get('authorization');
  if (auth && auth.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
      const separator = decoded.indexOf(':');
      if (separator >= 0) return oauthClients.get(decoded.slice(0, separator));
    } catch (_) {}
  }
  return oauthClients.get(req.body.client_id || req.query.client_id);
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a); const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

app.get('/oauth/auth', (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = req.query;
  const client = oauthClients.get(client_id);
  if (response_type !== 'code') return res.status(400).send('response_type harus code.');
  if (!client) return res.status(400).send('Client OAuth tidak dikenal.');
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send('redirect_uri tidak terdaftar.');
  if (code_challenge_method && code_challenge_method !== 'S256') return res.status(400).send('Hanya PKCE S256 yang didukung.');
  if (!code_challenge) return res.status(400).send('PKCE code_challenge diperlukan.');

  const esc = value => String(value || '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
  res.send(`<!doctype html><html><body style="font-family:sans-serif;text-align:center;margin:80px auto;max-width:480px;background:#0d1117;color:#c9d1d9;padding:40px"><h2>Koneksi MCP ChatGPT</h2><p>Izinkan ChatGPT mengakses terminal Anda?</p><form action="/oauth/approve" method="POST"><input type="hidden" name="client_id" value="${esc(client_id)}"><input type="hidden" name="redirect_uri" value="${esc(redirect_uri)}"><input type="hidden" name="state" value="${esc(state)}"><input type="hidden" name="code_challenge" value="${esc(code_challenge)}"><input type="hidden" name="code_challenge_method" value="S256"><input type="hidden" name="scope" value="${esc(scope || 'terminal')}"><button type="submit" style="padding:12px 24px;background:#10a37f;color:white;border:0;border-radius:6px;font-weight:bold">Setujui & Hubungkan</button></form></body></html>`);
});

app.post('/oauth/approve', (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = req.body;
  const client = oauthClients.get(client_id);
  if (!client || !client.redirectUris.includes(redirect_uri) || !code_challenge || code_challenge_method !== 'S256') return res.status(400).send('Permintaan OAuth tidak valid.');

  const code = randomToken('code');
  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    scope: scope || 'terminal',
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  console.log(`[OAUTH] Authorization approved for ${client_id}`);
  res.redirect(url.toString());
});

app.post('/oauth/token', (req, res) => {
  const grantType = req.body.grant_type;
  const client = getClient(req);
  if (!client) return res.status(401).json({ error: 'invalid_client' });

  if (grantType === 'authorization_code') {
    const { code, redirect_uri, code_verifier } = req.body;
    const record = authorizationCodes.get(code);
    if (!record || record.expiresAt <= Date.now() || record.clientId !== client.clientId || record.redirectUri !== redirect_uri) return res.status(400).json({ error: 'invalid_grant' });
    if (!code_verifier) return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier is required' });
    const challenge = crypto.createHash('sha256').update(code_verifier).digest('base64url');
    if (!safeEqual(challenge, record.codeChallenge)) return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });

    authorizationCodes.delete(code);
    const accessToken = randomToken('access');
    const refreshToken = randomToken('refresh');
    accessTokens.set(accessToken, { clientId: client.clientId, scope: record.scope, expiresAt: Date.now() + 3600 * 1000 });
    refreshTokens.set(refreshToken, { clientId: client.clientId, scope: record.scope, expiresAt: Date.now() + 30 * 24 * 3600 * 1000 });
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: refreshToken, scope: record.scope });
  }

  if (grantType === 'refresh_token') {
    const oldRefresh = req.body.refresh_token;
    const record = refreshTokens.get(oldRefresh);
    if (!record || record.expiresAt <= Date.now() || record.clientId !== client.clientId) return res.status(400).json({ error: 'invalid_grant' });
    refreshTokens.delete(oldRefresh);
    const accessToken = randomToken('access');
    const refreshToken = randomToken('refresh');
    accessTokens.set(accessToken, { clientId: client.clientId, scope: record.scope, expiresAt: Date.now() + 3600 * 1000 });
    refreshTokens.set(refreshToken, { clientId: client.clientId, scope: record.scope, expiresAt: Date.now() + 30 * 24 * 3600 * 1000 });
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: refreshToken, scope: record.scope });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

function requireBearer(req, res, next) {
  const header = req.get('authorization') || '';
  if (!header.startsWith('Bearer ')) {
    res.set('WWW-Authenticate', 'Bearer');
    return res.status(401).json({ error: 'unauthorized', error_description: 'Bearer token required' });
  }
  const token = header.slice(7).trim();
  const record = accessTokens.get(token);
  if (!record || record.expiresAt <= Date.now()) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
    return res.status(401).json({ error: 'invalid_token' });
  }
  req.oauth = record;
  next();
}

app.get('/mcp/sse', requireBearer, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  res.write(`data: ${JSON.stringify({ type: 'connected', message: 'MCP Server siap dan terhubung dengan ChatGPT!' })}\n\n`);
});

app.get('/mcp', requireBearer, (req, res) => res.json({ ok: true, service: 'Koyeb Web Terminal MCP', scope: req.oauth.scope }));

// -----------------------------------------------------------------
// WEB TERMINAL INTERFACE & WEBSOCKET SETUP
// -----------------------------------------------------------------
app.use('/', ensureAuthenticated, express.static('public'));

const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';
io.on('connection', socket => {
  console.log('[TERMINAL] Koneksi WebSocket baru ke Terminal');
  const ptyProcess = pty.spawn(shell, [], { name: 'xterm-color', cols: 80, rows: 30, cwd: process.env.HOME || '/app', env: process.env });
  ptyProcess.onData(data => socket.emit('output', data));
  socket.on('input', data => ptyProcess.write(data));
  socket.on('resize', size => ptyProcess.resize(size.cols, size.rows));
  socket.on('disconnect', () => ptyProcess.kill());
});

function startUptimeBots() {
  const appUrl = process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || process.env.KOYEB_PUBLIC_URL || 'http://localhost:8000';
  for (const minutes of [3, 4, 5]) {
    setInterval(() => {
      const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
      const client = target.startsWith('https') ? https : http;
      client.get(target, res => console.log(`[Uptime Bot ${minutes}m] Ping status: ${res.statusCode}`)).on('error', () => {});
    }, minutes * 60 * 1000);
  }
  console.log('🤖 3 Robot Uptime Ping berhasil diaktifkan!');
}

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`✅ Server berjalan di port ${PORT}`);
  startUptimeBots();
});
