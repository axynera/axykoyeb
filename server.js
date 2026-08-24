'use strict';

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
const { execFile } = require('child_process');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true } });

const PORT = Number(process.env.PORT || 8000);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const OAUTH_SIGNING_SECRET = process.env.OAUTH_SIGNING_SECRET || SESSION_SECRET;
const TERMINAL_PASSWORD = process.env.TERMINAL_PASSWORD || SESSION_SECRET;
const TERMINAL_OWNER = String(process.env.TERMINAL_OWNER || '').toLowerCase() || null;
const MCP_PROTOCOL_CURRENT = '2026-07-28';
const MCP_PROTOCOL_LEGACY = '2025-11-25';
const SERVER_NAME = 'Koyeb Web Terminal MCP';
const SERVER_VERSION = '2.1.1';
const MCP_EXEC_TIMEOUT_MS = Number(process.env.MCP_EXEC_TIMEOUT_MS || 120000);

if (!process.env.OAUTH_SIGNING_SECRET && !process.env.SESSION_SECRET) console.warn('[SECURITY] Set OAUTH_SIGNING_SECRET in Koyeb so OAuth survives restarts.');

app.disable('x-powered-by');
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json({ limit: '2mb' }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false, proxy: true, cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' } }));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

let dynamicOwnerUsername = TERMINAL_OWNER;
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({ clientID: process.env.GITHUB_CLIENT_ID, clientSecret: process.env.GITHUB_CLIENT_SECRET, callbackURL: process.env.GITHUB_CALLBACK_URL || 'https://koyeb-web-terminal.koyeb.app/auth/github/callback', passReqToCallback: true }, (req, accessToken, refreshToken, profile, done) => {
    const username = String(profile.username || '').toLowerCase();
    if (!username) return done(null, false, { message: 'GitHub username tidak ditemukan.' });
    if (!dynamicOwnerUsername) { dynamicOwnerUsername = username; console.log(`[AUTH] Owner di-set ke: ${username}`); }
    if (username === dynamicOwnerUsername) { console.log(`[AUTH] Owner login: ${username}`); return done(null, profile); }
    console.log(`[AUTH] Akses ditolak untuk user: ${username}`);
    return done(null, false, { message: 'Akses ditolak: Anda bukan owner dari terminal ini.' });
  }));
}

function ensureAuthenticated(req, res, next) { if (req.isAuthenticated()) return next(); return res.redirect('/auth/github'); }
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  app.get('/auth/github', passport.authenticate('github', { scope: ['user:email', 'repo'] }));
  app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/' }), (req, res) => res.redirect('/'));
} else {
  app.get('/auth/github', (req, res) => res.status(503).send('GitHub OAuth belum dikonfigurasi. Set GITHUB_CLIENT_ID dan GITHUB_CLIENT_SECRET.'));
}
app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));
app.get('/ping', (req, res) => res.status(200).send('OK - Server is Alive'));
app.get('/health', (req, res) => res.json({ ok: true, service: SERVER_NAME, version: SERVER_VERSION, mcp: true, oauth: true, protocol: MCP_PROTOCOL_CURRENT, time: new Date().toISOString() }));

function baseUrl(req) { const proto = (req.get('x-forwarded-proto') || req.protocol).split(',')[0].trim(); const host = req.get('x-forwarded-host') || req.get('host'); return `${proto}://${host}`; }
function b64url(value) { return Buffer.from(value).toString('base64url'); }
function unb64url(value) { return Buffer.from(value, 'base64url').toString('utf8'); }
function hmac(value) { return crypto.createHmac('sha256', OAUTH_SIGNING_SECRET).update(value).digest('base64url'); }
function randomId(bytes = 24) { return crypto.randomBytes(bytes).toString('hex'); }
function safeEqual(a, b) { if (typeof a !== 'string' || typeof b !== 'string') return false; const aa = Buffer.from(a); const bb = Buffer.from(b); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); }
function signObject(payload) { const body = b64url(JSON.stringify(payload)); return `${body}.${hmac(body)}`; }
function verifyObject(token, expectedType) { try { const [body, sig] = String(token || '').split('.'); if (!body || !sig || !safeEqual(sig, hmac(body))) return null; const payload = JSON.parse(unb64url(body)); if (expectedType && payload.typ !== expectedType) return null; if (!payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) return null; return payload; } catch (_) { return null; } }
function createClientId(redirectUris, clientName) { return `client_${signObject({ typ: 'client', id: randomId(16), ru: redirectUris, name: clientName, exp: Math.floor(Date.now() / 1000) + 3650 * 86400 })}`; }
function parseClientId(clientId) { const prefix = 'client_'; if (!String(clientId || '').startsWith(prefix)) return null; return verifyObject(String(clientId).slice(prefix.length), 'client'); }
function clientSecretFor(clientId) { return `secret_${hmac(`client:${clientId}`)}`; }
function clientFromCredentials(clientId, clientSecret) { const meta = parseClientId(clientId); if (!meta || !clientSecret || !safeEqual(clientSecret, clientSecretFor(clientId))) return null; return { clientId, clientSecret, redirectUris: meta.ru || [], clientName: meta.name || 'ChatGPT Terminal Connector' }; }

app.get('/.well-known/oauth-authorization-server', (req, res) => { const base = baseUrl(req); res.set('Cache-Control', 'no-store'); res.json({ issuer: base, authorization_endpoint: `${base}/oauth/auth`, token_endpoint: `${base}/oauth/token`, registration_endpoint: `${base}/oauth/register`, response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'], token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'], code_challenge_methods_supported: ['S256'], scopes_supported: ['terminal'] }); });
app.get('/.well-known/oauth-protected-resource', (req, res) => { const base = baseUrl(req); res.set('Cache-Control', 'no-store'); res.json({ resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: ['terminal'], bearer_methods_supported: ['header'] }); });
app.get('/.well-known/oauth-protected-resource/mcp', (req, res) => { const base = baseUrl(req); res.set('Cache-Control', 'no-store'); res.json({ resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: ['terminal'], bearer_methods_supported: ['header'] }); });

app.post('/oauth/register', (req, res) => {
  const redirectUris = Array.isArray(req.body.redirect_uris) ? req.body.redirect_uris.map(String) : [];
  if (!redirectUris.length) return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' });
  const clientName = String(req.body.client_name || 'ChatGPT Terminal Connector');
  const clientId = createClientId(redirectUris, clientName);
  const clientSecret = clientSecretFor(clientId);
  console.log(`[OAUTH:DCR] Registered client=${clientId} name=${clientName}`);
  return res.status(201).json({ client_id: clientId, client_secret: clientSecret, client_name: clientName, redirect_uris: redirectUris, token_endpoint_auth_method: 'client_secret_post', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], client_id_issued_at: Math.floor(Date.now() / 1000), client_secret_expires_at: 0 });
});

function getClient(req) {
  let clientId = req.body?.client_id || req.query?.client_id;
  let clientSecret = req.body?.client_secret || req.query?.client_secret;
  const auth = req.get('authorization') || '';
  if (auth.startsWith('Basic ')) { try { const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8'); const i = decoded.indexOf(':'); if (i >= 0) { clientId = decoded.slice(0, i); clientSecret = decoded.slice(i + 1); } } catch (_) {} }
  return clientFromCredentials(clientId, clientSecret);
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]); }
function passwordPage(res, fields, error = '') { const hidden = Object.entries(fields).map(([k,v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join(''); res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login Terminal</title></head><body style="font-family:sans-serif;text-align:center;margin:60px auto;max-width:430px;background:#0d1117;color:#c9d1d9;padding:30px"><h2>Login Terminal</h2><p>Masukkan password untuk melanjutkan koneksi ChatGPT.</p>${error ? `<p style="color:#ff6b6b">${escapeHtml(error)}</p>` : ''}<form action="/oauth/login" method="POST">${hidden}<input type="password" name="terminal_password" placeholder="Password" autocomplete="current-password" required style="padding:12px;width:90%;margin:15px 0"><button type="submit" style="padding:12px 24px;background:#10a37f;color:white;border:0;border-radius:6px;font-weight:bold">Login</button></form></body></html>`); }

app.get('/oauth/auth', (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = req.query;
  const clientMeta = parseClientId(client_id);
  if (response_type !== 'code') return res.status(400).send('response_type harus code.');
  if (!clientMeta) return res.status(400).send('Client OAuth tidak dikenal.');
  if (!Array.isArray(clientMeta.ru) || !clientMeta.ru.includes(String(redirect_uri))) return res.status(400).send('redirect_uri tidak terdaftar.');
  if (code_challenge_method !== 'S256' || !code_challenge) return res.status(400).send('PKCE S256 diperlukan.');
  return passwordPage(res, { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope: scope || 'terminal' });
});

app.post('/oauth/login', (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, terminal_password } = req.body;
  const clientMeta = parseClientId(client_id);
  if (!clientMeta || !Array.isArray(clientMeta.ru) || !clientMeta.ru.includes(String(redirect_uri)) || code_challenge_method !== 'S256' || !code_challenge) return res.status(400).send('Permintaan OAuth tidak valid.');
  if (!TERMINAL_PASSWORD) return res.status(500).send('TERMINAL_PASSWORD/SESSION_SECRET belum dikonfigurasi.');
  if (!safeEqual(terminal_password, TERMINAL_PASSWORD)) return passwordPage(res, { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope }, 'Password salah.');
  const code = signObject({ typ: 'code', cid: client_id, ru: String(redirect_uri), cc: String(code_challenge), sc: String(scope || 'terminal'), exp: Math.floor(Date.now() / 1000) + 300, jti: randomId(12) });
  const url = new URL(redirect_uri); url.searchParams.set('code', code); if (state) url.searchParams.set('state', state);
  console.log(`[OAUTH:AUTH] Authorization approved client=${client_id}`);
  return res.redirect(url.toString());
});

app.post('/oauth/token', (req, res) => {
  const grantType = req.body?.grant_type;
  console.log(`[OAUTH:TOKEN] grant_type=${grantType || 'missing'}`);
  const client = getClient(req);
  if (!client) { console.warn('[OAUTH:TOKEN] invalid_client'); return res.status(401).json({ error: 'invalid_client' }); }
  if (grantType === 'authorization_code') {
    const record = verifyObject(req.body.code, 'code');
    if (!record || record.cid !== client.clientId || record.ru !== String(req.body.redirect_uri)) return res.status(400).json({ error: 'invalid_grant' });
    if (!req.body.code_verifier) return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier is required' });
    const challenge = crypto.createHash('sha256').update(req.body.code_verifier).digest('base64url');
    if (!safeEqual(challenge, record.cc)) { console.warn(`[OAUTH:PKCE] failed client=${client.clientId}`); return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }); }
    const now = Math.floor(Date.now() / 1000);
    const accessToken = signObject({ typ: 'access', cid: client.clientId, sc: record.sc, exp: now + 3600, jti: randomId(12) });
    const refreshToken = signObject({ typ: 'refresh', cid: client.clientId, sc: record.sc, exp: now + 30 * 86400, jti: randomId(12) });
    console.log(`[OAUTH:ACCESS] issued client=${client.clientId}`);
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: refreshToken, scope: record.sc });
  }
  if (grantType === 'refresh_token') {
    const record = verifyObject(req.body.refresh_token, 'refresh');
    if (!record || record.cid !== client.clientId) return res.status(400).json({ error: 'invalid_grant' });
    const now = Math.floor(Date.now() / 1000);
    const accessToken = signObject({ typ: 'access', cid: client.clientId, sc: record.sc, exp: now + 3600, jti: randomId(12) });
    const refreshToken = signObject({ typ: 'refresh', cid: client.clientId, sc: record.sc, exp: now + 30 * 86400, jti: randomId(12) });
    console.log(`[OAUTH:REFRESH] rotated client=${client.clientId}`);
    return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: refreshToken, scope: record.sc });
  }
  return res.status(400).json({ error: 'unsupported_grant_type' });
});

function requireBearer(req, res, next) {
  const header = req.get('authorization') || '';
  if (!header.startsWith('Bearer ')) { res.set('WWW-Authenticate', `Bearer realm="mcp", resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`); return res.status(401).json({ error: 'unauthorized', error_description: 'Bearer token required' }); }
  const record = verifyObject(header.slice(7).trim(), 'access');
  if (!record) { res.set('WWW-Authenticate', 'Bearer error="invalid_token"'); return res.status(401).json({ error: 'invalid_token' }); }
  req.oauth = record;
  console.log(`[MCP:AUTH] token accepted client=${record.cid}`);
  next();
}

function jsonRpcResult(id, result) { return { jsonrpc: '2.0', id, result }; }
function jsonRpcError(id, code, message, data) { const error = { code, message }; if (data !== undefined) error.data = data; return { jsonrpc: '2.0', id: id ?? null, error }; }
const MCP_TOOLS = [
  { name: 'terminal_exec', description: 'Execute a shell command inside the Koyeb terminal container and return stdout/stderr.', inputSchema: { type: 'object', properties: { command: { type: 'string' }, cwd: { type: 'string' }, timeout_ms: { type: 'integer', minimum: 1000, maximum: 300000 } }, required: ['command'], additionalProperties: false }, annotations: { readOnlyHint: false, destructiveHint: true } },
  { name: 'terminal_pwd', description: 'Return the current working directory of the terminal container.', inputSchema: { type: 'object', properties: {}, additionalProperties: false }, annotations: { readOnlyHint: true } },
  { name: 'terminal_env', description: 'Return a safe runtime environment summary without exposing secret values.', inputSchema: { type: 'object', properties: {}, additionalProperties: false }, annotations: { readOnlyHint: true } }
];
function getDefaultCwd() { return process.env.HOME || process.cwd() || '/app'; }
function executeShellCommand(command, cwd, timeoutMs) { return new Promise(resolve => { const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash'; const args = os.platform() === 'win32' ? ['-NoLogo','-NoProfile','-NonInteractive','-Command',command] : ['-lc',command]; const startedAt = Date.now(); const child = execFile(shell, args, { cwd: cwd || getDefaultCwd(), env: process.env, timeout: Math.min(Math.max(Number(timeoutMs) || MCP_EXEC_TIMEOUT_MS, 1000), 300000), maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => resolve({ exitCode: typeof error?.code === 'number' ? error.code : (error ? 1 : 0), stdout: String(stdout || ''), stderr: String(stderr || ''), duration_ms: Date.now() - startedAt, timedOut: error?.killed === true })); child.on('error', error => resolve({ exitCode: 1, stdout: '', stderr: String(error.message || error), duration_ms: Date.now() - startedAt, timedOut: false })); }); }
async function handleToolCall(name, args = {}) {
  if (name === 'terminal_pwd') return { content: [{ type: 'text', text: getDefaultCwd() }], structuredContent: { cwd: getDefaultCwd() } };
  if (name === 'terminal_env') { const safeKeys = ['NODE_ENV','PORT','HOME','HOSTNAME','PWD','SHELL','USER','LANG','TZ']; const environment = Object.fromEntries(safeKeys.filter(k => Object.prototype.hasOwnProperty.call(process.env, k)).map(k => [k, process.env[k]])); Object.assign(environment, { platform: process.platform, arch: process.arch, node: process.version }); return { content: [{ type: 'text', text: JSON.stringify(environment, null, 2) }], structuredContent: { environment } }; }
  if (name === 'terminal_exec') { if (typeof args.command !== 'string' || !args.command.trim()) return { isError: true, content: [{ type: 'text', text: 'Parameter "command" wajib diisi.' }] }; const result = await executeShellCommand(args.command, args.cwd || getDefaultCwd(), args.timeout_ms); const output = [`exit_code: ${result.exitCode}`, `duration_ms: ${result.duration_ms}`, result.timedOut ? 'timed_out: true' : '', '', '--- stdout ---', result.stdout || '(empty)', '', '--- stderr ---', result.stderr || '(empty)'].filter(Boolean).join('\n'); return { isError: result.exitCode !== 0, content: [{ type: 'text', text: output }], structuredContent: { exit_code: result.exitCode, stdout: result.stdout, stderr: result.stderr, duration_ms: result.duration_ms, timed_out: result.timedOut } }; }
  return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
}
async function handleMcpMessage(message) {
  if (!message || message.jsonrpc !== '2.0') return jsonRpcError(message?.id ?? null, -32600, 'Invalid Request');
  const id = Object.prototype.hasOwnProperty.call(message, 'id') ? message.id : null;
  const method = message.method; const params = message.params || {};
  if (method === 'server/discover') return jsonRpcResult(id, { protocolVersion: MCP_PROTOCOL_CURRENT, capabilities: { tools: { listChanged: false } }, serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }, tools: MCP_TOOLS });
  if (method === 'initialize') return jsonRpcResult(id, { protocolVersion: MCP_PROTOCOL_LEGACY, capabilities: { tools: { listChanged: false } }, serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }, instructions: 'Koyeb Web Terminal MCP menyediakan terminal_exec, terminal_pwd, dan terminal_env.' });
  if (method === 'notifications/initialized') return null;
  if (method === 'ping') return jsonRpcResult(id, {});
  if (method === 'tools/list') { console.log('[MCP:TOOLS_LIST]'); return jsonRpcResult(id, { tools: MCP_TOOLS }); }
  if (method === 'tools/call') { console.log(`[MCP:TOOLS_CALL] ${params.name || 'unknown'}`); if (!MCP_TOOLS.some(t => t.name === params.name)) return jsonRpcError(id, -32602, `Unknown tool: ${params.name}`); try { return jsonRpcResult(id, await handleToolCall(params.name, params.arguments || {})); } catch (error) { console.error('[MCP:TOOLS_CALL] error', error); return jsonRpcError(id, -32603, 'Internal error', { message: String(error?.message || error) }); } }
  if (method === 'resources/list') return jsonRpcResult(id, { resources: [] });
  if (method === 'prompts/list') return jsonRpcResult(id, { prompts: [] });
  if (typeof method === 'string' && method.startsWith('notifications/')) return null;
  return jsonRpcError(id, -32601, `Method not found: ${method}`);
}
async function handleMcpRequest(req, res) { const body = req.body; if (Array.isArray(body)) { const responses = []; for (const message of body) { const response = await handleMcpMessage(message); if (response !== null) responses.push(response); } if (!responses.length) return res.status(202).end(); return sendMcpJson(res, responses); } const response = await handleMcpMessage(body); if (response === null) return res.status(202).end(); return sendMcpJson(res, response); }
function sendMcpJson(res, payload) { res.status(200).set({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'MCP-Protocol-Version': MCP_PROTOCOL_CURRENT }).json(payload); }

app.post('/mcp', requireBearer, async (req, res) => {
  const headerMethod = req.get('Mcp-Method'); const bodyMethod = req.body?.method;
  if (headerMethod && bodyMethod && headerMethod !== bodyMethod) return res.status(400).json(jsonRpcError(req.body?.id ?? null, -32600, 'Mcp-Method header does not match JSON-RPC method'));
  const protocolVersion = req.get('MCP-Protocol-Version');
  if (protocolVersion && ![MCP_PROTOCOL_CURRENT, MCP_PROTOCOL_LEGACY].includes(protocolVersion)) console.log(`[MCP] unknown protocol version=${protocolVersion}`);
  console.log(`[MCP] POST ${bodyMethod || 'unknown'}`);
  return handleMcpRequest(req, res);
});
app.get('/mcp', requireBearer, (req, res) => res.status(405).json({ error: 'method_not_allowed', message: 'Use POST /mcp for Streamable HTTP.' }));
app.delete('/mcp', requireBearer, (req, res) => res.status(405).json({ error: 'method_not_allowed' }));
app.get('/mcp/sse', requireBearer, (req, res) => { res.set({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' }); res.flushHeaders(); res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/ready' })}\n\n`); const heartbeat = setInterval(() => { if (res.writableEnded) return clearInterval(heartbeat); res.write(`: heartbeat ${Date.now()}\n\n`); }, 25000); req.on('close', () => clearInterval(heartbeat)); });
app.post('/mcp/messages', requireBearer, async (req, res) => handleMcpRequest(req, res));
app.get('/mcp/info', requireBearer, (req, res) => res.json({ ok: true, service: SERVER_NAME, version: SERVER_VERSION, protocol: MCP_PROTOCOL_CURRENT, transport: 'Streamable HTTP', endpoint: '/mcp', tools: MCP_TOOLS.map(t => t.name) }));

app.use('/', ensureAuthenticated, express.static('public'));
const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';
io.on('connection', socket => { const ptyProcess = pty.spawn(shell, [], { name: 'xterm-color', cols: 80, rows: 30, cwd: getDefaultCwd(), env: process.env }); ptyProcess.onData(data => socket.emit('output', data)); socket.on('input', data => { if (typeof data === 'string') ptyProcess.write(data); }); socket.on('resize', size => { if (!size) return; ptyProcess.resize(Math.max(1, Math.min(500, Number(size.cols) || 80)), Math.max(1, Math.min(500, Number(size.rows) || 30))); }); socket.on('disconnect', () => { try { ptyProcess.kill(); } catch (_) {} }); });

app.use((err, req, res, next) => { console.error('[HTTP ERROR]', err); if (res.headersSent) return next(err); res.status(500).json({ error: 'internal_server_error', message: process.env.NODE_ENV === 'production' ? 'Internal server error' : String(err?.message || err) }); });

function startUptimeBots() { const appUrl = process.env.APP_URL || process.env.KOYEB_PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`; for (const minutes of [3,4,5]) setInterval(() => { const target = `${appUrl.includes('http') ? appUrl.replace(/\/$/, '') : `https://${appUrl}`}/ping`; const client = target.startsWith('https') ? https : http; client.get(target, response => { console.log(`[Uptime Bot ${minutes}m] Ping status: ${response.statusCode}`); response.resume(); }).on('error', () => {}); }, minutes * 60 * 1000); console.log('🤖 3 Robot Uptime Ping berhasil diaktifkan!'); }

server.listen(PORT, '0.0.0.0', () => { console.log('=========================================='); console.log(`✅ ${SERVER_NAME}`); console.log(`✅ Port: ${PORT}`); console.log('✅ OAuth: stateless + PKCE'); console.log(`✅ MCP: /mcp (${MCP_PROTOCOL_CURRENT})`); console.log(`✅ Tools: ${MCP_TOOLS.map(t => t.name).join(', ')}`); console.log('=========================================='); startUptimeBots(); });