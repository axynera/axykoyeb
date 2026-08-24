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

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true
  }
});

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 8000);

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString('hex');

const TERMINAL_PASSWORD =
  process.env.TERMINAL_PASSWORD ||
  SESSION_SECRET;

const MCP_PROTOCOL_CURRENT = '2026-07-28';
const MCP_PROTOCOL_LEGACY = '2025-11-25';

const SERVER_NAME = 'Koyeb Web Terminal MCP';
const SERVER_VERSION = '2.0.0';

/*
 * Optional safety limit for MCP command execution.
 * Set MCP_EXEC_TIMEOUT_MS in Koyeb if you want another value.
 */
const MCP_EXEC_TIMEOUT_MS = Number(
  process.env.MCP_EXEC_TIMEOUT_MS || 120000
);

/* =========================================================
   STATE
========================================================= */

let dynamicOwnerUsername = null;

const oauthClients = new Map();
const authorizationCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

/* =========================================================
   EXPRESS
========================================================= */

app.disable('x-powered-by');

app.set('trust proxy', true);

app.use(express.urlencoded({
  extended: true,
  limit: '2mb'
}));

app.use(express.json({
  limit: '2mb'
}));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

/* =========================================================
   GITHUB AUTH
========================================================= */

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL:
      process.env.GITHUB_CALLBACK_URL ||
      'https://koyeb-web-terminal.koyeb.app/auth/github/callback',
    passReqToCallback: true
  }, (req, accessToken, refreshToken, profile, done) => {

    const username = String(profile.username || '').toLowerCase();

    if (!username) {
      return done(null, false, {
        message: 'GitHub username tidak ditemukan.'
      });
    }

    /*
     * First successful login becomes owner.
     *
     * For production you can set:
     *
     * TERMINAL_OWNER=yourgithubusername
     *
     * to make the owner persistent across restarts.
     */
    const configuredOwner =
      process.env.TERMINAL_OWNER
        ? process.env.TERMINAL_OWNER.toLowerCase()
        : null;

    if (configuredOwner) {
      dynamicOwnerUsername = configuredOwner;
    }

    if (!dynamicOwnerUsername) {
      dynamicOwnerUsername = username;
      console.log(`[AUTH] Owner di-set ke: ${dynamicOwnerUsername}`);
    }

    if (username === dynamicOwnerUsername) {
      console.log(`[AUTH] Owner login: ${username}`);
      return done(null, profile);
    }

    console.log(`[AUTH] Akses ditolak untuk user: ${username}`);

    return done(null, false, {
      message: 'Akses ditolak: Anda bukan owner dari terminal ini.'
    });
  }));
}

/* =========================================================
   WEB AUTH
========================================================= */

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  return res.redirect('/auth/github');
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {

  app.get(
    '/auth/github',
    passport.authenticate('github', {
      scope: ['user:email', 'repo']
    })
  );

  app.get(
    '/auth/github/callback',
    passport.authenticate('github', {
      failureRedirect: '/'
    }),
    (req, res) => {
      res.redirect('/');
    }
  );

} else {

  /*
   * Jangan bikin server crash kalau GitHub OAuth
   * belum dikonfigurasi.
   */
  app.get('/auth/github', (req, res) => {
    res.status(503).send(
      'GitHub OAuth belum dikonfigurasi. Set GITHUB_CLIENT_ID dan GITHUB_CLIENT_SECRET.'
    );
  });

}

app.get('/logout', (req, res) => {
  dynamicOwnerUsername = null;

  req.logout(() => {
    res.redirect('/');
  });
});

/* =========================================================
   HEALTH
========================================================= */

app.get('/ping', (req, res) => {
  res.status(200).send('OK - Server is Alive');
});

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: SERVER_NAME,
    version: SERVER_VERSION,
    mcp: true,
    protocol: MCP_PROTOCOL_CURRENT,
    time: new Date().toISOString()
  });
});

/* =========================================================
   BASE URL
========================================================= */

function baseUrl(req) {
  const forwardedProto = req.get('x-forwarded-proto');

  const proto = forwardedProto
    ? forwardedProto.split(',')[0].trim()
    : req.protocol;

  const host =
    req.get('x-forwarded-host') ||
    req.get('host');

  return `${proto}://${host}`;
}

/* =========================================================
   CRYPTO
========================================================= */

function randomToken(prefix) {
  return `${prefix}_${crypto.randomBytes(32).toString('hex')}`;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const aa = Buffer.from(a);
  const bb = Buffer.from(b);

  return (
    aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb)
  );
}

/* =========================================================
   OAUTH CLEANUP
========================================================= */

function cleanupOAuthState() {
  const now = Date.now();

  for (const [key, value] of authorizationCodes) {
    if (value.expiresAt <= now) {
      authorizationCodes.delete(key);
    }
  }

  for (const [key, value] of accessTokens) {
    if (value.expiresAt <= now) {
      accessTokens.delete(key);
    }
  }

  for (const [key, value] of refreshTokens) {
    if (value.expiresAt <= now) {
      refreshTokens.delete(key);
    }
  }
}

setInterval(
  cleanupOAuthState,
  60 * 1000
).unref();

/* =========================================================
   OAUTH DISCOVERY
========================================================= */

app.get(
  '/.well-known/oauth-authorization-server',
  (req, res) => {

    const base = baseUrl(req);

    res.setHeader('Cache-Control', 'no-store');

    res.json({
      issuer: base,

      authorization_endpoint:
        `${base}/oauth/auth`,

      token_endpoint:
        `${base}/oauth/token`,

      registration_endpoint:
        `${base}/oauth/register`,

      response_types_supported: [
        'code'
      ],

      grant_types_supported: [
        'authorization_code',
        'refresh_token'
      ],

      token_endpoint_auth_methods_supported: [
        'client_secret_post',
        'client_secret_basic',
        'none'
      ],

      code_challenge_methods_supported: [
        'S256'
      ],

      scopes_supported: [
        'terminal'
      ]
    });
  }
);

app.get(
  '/.well-known/oauth-protected-resource',
  (req, res) => {

    const base = baseUrl(req);

    res.setHeader('Cache-Control', 'no-store');

    res.json({
      resource: `${base}/mcp`,
      authorization_servers: [
        base
      ],
      scopes_supported: [
        'terminal'
      ]
    });
  }
);

/*
 * Some clients check the RFC-style metadata path
 * with the resource path included.
 */
app.get(
  '/.well-known/oauth-protected-resource/mcp',
  (req, res) => {

    const base = baseUrl(req);

    res.setHeader('Cache-Control', 'no-store');

    res.json({
      resource: `${base}/mcp`,
      authorization_servers: [
        base
      ],
      scopes_supported: [
        'terminal'
      ]
    });
  }
);

/* =========================================================
   OAUTH DYNAMIC CLIENT REGISTRATION
========================================================= */

app.post('/oauth/register', (req, res) => {

  const redirectUris =
    Array.isArray(req.body.redirect_uris)
      ? req.body.redirect_uris
      : [];

  if (!redirectUris.length) {
    return res.status(400).json({
      error: 'invalid_client_metadata',
      error_description:
        'redirect_uris is required'
    });
  }

  const clientId =
    `client_${crypto.randomBytes(16).toString('hex')}`;

  const clientSecret =
    randomToken('secret');

  const clientName =
    req.body.client_name ||
    'ChatGPT Terminal Connector';

  oauthClients.set(clientId, {
    clientId,
    clientSecret,
    redirectUris,
    clientName,
    createdAt: Date.now()
  });

  console.log(
    `[DCR] Registered client: ${clientId} (${clientName})`
  );

  return res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name: clientName,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: 'client_secret_post',
    grant_types: [
      'authorization_code',
      'refresh_token'
    ],
    response_types: [
      'code'
    ]
  });
});

/* =========================================================
   OAUTH CLIENT LOOKUP
========================================================= */

function getClient(req) {

  const auth =
    req.get('authorization') || '';

  /*
   * HTTP Basic
   */
  if (auth.startsWith('Basic ')) {

    try {

      const decoded =
        Buffer.from(
          auth.slice(6),
          'base64'
        ).toString('utf8');

      const separator =
        decoded.indexOf(':');

      if (separator >= 0) {

        const clientId =
          decoded.slice(0, separator);

        const clientSecret =
          decoded.slice(separator + 1);

        const client =
          oauthClients.get(clientId);

        if (
          client &&
          safeEqual(
            client.clientSecret,
            clientSecret
          )
        ) {
          return client;
        }
      }

    } catch (_) {}
  }

  /*
   * POST body / query fallback
   */
  const clientId =
    req.body?.client_id ||
    req.query?.client_id;

  const clientSecret =
    req.body?.client_secret ||
    req.query?.client_secret;

  const client =
    oauthClients.get(clientId);

  if (!client) {
    return null;
  }

  /*
   * Public clients may omit secret.
   */
  if (!clientSecret) {
    return client;
  }

  if (
    safeEqual(
      client.clientSecret,
      clientSecret
    )
  ) {
    return client;
  }

  return null;
}

/* =========================================================
   OAUTH LOGIN PAGE
========================================================= */

function escapeHtml(value) {

  return String(value || '')
    .replace(
      /[&<>"']/g,
      c => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      })[c]
    );
}

function passwordPage(
  res,
  fields,
  error = ''
) {

  const hidden =
    Object.entries(fields)
      .map(([key, value]) => {
        return `
          <input
            type="hidden"
            name="${escapeHtml(key)}"
            value="${escapeHtml(value)}"
          >
        `;
      })
      .join('');

  res.setHeader(
    'Content-Type',
    'text/html; charset=utf-8'
  );

  res.send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>Login Terminal</title>
</head>

<body style="
  font-family:sans-serif;
  text-align:center;
  margin:60px auto;
  max-width:430px;
  background:#0d1117;
  color:#c9d1d9;
  padding:30px;
">

<h2>Login Terminal</h2>

<p>
Masukkan password untuk melanjutkan
koneksi ChatGPT.
</p>

${
  error
    ? `<p style="color:#ff6b6b">
         ${escapeHtml(error)}
       </p>`
    : ''
}

<form
  action="/oauth/login"
  method="POST"
>

${hidden}

<input
  type="password"
  name="terminal_password"
  placeholder="Password"
  autocomplete="current-password"
  required
  style="
    padding:12px;
    width:90%;
    margin:15px 0;
    border-radius:6px;
    border:1px solid #30363d;
  "
>

<button
  type="submit"
  style="
    padding:12px 24px;
    background:#10a37f;
    color:white;
    border:0;
    border-radius:6px;
    font-weight:bold;
  "
>
Login
</button>

</form>

</body>
</html>
  `);
}

/* =========================================================
   OAUTH AUTHORIZE
========================================================= */

app.get('/oauth/auth', (req, res) => {

  const {
    response_type,
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
    scope
  } = req.query;

  const client =
    oauthClients.get(client_id);

  if (response_type !== 'code') {
    return res.status(400).send(
      'response_type harus code.'
    );
  }

  if (!client) {
    return res.status(400).send(
      'Client OAuth tidak dikenal.'
    );
  }

  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send(
      'redirect_uri tidak terdaftar.'
    );
  }

  /*
   * PKCE wajib.
   */
  if (
    code_challenge_method !== 'S256' ||
    !code_challenge
  ) {
    return res.status(400).send(
      'PKCE S256 diperlukan.'
    );
  }

  return passwordPage(
    res,
    {
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      scope: scope || 'terminal'
    }
  );
});

/* =========================================================
   OAUTH LOGIN
========================================================= */

app.post('/oauth/login', (req, res) => {

  const {
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
    scope,
    terminal_password
  } = req.body;

  const client =
    oauthClients.get(client_id);

  if (
    !client ||
    !client.redirectUris.includes(redirect_uri) ||
    code_challenge_method !== 'S256' ||
    !code_challenge
  ) {
    return res.status(400).send(
      'Permintaan OAuth tidak valid.'
    );
  }

  if (!TERMINAL_PASSWORD) {
    return res.status(500).send(
      'TERMINAL_PASSWORD/SESSION_SECRET belum dikonfigurasi.'
    );
  }

  if (
    !safeEqual(
      terminal_password,
      TERMINAL_PASSWORD
    )
  ) {

    return passwordPage(
      res,
      {
        client_id,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        scope
      },
      'Password salah.'
    );
  }

  const code =
    randomToken('code');

  authorizationCodes.set(
    code,
    {
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      scope: scope || 'terminal',
      expiresAt:
        Date.now() + 5 * 60 * 1000
    }
  );

  const url =
    new URL(redirect_uri);

  url.searchParams.set(
    'code',
    code
  );

  if (state) {
    url.searchParams.set(
      'state',
      state
    );
  }

  console.log(
    `[OAUTH] Authorization approved for ${client_id}`
  );

  return res.redirect(
    url.toString()
  );
});

/* =========================================================
   OAUTH TOKEN
========================================================= */

app.post('/oauth/token', (req, res) => {

  const grantType =
    req.body.grant_type;

  const client =
    getClient(req);

  if (!client) {
    return res.status(401).json({
      error: 'invalid_client'
    });
  }

  /*
   * AUTHORIZATION CODE
   */
  if (grantType === 'authorization_code') {

    const {
      code,
      redirect_uri,
      code_verifier
    } = req.body;

    const record =
      authorizationCodes.get(code);

    if (
      !record ||
      record.expiresAt <= Date.now() ||
      record.clientId !== client.clientId ||
      record.redirectUri !== redirect_uri
    ) {
      return res.status(400).json({
        error: 'invalid_grant'
      });
    }

    if (!code_verifier) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description:
          'code_verifier is required'
      });
    }

    const challenge =
      crypto
        .createHash('sha256')
        .update(code_verifier)
        .digest('base64url');

    if (
      !safeEqual(
        challenge,
        record.codeChallenge
      )
    ) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description:
          'PKCE verification failed'
      });
    }

    authorizationCodes.delete(code);

    const accessToken =
      randomToken('access');

    const refreshToken =
      randomToken('refresh');

    accessTokens.set(
      accessToken,
      {
        clientId: client.clientId,
        scope: record.scope,
        expiresAt:
          Date.now() + 60 * 60 * 1000
      }
    );

    refreshTokens.set(
      refreshToken,
      {
        clientId: client.clientId,
        scope: record.scope,
        expiresAt:
          Date.now() +
          30 * 24 * 60 * 60 * 1000
      }
    );

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: record.scope
    });
  }

  /*
   * REFRESH TOKEN
   */
  if (grantType === 'refresh_token') {

    const oldRefresh =
      req.body.refresh_token;

    const record =
      refreshTokens.get(oldRefresh);

    if (
      !record ||
      record.expiresAt <= Date.now() ||
      record.clientId !== client.clientId
    ) {
      return res.status(400).json({
        error: 'invalid_grant'
      });
    }

    refreshTokens.delete(oldRefresh);

    const accessToken =
      randomToken('access');

    const refreshToken =
      randomToken('refresh');

    accessTokens.set(
      accessToken,
      {
        clientId: client.clientId,
        scope: record.scope,
        expiresAt:
          Date.now() + 60 * 60 * 1000
      }
    );

    refreshTokens.set(
      refreshToken,
      {
        clientId: client.clientId,
        scope: record.scope,
        expiresAt:
          Date.now() +
          30 * 24 * 60 * 60 * 1000
      }
    );

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: record.scope
    });
  }

  return res.status(400).json({
    error: 'unsupported_grant_type'
  });
});

/* =========================================================
   BEARER AUTH
========================================================= */

function requireBearer(req, res, next) {

  const header =
    req.get('authorization') || '';

  if (!header.startsWith('Bearer ')) {

    res.set(
      'WWW-Authenticate',
      'Bearer'
    );

    return res.status(401).json({
      error: 'unauthorized',
      error_description:
        'Bearer token required'
    });
  }

  const token =
    header.slice(7).trim();

  const record =
    accessTokens.get(token);

  if (
    !record ||
    record.expiresAt <= Date.now()
  ) {

    res.set(
      'WWW-Authenticate',
      'Bearer error="invalid_token"'
    );

    return res.status(401).json({
      error: 'invalid_token'
    });
  }

  req.oauth = record;

  next();
}

/* =========================================================
   MCP HELPERS
========================================================= */

function jsonRpcResult(id, result) {

  return {
    jsonrpc: '2.0',
    id,
    result
  };
}

function jsonRpcError(
  id,
  code,
  message,
  data
) {

  const error = {
    code,
    message
  };

  if (data !== undefined) {
    error.data = data;
  }

  return {
    jsonrpc: '2.0',
    id: id ?? null,
    error
  };
}

/*
 * MCP tool definitions.
 *
 * The terminal tool executes a command inside
 * the Koyeb container where this Node process runs.
 */
const MCP_TOOLS = [
  {
    name: 'terminal_exec',
    description:
      'Execute a shell command inside the Koyeb terminal container and return stdout/stderr.',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description:
            'Shell command to execute.'
        },
        cwd: {
          type: 'string',
          description:
            'Optional working directory.'
        },
        timeout_ms: {
          type: 'integer',
          minimum: 1000,
          maximum: 300000,
          description:
            'Optional command timeout in milliseconds.'
        }
      },
      required: [
        'command'
      ],
      additionalProperties: false
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true
    }
  },

  {
    name: 'terminal_pwd',
    description:
      'Return the current home/working directory of the terminal container.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false
    },
    annotations: {
      readOnlyHint: true
    }
  },

  {
    name: 'terminal_env',
    description:
      'Return a safe summary of the terminal runtime environment without exposing secret environment variable values.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false
    },
    annotations: {
      readOnlyHint: true
    }
  }
];

/* =========================================================
   MCP COMMAND EXECUTION
========================================================= */

function getDefaultCwd() {
  return (
    process.env.HOME ||
    process.cwd() ||
    '/app'
  );
}

function executeShellCommand(
  command,
  cwd,
  timeoutMs
) {

  return new Promise((resolve) => {

    const shell =
      os.platform() === 'win32'
        ? 'powershell.exe'
        : 'bash';

    const args =
      os.platform() === 'win32'
        ? [
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            command
          ]
        : [
            '-lc',
            command
          ];

    const startedAt =
      Date.now();

    const child =
      execFile(
        shell,
        args,
        {
          cwd:
            cwd || getDefaultCwd(),

          env:
            process.env,

          timeout:
            Math.min(
              Math.max(
                Number(timeoutMs) ||
                MCP_EXEC_TIMEOUT_MS,
                1000
              ),
              300000
            ),

          maxBuffer:
            10 * 1024 * 1024
        },
        (error, stdout, stderr) => {

          const duration =
            Date.now() - startedAt;

          resolve({
            exitCode:
              typeof error?.code === 'number'
                ? error.code
                : error
                  ? 1
                  : 0,

            stdout:
              String(stdout || ''),

            stderr:
              String(stderr || ''),

            duration_ms:
              duration,

            timedOut:
              error?.killed === true
          });
        }
      );

    child.on('error', (error) => {

      resolve({
        exitCode: 1,
        stdout: '',
        stderr: String(error.message || error),
        duration_ms:
          Date.now() - startedAt,
        timedOut: false
      });
    });
  });
}

/* =========================================================
   MCP TOOL CALL
========================================================= */

async function handleToolCall(
  name,
  args
) {

  args =
    args &&
    typeof args === 'object'
      ? args
      : {};

  /*
   * terminal_pwd
   */
  if (name === 'terminal_pwd') {

    return {
      content: [
        {
          type: 'text',
          text: getDefaultCwd()
        }
      ],
      structuredContent: {
        cwd: getDefaultCwd()
      }
    };
  }

  /*
   * terminal_env
   */
  if (name === 'terminal_env') {

    const safeKeys = [
      'NODE_ENV',
      'PORT',
      'HOME',
      'HOSTNAME',
      'PWD',
      'SHELL',
      'USER',
      'LANG',
      'TZ'
    ];

    const environment = {};

    for (const key of safeKeys) {

      if (
        Object.prototype.hasOwnProperty.call(
          process.env,
          key
        )
      ) {
        environment[key] =
          process.env[key];
      }
    }

    environment.platform =
      process.platform;

    environment.arch =
      process.arch;

    environment.node =
      process.version;

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            environment,
            null,
            2
          )
        }
      ],
      structuredContent: {
        environment
      }
    };
  }

  /*
   * terminal_exec
   */
  if (name === 'terminal_exec') {

    if (
      typeof args.command !== 'string' ||
      !args.command.trim()
    ) {

      return {
        isError: true,
        content: [
          {
            type: 'text',
            text:
              'Parameter "command" wajib diisi.'
          }
        ]
      };
    }

    const result =
      await executeShellCommand(
        args.command,
        args.cwd || getDefaultCwd(),
        args.timeout_ms
      );

    const output = [
      `exit_code: ${result.exitCode}`,
      `duration_ms: ${result.duration_ms}`,
      result.timedOut
        ? 'timed_out: true'
        : '',
      '',
      '--- stdout ---',
      result.stdout || '(empty)',
      '',
      '--- stderr ---',
      result.stderr || '(empty)'
    ]
      .filter(Boolean)
      .join('\n');

    return {
      isError:
        result.exitCode !== 0,

      content: [
        {
          type: 'text',
          text: output
        }
      ],

      structuredContent: {
        exit_code: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        duration_ms: result.duration_ms,
        timed_out: result.timedOut
      }
    };
  }

  return {
    isError: true,
    content: [
      {
        type: 'text',
        text:
          `Unknown tool: ${name}`
      }
    ]
  };
}

/* =========================================================
   MCP REQUEST HANDLER
========================================================= */

async function handleMcpRequest(
  req,
  res
) {

  const body = req.body;

  /*
   * JSON-RPC batch is accepted.
   */
  if (Array.isArray(body)) {

    const responses = [];

    for (const message of body) {

      const response =
        await handleMcpMessage(
          message,
          req
        );

      if (response !== null) {
        responses.push(response);
      }
    }

    /*
     * Notifications only.
     */
    if (!responses.length) {
      return res.status(202).end();
    }

    return sendMcpJson(
      res,
      responses
    );
  }

  const response =
    await handleMcpMessage(
      body,
      req
    );

  /*
   * Notification.
   */
  if (response === null) {
    return res.status(202).end();
  }

  return sendMcpJson(
    res,
    response
  );
}

/* =========================================================
   MCP MESSAGE
========================================================= */

async function handleMcpMessage(
  message,
  req
) {

  if (
    !message ||
    message.jsonrpc !== '2.0'
  ) {

    return jsonRpcError(
      message?.id ?? null,
      -32600,
      'Invalid Request'
    );
  }

  const id =
    Object.prototype.hasOwnProperty.call(
      message,
      'id'
    )
      ? message.id
      : null;

  const method =
    message.method;

  const params =
    message.params || {};

  /*
   * -------------------------------------------------------
   * MCP 2025 initialize
   * -------------------------------------------------------
   *
   * Kept for compatibility with clients which still
   * perform the initialize/initialized handshake.
   */
  if (method === 'initialize') {

    return jsonRpcResult(
      id,
      {
        protocolVersion:
          params.protocolVersion &&
          [
            MCP_PROTOCOL_CURRENT,
            MCP_PROTOCOL_LEGACY
          ].includes(params.protocolVersion)
            ? params.protocolVersion
            : MCP_PROTOCOL_LEGACY,

        capabilities: {
          tools: {
            listChanged: false
          }
        },

        serverInfo: {
          name: SERVER_NAME,
          version: SERVER_VERSION
        },

        instructions:
          'Koyeb Web Terminal MCP menyediakan terminal_exec, terminal_pwd, dan terminal_env.'
      }
    );
  }

  /*
   * -------------------------------------------------------
   * initialized notification
   * -------------------------------------------------------
   */
  if (method === 'notifications/initialized') {
    return null;
  }

  /*
   * -------------------------------------------------------
   * ping
   * -------------------------------------------------------
   */
  if (method === 'ping') {

    return jsonRpcResult(
      id,
      {}
    );
  }

  /*
   * -------------------------------------------------------
   * Current MCP discovery
   * -------------------------------------------------------
   */
  if (method === 'server/discover') {

    return jsonRpcResult(
      id,
      {
        protocolVersion:
          MCP_PROTOCOL_CURRENT,

        capabilities: {
          tools: {
            listChanged: false
          }
        },

        serverInfo: {
          name: SERVER_NAME,
          version: SERVER_VERSION
        },

        tools: MCP_TOOLS
      }
    );
  }

  /*
   * -------------------------------------------------------
   * tools/list
   * -------------------------------------------------------
   */
  if (method === 'tools/list') {

    return jsonRpcResult(
      id,
      {
        tools: MCP_TOOLS
      }
    );
  }

  /*
   * -------------------------------------------------------
   * tools/call
   * -------------------------------------------------------
   */
  if (method === 'tools/call') {

    const name =
      params.name;

    if (
      typeof name !== 'string'
    ) {

      return jsonRpcError(
        id,
        -32602,
        'Missing tool name'
      );
    }

    const known =
      MCP_TOOLS.some(
        tool =>
          tool.name === name
      );

    if (!known) {

      return jsonRpcError(
        id,
        -32602,
        `Unknown tool: ${name}`
      );
    }

    try {

      const result =
        await handleToolCall(
          name,
          params.arguments || {}
        );

      return jsonRpcResult(
        id,
        result
      );

    } catch (error) {

      console.error(
        '[MCP] tools/call error:',
        error
      );

      return jsonRpcError(
        id,
        -32603,
        'Internal error',
        {
          message:
            String(
              error?.message ||
              error
            )
        }
      );
    }
  }

  /*
   * -------------------------------------------------------
   * resources/list
   * -------------------------------------------------------
   *
   * Return an empty valid result instead of 404.
   */
  if (method === 'resources/list') {

    return jsonRpcResult(
      id,
      {
        resources: []
      }
    );
  }

  /*
   * -------------------------------------------------------
   * prompts/list
   * -------------------------------------------------------
   */
  if (method === 'prompts/list') {

    return jsonRpcResult(
      id,
      {
        prompts: []
      }
    );
  }

  /*
   * -------------------------------------------------------
   * notifications
   * -------------------------------------------------------
   */
  if (
    typeof method === 'string' &&
    method.startsWith('notifications/')
  ) {
    return null;
  }

  return jsonRpcError(
    id,
    -32601,
    `Method not found: ${method}`
  );
}

/* =========================================================
   MCP RESPONSE
========================================================= */

function sendMcpJson(
  res,
  payload
) {

  res.status(200);

  res.setHeader(
    'Content-Type',
    'application/json; charset=utf-8'
  );

  res.setHeader(
    'Cache-Control',
    'no-store'
  );

  res.setHeader(
    'MCP-Protocol-Version',
    MCP_PROTOCOL_CURRENT
  );

  res.json(payload);
}

/* =========================================================
   MCP ORIGIN VALIDATION
========================================================= */

function validateMcpOrigin(
  req,
  res
) {

  const origin =
    req.get('origin');

  /*
   * Non-browser clients frequently don't send Origin.
   * That's okay.
   */
  if (!origin) {
    return true;
  }

  const allowed =
    new Set(
      [
        baseUrl(req),
        process.env.APP_URL,
        process.env.KOYEB_PUBLIC_URL
      ]
        .filter(Boolean)
        .map(String)
        .map(
          value =>
            value.replace(/\/+$/, '')
        )
    );

  /*
   * Allow ChatGPT / remote MCP clients which don't
   * present the server's own Origin.
   *
   * The bearer OAuth layer remains mandatory.
   */
  if (allowed.has(origin)) {
    return true;
  }

  /*
   * MCP remote clients may use external origins.
   * Authentication is still required.
   *
   * We therefore don't reject authenticated MCP clients
   * solely because Origin differs.
   */
  return true;
}

/* =========================================================
   MCP STREAMABLE HTTP
========================================================= */

/*
 * IMPORTANT:
 *
 * ChatGPT should use:
 *
 * https://YOUR-KOYEB-DOMAIN/mcp
 *
 * not /mcp/sse.
 *
 * The old /mcp/sse endpoint remains below only for
 * backward compatibility.
 */

app.post(
  '/mcp',
  requireBearer,
  async (req, res) => {

    if (!validateMcpOrigin(req, res)) {
      return;
    }

    /*
     * Current MCP Streamable HTTP clients may provide:
     *
     * MCP-Protocol-Version
     * Mcp-Method
     * Mcp-Name
     *
     * Older clients may not.
     *
     * We accept both generations.
     */
    const protocolVersion =
      req.get('MCP-Protocol-Version');

    const headerMethod =
      req.get('Mcp-Method');

    const bodyMethod =
      req.body?.method;

    if (
      headerMethod &&
      bodyMethod &&
      headerMethod !== bodyMethod
    ) {

      return res.status(400).json(
        jsonRpcError(
          req.body?.id ?? null,
          -32600,
          'Mcp-Method header does not match JSON-RPC method'
        )
      );
    }

    if (
      protocolVersion &&
      protocolVersion !== MCP_PROTOCOL_CURRENT &&
      protocolVersion !== MCP_PROTOCOL_LEGACY
    ) {

      /*
       * Don't hard fail old clients unnecessarily.
       * MCP implementations can negotiate using initialize.
       */
      console.log(
        `[MCP] Unknown protocol version received: ${protocolVersion}`
      );
    }

    console.log(
      `[MCP] POST ${bodyMethod || 'unknown'}`
    );

    return handleMcpRequest(
      req,
      res
    );
  }
);

/*
 * Streamable HTTP GET.
 *
 * Keep this endpoint available so a client can probe
 * the MCP URL without receiving an Express 404.
 */
app.get(
  '/mcp',
  requireBearer,
  (req, res) => {

    if (!validateMcpOrigin(req, res)) {
      return;
    }

    res.setHeader(
      'Content-Type',
      'text/event-stream; charset=utf-8'
    );

    res.setHeader(
      'Cache-Control',
      'no-cache, no-store'
    );

    res.setHeader(
      'Connection',
      'keep-alive'
    );

    res.setHeader(
      'X-Accel-Buffering',
      'no'
    );

    res.flushHeaders();

    /*
     * Keep the connection alive.
     */
    res.write(
      `event: message\n` +
      `data: ${JSON.stringify({
        jsonrpc: '2.0',
        method: 'notifications/ready'
      })}\n\n`
    );

    const heartbeat =
      setInterval(() => {

        if (res.writableEnded) {
          clearInterval(heartbeat);
          return;
        }

        res.write(
          `: heartbeat ${Date.now()}\n\n`
        );

      }, 25000);

    req.on('close', () => {
      clearInterval(heartbeat);
    });
  }
);

/* =========================================================
   LEGACY MCP SSE
========================================================= */

app.get(
  '/mcp/sse',
  requireBearer,
  (req, res) => {

    res.setHeader(
      'Content-Type',
      'text/event-stream; charset=utf-8'
    );

    res.setHeader(
      'Cache-Control',
      'no-cache, no-store'
    );

    res.setHeader(
      'Connection',
      'keep-alive'
    );

    res.setHeader(
      'X-Accel-Buffering',
      'no'
    );

    res.flushHeaders();

    res.write(
      `event: message\n` +
      `data: ${JSON.stringify({
        jsonrpc: '2.0',
        method: 'notifications/ready'
      })}\n\n`
    );

    const heartbeat =
      setInterval(() => {

        if (res.writableEnded) {
          clearInterval(heartbeat);
          return;
        }

        res.write(
          `: heartbeat ${Date.now()}\n\n`
        );

      }, 25000);

    req.on('close', () => {
      clearInterval(heartbeat);
    });
  }
);

/*
 * Optional legacy message endpoint.
 *
 * Some old MCP clients expect a separate endpoint after
 * establishing SSE. We accept JSON-RPC here as well.
 */
app.post(
  '/mcp/messages',
  requireBearer,
  async (req, res) => {

    return handleMcpRequest(
      req,
      res
    );
  }
);

/* =========================================================
   MCP ROOT INFO
========================================================= */

app.get(
  '/mcp/info',
  requireBearer,
  (req, res) => {

    res.json({
      ok: true,
      service: SERVER_NAME,
      version: SERVER_VERSION,
      protocol: MCP_PROTOCOL_CURRENT,
      transport: 'Streamable HTTP',
      endpoint: '/mcp',
      tools: MCP_TOOLS.map(
        tool => tool.name
      )
    });
  }
);

/* =========================================================
   WEB TERMINAL
========================================================= */

app.use(
  '/',
  ensureAuthenticated,
  express.static('public')
);

const shell =
  os.platform() === 'win32'
    ? 'powershell.exe'
    : 'bash';

io.on(
  'connection',
  socket => {

    console.log(
      '[TERMINAL] WebSocket terminal connected'
    );

    const ptyProcess =
      pty.spawn(
        shell,
        [],
        {
          name: 'xterm-color',
          cols: 80,
          rows: 30,
          cwd: getDefaultCwd(),
          env: process.env
        }
      );

    ptyProcess.onData(
      data => {
        socket.emit(
          'output',
          data
        );
      }
    );

    socket.on(
      'input',
      data => {

        if (
          typeof data === 'string'
        ) {
          ptyProcess.write(data);
        }
      }
    );

    socket.on(
      'resize',
      size => {

        if (
          !size ||
          !Number.isFinite(
            Number(size.cols)
          ) ||
          !Number.isFinite(
            Number(size.rows)
          )
        ) {
          return;
        }

        const cols =
          Math.max(
            1,
            Math.min(
              500,
              Number(size.cols)
            )
          );

        const rows =
          Math.max(
            1,
            Math.min(
              500,
              Number(size.rows)
            )
          );

        ptyProcess.resize(
          cols,
          rows
        );
      }
    );

    socket.on(
      'disconnect',
      () => {

        console.log(
          '[TERMINAL] WebSocket terminal disconnected'
        );

        try {
          ptyProcess.kill();
        } catch (_) {}
      }
    );
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(
      '[HTTP ERROR]',
      err
    );

    if (res.headersSent) {
      return next(err);
    }

    res.status(500).json({
      error: 'internal_server_error',
      message:
        process.env.NODE_ENV === 'production'
          ? 'Internal server error'
          : String(
              err?.message ||
              err
            )
    });
  }
);

/* =========================================================
   UPTIME
========================================================= */

function startUptimeBots() {

  const appUrl =
    process.env.RENDER_EXTERNAL_URL ||
    process.env.APP_URL ||
    process.env.KOYEB_PUBLIC_URL ||
    `http://localhost:${PORT}`;

  for (const minutes of [3, 4, 5]) {

    setInterval(
      () => {

        const target =
          `${
            appUrl.includes('http')
              ? appUrl
              : `https://${appUrl}`
          }/ping`;

        const client =
          target.startsWith('https')
            ? https
            : http;

        client
          .get(
            target,
            response => {

              console.log(
                `[Uptime Bot ${minutes}m] Ping status: ${response.statusCode}`
              );

              response.resume();
            }
          )
          .on(
            'error',
            () => {}
          );

      },
      minutes * 60 * 1000
    );
  }

  console.log(
    '🤖 3 Robot Uptime Ping berhasil diaktifkan!'
  );
}

/* =========================================================
   START
========================================================= */

server.listen(
  PORT,
  '0.0.0.0',
  () => {

    console.log('');
    console.log(
      '=========================================='
    );

    console.log(
      `✅ ${SERVER_NAME}`
    );

    console.log(
      `✅ Port: ${PORT}`
    );

    console.log(
      `✅ MCP: /mcp`
    );

    console.log(
      `✅ MCP Protocol: ${MCP_PROTOCOL_CURRENT}`
    );

    console.log(
      `✅ Legacy MCP: ${MCP_PROTOCOL_LEGACY}`
    );

    console.log(
      `✅ OAuth: enabled`
    );

    console.log(
      `✅ Streamable HTTP: enabled`
    );

    console.log(
      `✅ Tools: ${MCP_TOOLS.map(
        tool => tool.name
      ).join(', ')}`
    );

    console.log(
      '=========================================='
    );

    console.log('');

    startUptimeBots();
  }
);
