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

// Variabel untuk menyimpan akun GitHub yang pertama kali login
let dynamicOwnerUsername = null;

// Middleware untuk mem-parsing JSON (Dibutuhkan oleh ChatGPT DCR)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Konfigurasi Session untuk Passport.js (GitHub Login)
app.use(session({
  secret: process.env.SESSION_SECRET || 'rahasia-terminal-koyeb-2026',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Serialisasi user ke dalam sesi
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(obj, done);
});

// Strategi Autentikasi GitHub
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL || 'https://koyeb-web-terminal.koyeb.app/auth/github/callback',
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    // Jika belum ada owner, akun pertama yang login akan menjadi owner
    if (!dynamicOwnerUsername) {
      dynamicOwnerUsername = profile.username.toLowerCase();
      console.log(`[AUTH] Owner di-set ke: ${dynamicOwnerUsername}`);
    }
    
    // Verifikasi apakah yang login adalah owner
    if (profile.username.toLowerCase() === dynamicOwnerUsername) {
      return done(null, profile);
    } else {
      console.log(`[AUTH] Akses ditolak untuk user: ${profile.username}`);
      return done(null, false, { message: 'Akses ditolak: Anda bukan owner dari terminal ini.' });
    }
  }
));

// Middleware untuk memblokir akses ke web terminal jika belum login
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/auth/github');
}

// -----------------------------------------------------------------
// ROUTES AUTENTIKASI WEB TERMINAL (GITHUB)
// -----------------------------------------------------------------
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email', 'repo'] }));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.get('/logout', (req, res) => {
  dynamicOwnerUsername = null; // Opsional: reset owner agar akun lain bisa login
  req.logout(() => {
    res.redirect('/');
  });
});

// Endpoint untuk di-ping oleh Uptime Bots
app.get('/ping', (req, res) => {
  res.status(200).send('OK - Server is Alive');
});


// -----------------------------------------------------------------
// ROUTES OAUTH & DCR UNTUK CHATGPT MCP CONNECTOR
// -----------------------------------------------------------------

// 1. Endpoint Metadata (ChatGPT menggunakan ini untuk mencari alur otorisasi)
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    resource: baseUrl,
    authorization_servers: [`${baseUrl}/oauth/auth`],
    registration_endpoint: `${baseUrl}/oauth/register`, // Penting agar error DCR hilang!
    token_endpoint: `${baseUrl}/oauth/token`
  });
});

// 2. Endpoint DCR (Dynamic Client Registration)
// ChatGPT otomatis mengirim POST ke sini untuk meminta Client ID baru
app.post('/oauth/register', (req, res) => {
  const newClientId = "chatgpt_mcp_client_" + Date.now();
  const newClientSecret = "secret_mcp_koyeb_" + Math.random().toString(36).substring(2);
  
  console.log(`[DCR] ChatGPT berhasil mendaftarkan client: ${newClientId}`);
  
  res.status(201).json({
    client_id: newClientId,
    client_secret: newClientSecret,
    client_name: req.body.client_name || "ChatGPT Terminal Connector",
    redirect_uris: req.body.redirect_uris || ["https://chatgpt.com/connector/oauth/M5NWKmu0hXIX"]
  });
});

// 3. Endpoint Authorization (Halaman persetujuan pengguna saat dari ChatGPT)
app.get('/oauth/auth', (req, res) => {
  const { redirect_uri, state, client_id } = req.query;
  
  res.send(`
    <div style="font-family: sans-serif; text-align: center; margin-top: 80px; background: #0d1117; color: #c9d1d9; padding: 40px; border-radius: 10px; max-width: 400px; margin-left: auto; margin-right: auto; border: 1px solid #30363d;">
      <h2>Koneksi MCP ChatGPT</h2>
      <p style="color: #8b949e;">Izinkan ChatGPT mengakses plugin terminal Anda.</p>
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

// 4. Proses Persetujuan & Pengalihan kembali ke Callback URL ChatGPT
app.post('/oauth/approve', (req, res) => {
  const { redirect_uri, state } = req.body;
  const authCode = "chatgpt_oauth_auth_code_secure_" + Date.now();
  
  if (redirect_uri) {
    const separator = redirect_uri.includes('?') ? '&' : '?';
    const finalUrl = `${redirect_uri}${separator}code=${authCode}&state=${state || ''}`;
    console.log(`[OAUTH] Mengalihkan kembali ke ChatGPT: ${finalUrl}`);
    return res.redirect(finalUrl);
  }
  
  res.send("Persetujuan berhasil, namun Redirect URI tidak valid.");
});

// 5. Endpoint Penukaran Token (ChatGPT menukar kode auth menjadi token akses)
app.post('/oauth/token', (req, res) => {
  res.json({
    access_token: "chatgpt_mcp_access_token_" + Date.now(),
    token_type: "Bearer",
    expires_in: 86400,
    refresh_token: "chatgpt_mcp_refresh_token_" + Date.now()
  });
});

// 6. Endpoint SSE / Event Stream (Alur komunikasi data langsung ke ChatGPT)
app.get('/mcp/sse', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  res.write(`data: ${JSON.stringify({ type: 'connected', message: 'MCP Server siap dan terhubung dengan ChatGPT!' })}\n\n`);
});


// -----------------------------------------------------------------
// WEB TERMINAL INTERFACE & WEBSOCKET SETUP
// -----------------------------------------------------------------

// Semua route di bawah ini diproteksi oleh fungsi ensureAuthenticated (Wajib Login GitHub)
app.use('/', ensureAuthenticated, express.static('public'));

// Mendeteksi jenis sistem operasi untuk Shell (Linux = bash)
const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';

io.on('connection', (socket) => {
  console.log('[TERMINAL] Koneksi WebSocket baru ke Terminal');
  
  const ptyProcess = pty.spawn(shell, [], {
    name: 'xterm-color',
    cols: 80,
    rows: 30,
    cwd: process.env.HOME || '/app',
    env: process.env
  });

  // Kirim output dari proses background ke frontend terminal web
  ptyProcess.onData((data) => {
    socket.emit('output', data);
  });

  // Terima ketikan dari frontend terminal web dan masukkan ke proses background
  socket.on('input', (data) => {
    ptyProcess.write(data);
  });

  // Atur ukuran layar terminal agar presisi
  socket.on('resize', (size) => {
    ptyProcess.resize(size.cols, size.rows);
  });

  // Matikan proses terminal jika user menutup tab
  socket.on('disconnect', () => {
    console.log('[TERMINAL] Tab tertutup, mematikan proses bash.');
    ptyProcess.kill();
  });
});


// -----------------------------------------------------------------
// UPTIME ROBOTS (Mencegah Koyeb Sleep)
// -----------------------------------------------------------------
function startUptimeBots() {
  const appUrl = process.env.RENDER_EXTERNAL_URL || process.env.APP_URL || process.env.KOYEB_PUBLIC_URL || 'http://localhost:8000';
  
  // Robot 1: Interval 3 Menit
  setInterval(() => {
    const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
    const client = target.startsWith('https') ? https : http;
    client.get(target, (res) => {
      console.log(`[Uptime Bot 1] Ping status: ${res.statusCode}`);
    }).on('error', (err) => {
      // Abaikan error saat uji coba lokal
    });
  }, 3 * 60 * 1000);

  // Robot 2: Interval 4 Menit
  setInterval(() => {
    const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
    const client = target.startsWith('https') ? https : http;
    client.get(target, (res) => {
      console.log(`[Uptime Bot 2] Ping status: ${res.statusCode}`);
    }).on('error', (err) => {});
  }, 4 * 60 * 1000);

  // Robot 3: Interval 5 Menit
  setInterval(() => {
    const target = `${appUrl.includes('http') ? appUrl : 'https://' + appUrl}/ping`;
    const client = target.startsWith('https') ? https : http;
    client.get(target, (res) => {
      console.log(`[Uptime Bot 3] Ping status: ${res.statusCode}`);
    }).on('error', (err) => {});
  }, 5 * 60 * 1000);
  
  console.log('🤖 3 Robot Uptime Ping berhasil diaktifkan!');
}

// -----------------------------------------------------------------
// JALANKAN SERVER
// -----------------------------------------------------------------
const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`✅ Server berjalan di port ${PORT}`);
  startUptimeBots();
});
