const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const pty = require('node-pty');
const os = require('os');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Owner akan otomatis terdeteksi dari akun GitHub pertama yang berhasil login
let dynamicOwnerUsername = null;

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
    callbackURL: process.env.GITHUB_CALLBACK_URL || 'https://app-name.koyeb.app/auth/github/callback'
  },
  function(accessToken, refreshToken, profile, done) {
    // User pertama yang login otomatis menjadi Owner eksklusif terminal ini
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

// Routes Autentikasi GitHub
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email', 'repo'] }));

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

app.get('/logout', (req, res) => {
  dynamicOwnerUsername = null; // Reset owner jika ingin ganti akun
  req.logout(() => {
    res.redirect('/');
  });
});

// Proteksi Tampilan UI Terminal (Hanya untuk Owner)
app.use('/', ensureAuthenticated, express.static('public'));

// Terminal WebSocket Setup (node-pty untuk Full Command Bash)
const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';

io.on('connection', (socket) => {
  const ptyProcess = pty.spawn(shell, [], {
    name: 'xterm-color',
    cols: 80,
    rows: 30,
    cwd: process.env.HOME || '/app',
    env: process.env
  });

  ptyProcess.onData((data) => {
    socket.emit('output', data);
  });

  socket.on('input', (data) => {
    ptyProcess.write(data);
  });

  socket.on('resize', (size) => {
    ptyProcess.resize(size.cols, size.rows);
  });

  socket.on('disconnect', () => {
    ptyProcess.kill();
  });
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`Server terminal berjalan di port ${PORT}`);
});
