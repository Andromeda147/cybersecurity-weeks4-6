const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const app = express();

function log(msg) {
  const ts = new Date().toISOString();
  fs.appendFileSync('security.log', `[${ts}] ${msg}\n`);
  console.log(`[${ts}] ${msg}`);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  }
}));
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

const allowedOrigins = ['http://localhost:3000'];
app.use(cors({ origin: allowedOrigins, credentials: true }));

const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 10 });
app.use(globalLimiter);
app.use('/login', authLimiter);
app.use('/signup', authLimiter);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(cookieParser());
app.use(session({ secret: 'your-session-secret-change-me', resave: false, saveUninitialized: true }));
app.use(csrf({ cookie: true }));
app.use((req, res, next) => { res.locals.csrfToken = req.csrfToken(); next(); });

const failedAttempts = new Map();
const BAN_TIME = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
function checkBan(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const rec = failedAttempts.get(ip);
  if (rec && rec.bannedUntil && Date.now() < rec.bannedUntil)
    return res.status(403).send('Too many failed attempts. Try again later.');
  if (rec && rec.bannedUntil && Date.now() >= rec.bannedUntil)
    failedAttempts.delete(ip);
  next();
}
app.use(checkBan);

// ✅ CORRECT MongoDB URI (no directConnection, uses replica set)
const mongoURI = 'mongodb://alimanzarmir12_db_user:vwt4GIbi4UAzLY2L@ac-se85vy9-shard-00-00.dl9zcyg.mongodb.net:27017,ac-se85vy9-shard-00-01.dl9zcyg.mongodb.net:27017,ac-se85vy9-shard-00-02.dl9zcyg.mongodb.net:27017/userdb?ssl=true&replicaSet=atlas-jlq3oc-shard-0&authSource=admin&retryWrites=true&w=majority';
mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB error:', err.message));

const userSchema = new mongoose.Schema({ name: String, email: String, password: String });
const User = mongoose.model('User', userSchema);

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>]/g, m => m === '&' ? '&amp;' : m === '<' ? '&lt;' : '&gt;');
}

app.get('/', (req, res) => res.render('index'));
app.get('/signup', (req, res) => res.render('signup', { csrfToken: req.csrfToken() }));
app.get('/login', (req, res) => res.render('login', { csrfToken: req.csrfToken() }));

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || name.length < 2) return res.send('<h1>Error: Name too short</h1>');
  if (!validator.isEmail(email)) return res.send('<h1>Error: Invalid email</h1>');
  if (!password || password.length < 6) return res.send('<h1>Error: Password too short</h1>');
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed });
    await user.save();
    res.send('<h1>Signup successful! <a href="/login">Login</a></h1>');
  } catch (err) {
    res.send('<h1>Error</h1>');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress;
  if (!validator.isEmail(email)) {
    log(`Failed login - invalid email: ${email} from ${ip}`);
    return res.send('<h1>Error: Invalid email</h1>');
  }
  const user = await User.findOne({ email });
  if (!user) {
    const rec = failedAttempts.get(ip) || { count: 0, bannedUntil: null };
    rec.count++;
    if (rec.count >= MAX_ATTEMPTS) {
      rec.bannedUntil = Date.now() + BAN_TIME;
      log(`IP ${ip} banned (user not found)`);
    }
    failedAttempts.set(ip, rec);
    log(`Failed login - user not found: ${email} from ${ip}`);
    return res.send('<h1>Invalid credentials</h1>');
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    const rec = failedAttempts.get(ip) || { count: 0, bannedUntil: null };
    rec.count++;
    if (rec.count >= MAX_ATTEMPTS) {
      rec.bannedUntil = Date.now() + BAN_TIME;
      log(`IP ${ip} banned (wrong password)`);
    }
    failedAttempts.set(ip, rec);
    log(`Failed login - wrong password: ${email} from ${ip}`);
    return res.send('<h1>Invalid credentials</h1>');
  }
  failedAttempts.delete(ip);
  log(`Successful login: ${email} from ${ip}`);
  res.send(`<h1>Welcome ${escapeHtml(user.name)}!</h1><p>Email: ${user.email}</p>`);
});

const apiKeys = new Set(['test-api-key-123']);
app.get('/api/data', (req, res) => {
  const key = req.headers['x-api-key'];
  if (!key || !apiKeys.has(key)) return res.status(401).json({ error: 'Invalid API key' });
  res.json({ message: 'Sensitive data', timestamp: new Date() });
});

app.get('/csrf-token', (req, res) => res.json({ csrfToken: req.csrfToken() }));

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("INSERT INTO users (username, password) VALUES ('admin', 'admin123')");
  db.run("INSERT INTO users (username, password) VALUES ('user', 'pass456')");
});
app.post('/sqli-test', (req, res) => {
  const { username } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ query, rows });
  });
});
app.post('/sqli-safe', (req, res) => {
  const { username } = req.body;
  const query = `SELECT * FROM users WHERE username = ?`;
  db.all(query, [username], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ rows });
  });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Secure app running on port ${PORT}`));
