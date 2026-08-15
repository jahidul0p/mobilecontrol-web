const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);

const app = express();
const PORT = process.env.PORT || 3000;

// IMPORTANT FOR RENDER
app.set("trust proxy", 1);

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
      "mobilecontrol-secret-change-this",

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

// ================= DATABASE =================

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

    console.log("Database is ready.");
  } catch (error) {
    console.error("Database setup failed:", error);
  }
}

setupDatabase();

// ================= HEALTH =================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      status: "error",
      database: "connection failed"
    });
  }
});

// ================= SIGNUP =================

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      RETURNING id, email, created_at
      `,
      [normalizedEmail, passwordHash]
    );

    req.session.userId = result.rows[0].id;

    // IMPORTANT: save session before responding
    req.session.save((error) => {
      if (error) {
        console.error("Signup session save error:", error);

        return res.status(500).json({
          error: "Unable to save login session."
        });
      }

      res.status(201).json({
        message: "Account created successfully.",
        user: result.rows[0]
      });
    });

  } catch (error) {
    console.error("Signup error:", error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

// ================= LOGIN =================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `
      SELECT id, email, password_hash
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    // Set logged-in user
    req.session.userId = user.id;

    // IMPORTANT:
    // Wait until session is stored in PostgreSQL
    // before sending login response.
    req.session.save((error) => {
      if (error) {
        console.error("Login session save error:", error);

        return res.status(500).json({
          error: "Unable to save login session."
        });
      }

      console.log(
        "LOGIN SUCCESS - Session ID:",
        req.sessionID,
        "User ID:",
        req.session.userId
      );

      res.json({
        message: "Login successful.",
        user: {
          id: user.id,
          email: user.email
        }
      });
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Unable to login."
    });
  }
});

// ================= CURRENT USER =================

app.get("/api/me", async (req, res) => {
  try {
    console.log(
      "SESSION CHECK:",
      req.sessionID,
      "USER:",
      req.session.userId
    );

    if (!req.session.userId) {
      return res.status(401).json({
        authenticated: false
      });
    }

    const result = await pool.query(
      `
      SELECT id, email, created_at
      FROM users
      WHERE id = $1
      `,
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        authenticated: false
      });
    }

    const user = result.rows[0];

    res.json({
      authenticated: true,

      user: user,

      // Also provide these directly
      id: user.id,
      email: user.email
    });

  } catch (error) {
    console.error("Session error:", error);

    res.status(500).json({
      error: "Unable to check session."
    });
  }
});

// ================= LOGOUT =================

app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.error("Logout error:", error);

      return res.status(500).json({
        error: "Unable to logout."
      });
    }

    res.clearCookie("connect.sid");

    res.json({
      message: "Logged out successfully."
    });
  });
});

// ================= WEBSITE =================

// Home page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Dashboard
app.get("/dashboard.html", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

// Keep these only if old links still use them
app.get("/login.html", (req, res) => {
  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.redirect("/");
});

// ================= SERVER =================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
