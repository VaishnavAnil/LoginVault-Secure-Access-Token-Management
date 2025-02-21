require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.RATE_LIMIT || 5,
  message: "Too many attempts. Try again later.",
});

const SECRET_KEY = process.env.JWT_SECRET;

// 🟢 Welcome route
app.get("/", (req, res) => {
  res.send("Server is running! Welcome to the Node.js Authentication API.");
});

// 🟢 Register API
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 5) {
    return res.status(400).json({ message: "Invalid input" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, password, failed_attempts, locked) VALUES ($1, $2, 0, false)",
      [username, hashedPassword]
    );
    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error registering user" });
  }
});

// 🟢 Login API
app.post("/login", limiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    if (user.rows.length === 0 || user.rows[0].locked) {
      return res
        .status(401)
        .json({ message: "Invalid credentials or account locked" });
    }

    const isValid = await bcrypt.compare(password, user.rows[0].password);
    if (!isValid) {
      await pool.query(
        "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = $1",
        [username]
      );
      if (user.rows[0].failed_attempts + 1 >= process.env.LOCKOUT_ATTEMPTS) {
        await pool.query("UPDATE users SET locked = true WHERE username = $1", [
          username,
        ]);
        return res
          .status(403)
          .json({ message: "Account locked due to too many failed attempts" });
      }
      return res.status(401).json({ message: "Invalid credentials" });
    }

    await pool.query(
      "UPDATE users SET failed_attempts = 0 WHERE username = $1",
      [username]
    );
    const token = jwt.sign({ username }, SECRET_KEY, {
      expiresIn: process.env.TOKEN_EXPIRY,
    });
    await pool.query(
      "INSERT INTO user_tokens (username, token) VALUES ($1, $2)",
      [username, token]
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 🟢 One-Time Link API
app.post("/one-time-link", async (req, res) => {
  const { username } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    if (user.rows.length === 0 || user.rows[0].locked) {
      return res.status(404).json({ message: "User not found or locked" });
    }

    const linkToken = crypto.randomBytes(32).toString("hex");
    await pool.query(
      "INSERT INTO one_time_links (username, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes')",
      [username, linkToken]
    );

    res.json({ link: `http://localhost:3000/verify-link/${linkToken}` });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 🟢 Verify One-Time Link
app.get("/verify-link/:token", async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM one_time_links WHERE token = $1 AND expires_at > NOW()",
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid or expired link" });
    }

    await pool.query("DELETE FROM one_time_links WHERE token = $1", [token]);
    const authToken = jwt.sign(
      { username: result.rows[0].username },
      SECRET_KEY,
      { expiresIn: process.env.TOKEN_EXPIRY }
    );
    res.json({ token: authToken });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 🟢 Get Time API
app.get("/time", async (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    jwt.verify(token, SECRET_KEY);
    res.json({ time: new Date().toISOString() });
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// 🟢 Kickout API
app.post("/kickout", async (req, res) => {
  const { username } = req.body;
  try {
    await pool.query("DELETE FROM user_tokens WHERE username = $1", [username]);
    res.json({ message: "User logged out" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
