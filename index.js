// index.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";

dotenv.config();
const { Pool } = pkg;

const app = express();
app.use(express.json());
app.use(cors());

// ============================================================
// 🔧 PostgreSQL Connection
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool
  .connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ Database connection failed:", err));

// ============================================================
// 🔐 API KEY middleware (x-api-key)
// ============================================================
function requireApiKey(req, res, next) {
  const serverKey = process.env.API_KEY;
  if (!serverKey) {
    return res.status(500).json({
      ok: false,
      message: "Server missing API_KEY (Railway Variables)",
    });
  }

  const clientKey = req.headers["x-api-key"];
  if (!clientKey || clientKey !== serverKey) {
    return res.status(401).json({ ok: false, message: "Unauthorized" });
  }
  next();
}

// ============================================================
// 🧱 Auto-migrate: create table bots
// ============================================================
async function ensureTables() {
  const sql = `
  CREATE TABLE IF NOT EXISTS bots (
    id SERIAL PRIMARY KEY,
    client_key TEXT UNIQUE NOT NULL,     -- user nhập trong tool (telegram_config.bot_token)
    bot_token TEXT NOT NULL,             -- token thật
    bot_id BIGINT,
    bot_username TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  );

  CREATE INDEX IF NOT EXISTS idx_bots_client_key ON bots(client_key);
  `;

  await pool.query(sql);
  console.log("✅ ensureTables OK (bots)");
}

ensureTables().catch((err) => {
  console.error("❌ ensureTables failed:", err);
});

// ============================================================
// 🔐 LOGIN API (bảng: accounts) - giữ nguyên như bạn
// ============================================================
app.post("/login", async (req, res) => {
  const { username, password, ip } = req.body;

  console.log("📥 Login request:", username, ip);

  if (!username || !password || !ip) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const result = await pool.query("SELECT * FROM accounts WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      console.warn("⚠️ User not found:", username);
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const user = result.rows[0];

    let passwordMatch = false;
    try {
      passwordMatch = await bcrypt.compare(password, user.password);
    } catch {
      passwordMatch = password === user.password;
    }

    if (!passwordMatch) {
      console.warn("⚠️ Invalid password for:", username);
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    if (user.ip && user.ip !== ip) {
      console.warn("⚠️ Invalid IP:", username, "Expected:", user.ip, "Got:", ip);
      return res.status(403).json({ success: false, message: "Invalid IP address" });
    }

    console.log("✅ Login successful:", username);
    return res.json({
      success: true,
      message: "Login successful",
      user: {
        username: user.username,
        ip: user.ip,
        type: user.type,
      },
    });
  } catch (err) {
    console.error("🔥 SERVER ERROR:", err);
    return res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

// ============================================================
// ✅ TOOL API: Resolve token thật theo client_key
// Tool gọi endpoint này để lấy bot_token thật.
// Header: x-api-key: API_KEY
// Body: { "client_key": "..." }
// ============================================================
app.post("/bot/resolve", requireApiKey, async (req, res) => {
  const { client_key } = req.body || {};
  if (!client_key) {
    return res.status(400).json({ ok: false, message: "Missing client_key" });
  }

  try {
    const r = await pool.query(
      `SELECT bot_token, bot_id, bot_username
       FROM bots
       WHERE client_key = $1
       LIMIT 1`,
      [client_key]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, message: "Bot not found for this client_key" });
    }

    const bot = r.rows[0];
    return res.json({
      ok: true,
      bot_token: bot.bot_token,
      bot_id: bot.bot_id,
      bot_username: bot.bot_username,
    });
  } catch (err) {
    console.error("🔥 /bot/resolve error:", err);
    return res.status(500).json({ ok: false, message: "Server error", error: err.message });
  }
});

// ============================================================
// ✅ ADMIN API: Upsert bot token (để bạn add/update token thật)
// Header: x-api-key: API_KEY
// Body: { client_key, bot_token, bot_id?, bot_username? }
// ============================================================
app.post("/bot/upsert", requireApiKey, async (req, res) => {
  const { client_key, bot_token, bot_id, bot_username } = req.body || {};

  if (!client_key || !bot_token) {
    return res.status(400).json({ ok: false, message: "Missing client_key or bot_token" });
  }

  try {
    const q = `
      INSERT INTO bots (client_key, bot_token, bot_id, bot_username, created_at, updated_at)
      VALUES ($1, $2, $3, $4, NOW(), NOW())
      ON CONFLICT (client_key)
      DO UPDATE SET
        bot_token = EXCLUDED.bot_token,
        bot_id = EXCLUDED.bot_id,
        bot_username = EXCLUDED.bot_username,
        updated_at = NOW()
      RETURNING id, client_key, bot_id, bot_username, updated_at;
    `;

    const r = await pool.query(q, [client_key, bot_token, bot_id || null, bot_username || null]);
    return res.json({ ok: true, bot: r.rows[0] });
  } catch (err) {
    console.error("🔥 /bot/upsert error:", err);
    return res.status(500).json({ ok: false, message: "Server error", error: err.message });
  }
});

// ============================================================
// 🚀 Start server
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
