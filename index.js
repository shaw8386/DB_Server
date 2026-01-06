// index.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";

dotenv.config();
const { Pool } = pkg;

const app = express();
app.use(express.json({ limit: "1mb" }));
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
// 🔐 API KEY MIDDLEWARE (NO JWT)
// ============================================================
const API_KEY = (process.env.API_KEY || "").trim();

function requireApiKey(req, res, next) {
  // Header chuẩn: x-api-key
  const key = (req.headers["x-api-key"] || "").toString().trim();

  if (!API_KEY) {
    return res.status(500).json({ ok: false, message: "Server missing API_KEY (Railway Variables)" });
  }
  if (!key || key !== API_KEY) {
    return res.status(401).json({ ok: false, message: "Unauthorized" });
  }
  next();
}

// ============================================================
// 🧱 INIT TABLE bot_tokens (AUTO CREATE ON START)
// ============================================================
async function initBotTokensTable() {
  const sql = `
  CREATE TABLE IF NOT EXISTS bot_tokens (
    id SERIAL PRIMARY KEY,
    bot_ref TEXT UNIQUE NOT NULL,         -- cái user nhập ở DB local (telegram_config.bot_token)
    bot_token TEXT NOT NULL,              -- token thật
    bot_id BIGINT,
    bot_username TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  );

  CREATE INDEX IF NOT EXISTS idx_bot_tokens_bot_ref ON bot_tokens(bot_ref);
  `;

  await pool.query(sql);
  console.log("✅ bot_tokens table ensured");
}

// ============================================================
// ✅ HEALTH CHECK
// ============================================================
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "bcr-token-server", time: new Date().toISOString() });
});

// ============================================================
// 🔐 LOGIN API (bảng: accounts)
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
// 🤖 BOT TOKEN APIs
// ============================================================

/**
 * POST /bot/register  (BẢO TRÌ / ADMIN)
 * - Mục đích: bạn (admin) đẩy token thật lên server để lưu.
 * - Bắt buộc x-api-key
 * Body: { bot_ref, bot_token, bot_id?, bot_username? }
 *
 * Gợi ý: bot_ref chính là chuỗi user nhập ở local telegram_config.bot_token
 *        (ví dụ: "A01" hoặc "ref_group1" ...)
 */
app.post("/bot/register", requireApiKey, async (req, res) => {
  const { bot_ref, bot_token, bot_id, bot_username } = req.body || {};

  if (!bot_ref || !bot_token) {
    return res.status(400).json({ ok: false, message: "Missing bot_ref or bot_token" });
  }
  if (!String(bot_token).includes(":")) {
    return res.status(400).json({ ok: false, message: "bot_token invalid format (missing ':')" });
  }

  try {
    const q = `
      INSERT INTO bot_tokens (bot_ref, bot_token, bot_id, bot_username, created_at, updated_at)
      VALUES ($1, $2, $3, $4, NOW(), NOW())
      ON CONFLICT (bot_ref)
      DO UPDATE SET
        bot_token = EXCLUDED.bot_token,
        bot_id = EXCLUDED.bot_id,
        bot_username = EXCLUDED.bot_username,
        updated_at = NOW()
      RETURNING id, bot_ref, bot_id, bot_username, updated_at
    `;
    const r = await pool.query(q, [
      String(bot_ref).trim(),
      String(bot_token).trim(),
      bot_id ?? null,
      bot_username ?? null,
    ]);

    return res.json({ ok: true, data: r.rows[0] });
  } catch (err) {
    console.error("🔥 /bot/register ERROR:", err);
    return res.status(500).json({ ok: false, message: "Server error", error: err.message });
  }
});

/**
 * POST /bot/resolve  (TOOL CALL)
 * - Mục đích: tool BCR gửi bot_ref (token user nhập) lên để lấy token thật.
 * - Bắt buộc x-api-key
 * Body: { bot_ref }
 * Response: { ok: true, bot_token, bot_id?, bot_username? }
 */
app.post("/bot/resolve", requireApiKey, async (req, res) => {
  const { bot_ref } = req.body || {};
  if (!bot_ref) return res.status(400).json({ ok: false, message: "Missing bot_ref" });

  try {
    const r = await pool.query(
      "SELECT bot_token, bot_id, bot_username FROM bot_tokens WHERE bot_ref = $1 LIMIT 1",
      [String(bot_ref).trim()]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, message: "bot_ref not found" });
    }

    const row = r.rows[0];
    return res.json({
      ok: true,
      bot_token: row.bot_token,
      bot_id: row.bot_id,
      bot_username: row.bot_username,
    });
  } catch (err) {
    console.error("🔥 /bot/resolve ERROR:", err);
    return res.status(500).json({ ok: false, message: "Server error", error: err.message });
  }
});

// ============================================================
// 🚀 Start server (ensure tables first)
// ============================================================
const PORT = process.env.PORT || 3000;

(async () => {
  try {
    await initBotTokensTable();
    app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
  } catch (err) {
    console.error("❌ Failed to init server:", err);
    process.exit(1);
  }
})();
