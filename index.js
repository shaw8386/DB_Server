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

pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ Database connection failed:", err));

// ============================================================
// 🔐 API KEY middleware
// ============================================================
function requireApiKey(req, res, next) {
  const serverKey = process.env.API_KEY; // Railway Variables: API_KEY
  const clientKey = req.headers["x-api-key"];

  if (!serverKey) {
    return res.status(500).json({ ok: false, message: "Server missing API_KEY (Railway Variables)" });
  }
  if (!clientKey || clientKey !== serverKey) {
    return res.status(401).json({ ok: false, message: "Unauthorized (invalid x-api-key)" });
  }
  next();
}

// ============================================================
// 🧱 Ensure table (singleton bot storage)
// ============================================================
async function ensureTables() {
  const sql = `
  CREATE TABLE IF NOT EXISTS bot_master (
    id INT PRIMARY KEY DEFAULT 1,
    bot_token TEXT NOT NULL,
    bot_id BIGINT,
    bot_username TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  );
  `;
  await pool.query(sql);
  console.log("✅ ensureTables OK");
}

ensureTables().catch((e) => console.error("❌ ensureTables error:", e));

// ============================================================
// ✅ Health
// ============================================================
app.get("/health", (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// ============================================================
// 🔐 LOGIN API (bảng: accounts) - giữ nguyên của bạn
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
      passwordMatch = (password === user.password);
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
// ✅ BOT: RESOLVE (Tool gọi để lấy bot_token thật)
// POST /bot/resolve
// Header: x-api-key
// Response: { ok: true, bot_token, bot_id, bot_username }
// ============================================================
app.post("/bot/resolve", requireApiKey, async (req, res) => {
  try {
    const rs = await pool.query(
      "SELECT bot_token, bot_id, bot_username FROM bot_master WHERE id = 1 LIMIT 1"
    );

    if (rs.rows.length === 0) {
      return res.status(404).json({ ok: false, message: "Bot token not set on server yet" });
    }

    const bot = rs.rows[0];
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
// ✅ BOT: UPSERT (Admin cập nhật token thật)
// POST /bot/upsert
// Header: x-api-key
// Body: { bot_token, bot_id?, bot_username? }
// ============================================================
app.post("/bot/upsert", requireApiKey, async (req, res) => {
  const { bot_token, bot_id, bot_username } = req.body || {};

  if (!bot_token || typeof bot_token !== "string" || !bot_token.includes(":")) {
    return res.status(400).json({ ok: false, message: "bot_token invalid (must contain ':')" });
  }

  try {
    await pool.query(
      `
      INSERT INTO bot_master (id, bot_token, bot_id, bot_username)
      VALUES (1, $1, $2, $3)
      ON CONFLICT (id)
      DO UPDATE SET
        bot_token = EXCLUDED.bot_token,
        bot_id = EXCLUDED.bot_id,
        bot_username = EXCLUDED.bot_username,
        updated_at = NOW()
      `,
      [bot_token, bot_id || null, bot_username || null]
    );

    return res.json({
      ok: true,
      message: "Bot token updated",
    });
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
