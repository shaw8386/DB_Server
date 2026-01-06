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
// 🔧 PostgreSQL Connection (Railway)
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ Database connection failed:", err));

// ============================================================
// 🔐 SIMPLE API KEY MIDDLEWARE (FOR TOOL BCR)
// ============================================================
function requireApiKey(req, res, next) {
  const key = req.headers["x-api-key"];
  if (!key || key !== process.env.API_KEY) {
    return res.status(401).json({ success: false, message: "Invalid API key" });
  }
  next();
}

// ============================================================
// 🗄️ INIT TABLE: bot_tokens
// ============================================================
async function initBotTokenTable() {
  const sql = `
    CREATE TABLE IF NOT EXISTS bot_tokens (
      id SERIAL PRIMARY KEY,
      bot_ref TEXT UNIQUE NOT NULL,
      bot_token TEXT NOT NULL,
      bot_id BIGINT,
      bot_username TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_bot_tokens_bot_ref ON bot_tokens(bot_ref);
  `;
  await pool.query(sql);
  console.log("✅ bot_tokens table ready");
}

initBotTokenTable().catch(console.error);

// ============================================================
// 🔐 LOGIN API (OPTIONAL – GIỮ LẠI NẾU CẦN)
// ============================================================
app.post("/login", async (req, res) => {
  const { username, password, ip } = req.body;

  if (!username || !password || !ip) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM accounts WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const user = result.rows[0];

    let ok = false;
    try {
      ok = await bcrypt.compare(password, user.password);
    } catch {
      ok = password === user.password;
    }

    if (!ok) {
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    if (user.ip && user.ip !== ip) {
      return res.status(403).json({ success: false, message: "Invalid IP" });
    }

    return res.json({
      success: true,
      message: "Login successful",
      user: {
        username: user.username,
        type: user.type,
        ip: user.ip,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// 🤖 UPSERT BOT TOKEN (ADMIN / SERVER SIDE)
// ============================================================
app.post("/bot/upsert", requireApiKey, async (req, res) => {
  const { bot_ref, bot_token, bot_id, bot_username } = req.body;

  if (!bot_ref || !bot_token) {
    return res.status(400).json({ success: false, message: "Missing bot_ref or bot_token" });
  }

  try {
    await pool.query(
      `
      INSERT INTO bot_tokens (bot_ref, bot_token, bot_id, bot_username, updated_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (bot_ref)
      DO UPDATE SET
        bot_token = EXCLUDED.bot_token,
        bot_id = EXCLUDED.bot_id,
        bot_username = EXCLUDED.bot_username,
        updated_at = NOW()
      `,
      [bot_ref, bot_token, bot_id || null, bot_username || null]
    );

    return res.json({ success: true, message: "Bot token updated" });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// 🔁 TOOL BCR → RESOLVE TOKEN
// ============================================================
app.post("/bot/resolve", requireApiKey, async (req, res) => {
  const { bot_ref } = req.body;

  if (!bot_ref) {
    return res.status(400).json({ success: false, message: "Missing bot_ref" });
  }

  try {
    const result = await pool.query(
      "SELECT bot_token, bot_id, bot_username FROM bot_tokens WHERE bot_ref = $1",
      [bot_ref]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "Bot not found" });
    }

    return res.json({
      success: true,
      bot_token: result.rows[0].bot_token,
      bot_id: result.rows[0].bot_id,
      bot_username: result.rows[0].bot_username,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// 🚀 START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
