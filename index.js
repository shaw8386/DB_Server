import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

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

async function ensureSchema() {
  // ✅ Tạo bảng + index nếu chưa có
  const ddl = `
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
  await pool.query(ddl);
  console.log("✅ DB schema ensured (bot_tokens)");
}

pool
  .connect()
  .then(async () => {
    console.log("✅ Connected to PostgreSQL");
    try {
      await ensureSchema();
    } catch (e) {
      console.error("❌ ensureSchema failed:", e);
    }
  })
  .catch((err) => console.error("❌ Database connection failed:", err));

// ============================================================
// 🔐 Helpers
// ============================================================
function requireApiKey(req, res, next) {
  const got = req.headers["x-api-key"];
  const expected = process.env.BCR_API_KEY;

  if (!expected) {
    return res.status(500).json({ ok: false, message: "Server missing env BCR_API_KEY" });
  }
  if (!got || got !== expected) {
    return res.status(401).json({ ok: false, message: "Invalid api key" });
  }
  next();
}

function signJwt(user) {
  const secret = process.env.JWT_SECRET;
  if (!secret) return "";
  return jwt.sign(
    { username: user.username, type: user.type || "user" },
    secret,
    { expiresIn: "7d" }
  );
}

function requireJwtOptional(req, res, next) {
  const secret = process.env.JWT_SECRET;
  if (!secret) return next();

  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return next();

  try {
    req.user = jwt.verify(token, secret);
  } catch {
    // ignore
  }
  next();
}

app.use(requireJwtOptional);

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

    const token = signJwt(user);

    console.log("✅ Login successful:", username);
    return res.json({
      success: true,
      message: "Login successful",
      token,
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
// 🤖 Telegram helpers
// ============================================================
async function telegramGetMe(botToken) {
  const url = `https://api.telegram.org/bot${botToken}/getMe`;
  const r = await fetch(url, { method: "GET" });
  const data = await r.json().catch(() => ({}));
  return data;
}

function isValidBotTokenFormat(s) {
  return typeof s === "string" && s.includes(":") && s.length > 10;
}

// ============================================================
// ✅ BOT UPSERT (Update Bot_token lên server)
// POST /bot/upsert
// Header: x-api-key
// Body: { bot_ref, bot_token }
// ============================================================
app.post("/bot/upsert", requireApiKey, async (req, res) => {
  const { bot_ref, bot_token } = req.body;

  if (!bot_ref || !bot_token) {
    return res.status(400).json({ ok: false, message: "Missing bot_ref or bot_token" });
  }

  const ref = String(bot_ref).trim();
  const token = String(bot_token).trim();

  if (!ref) return res.status(400).json({ ok: false, message: "bot_ref is empty" });

  if (!isValidBotTokenFormat(token)) {
    return res.status(400).json({ ok: false, message: "Invalid bot_token format. Must contain ':'" });
  }

  try {
    const me = await telegramGetMe(token);
    if (!me || me.ok !== true || !me.result) {
      return res.status(400).json({
        ok: false,
        message: "Telegram token invalid (getMe failed)",
        telegram: me,
      });
    }

    const botId = me.result.id || null;
    const botUsername = me.result.username || null;

    const q = `
      INSERT INTO bot_tokens (bot_ref, bot_token, bot_id, bot_username, created_at, updated_at)
      VALUES ($1, $2, $3, $4, NOW(), NOW())
      ON CONFLICT (bot_ref)
      DO UPDATE SET
        bot_token = EXCLUDED.bot_token,
        bot_id = EXCLUDED.bot_id,
        bot_username = EXCLUDED.bot_username,
        updated_at = NOW()
      RETURNING bot_ref, bot_id, bot_username, updated_at
    `;

    const result = await pool.query(q, [ref, token, botId, botUsername]);

    return res.json({
      ok: true,
      message: "Bot token updated",
      data: result.rows[0],
    });
  } catch (err) {
    console.error("🔥 /bot/upsert ERROR:", err);
    return res.status(500).json({ ok: false, message: "Server error", error: err.message });
  }
});

// ============================================================
// ✅ RESOLVE TOKEN (Tool BCR gọi để lấy token thật)
// POST /resolve
// Header: x-api-key
// Body: { bot_ref }
// ============================================================
app.post("/resolve", requireApiKey, async (req, res) => {
  const { bot_ref } = req.body;

  if (!bot_ref) return res.status(400).json({ ok: false, message: "Missing bot_ref" });

  const ref = String(bot_ref).trim();
  if (!ref) return res.status(400).json({ ok: false, message: "bot_ref is empty" });

  try {
    const result = await pool.query(
      "SELECT bot_token, bot_id, bot_username, updated_at FROM bot_tokens WHERE bot_ref = $1 LIMIT 1",
      [ref]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ ok: false, message: "bot_ref not found on server" });
    }

    const row = result.rows[0];
    return res.json({
      ok: true,
      bot_token: row.bot_token,
      bot_id: row.bot_id,
      bot_username: row.bot_username,
      updated_at: row.updated_at,
    });
  } catch (err) {
    console.error("🔥 /resolve ERROR:", err);
    return res.status(500).json({ ok: false, message: "Server error", error: err.message });
  }
});

// ============================================================
// ✅ Health check
// ============================================================
app.get("/", (req, res) => res.json({ ok: true, service: "bcr-server" }));

// ============================================================
// 🚀 Start server
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
