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
// 🧱 Ensure tables
//  - bot_master: multi-bot storage (key = bot_username, chuẩn Railway)
//  - accounts_tool_bcr: login accounts for Tool BCR (plain-text, giống index_login.js)
// ============================================================
async function ensureTables() {
  // ---- bot_master (multi-bot, key = bot_username) ----
  const sqlBot = `
  CREATE TABLE IF NOT EXISTS bot_master (
    id SERIAL PRIMARY KEY,
    bot_token TEXT NOT NULL,
    bot_id BIGINT,
    bot_username TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  );
  `;
  await pool.query(sqlBot);

  // Đảm bảo bot_username unique (Railway DB lưu theo bot_username)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_bot_master_bot_username
    ON bot_master(bot_username)
    WHERE bot_username IS NOT NULL
  `);

  console.log("✅ ensureTables OK (bot_master key = bot_username)");

  // ---- accounts_tool_bcr (login giống index_login.js) ----
  const sqlAccounts = `
  CREATE TABLE IF NOT EXISTS accounts_tool_bcr (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, -- PLAIN TEXT (giống index_login.js)
    ip_address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  `;
  await pool.query(sqlAccounts);

  console.log("✅ accounts_tool_bcr table ready");
}

ensureTables().catch((e) => console.error("❌ ensureTables error:", e));

// ============================================================
// ✅ Health
// ============================================================
app.get("/health", (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// ============================================================
// 🔐 LOGIN API cũ (bảng: accounts) – giữ nguyên cho các client đang dùng
// ============================================================
app.post("/login", async (req, res) => {
  const { username, password, ip } = req.body;

  console.log("📥 Login request (accounts):", username, ip);

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

    console.log("✅ Login successful (accounts):", username);
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
// 🔐 LOGIN API mới cho Tool BCR (bảng: accounts_tool_bcr)
//   - Logic & cấu trúc giống index_login.js nhưng dùng bảng riêng
//   - PLAIN TEXT PASSWORD + check IP theo ip_address
// ============================================================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password, ip } = req.body;

    if (!username || !password || !ip) {
      return res.status(400).json({
        success: false,
        message: "Thiếu username / password / ip",
      });
    }

    const result = await pool.query(
      "SELECT id, username, password FROM accounts_tool_bcr WHERE username = $1 AND ip_address = $2",
      [username, ip]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({
        success: false,
        message: "Username hoặc IP không hợp lệ",
      });
    }

    const user = result.rows[0];

    // PLAIN TEXT COMPARE (giống index_login.js)
    if (password !== user.password) {
      return res.status(401).json({
        success: false,
        message: "Sai mật khẩu",
      });
    }

    return res.json({
      success: true,
      message: "Đăng nhập thành công",
      user: {
        id: user.id,
        username: user.username,
      },
    });
  } catch (err) {
    console.error("🔥 /api/login error:", err);
    return res.status(500).json({
      success: false,
      message: "Lỗi server",
    });
  }
});

// ============================================================
// 👑 Admin - Add User cho Tool BCR (bảng: accounts_tool_bcr)
//   POST /api/admin/add-user
//   Body: { username, password, ip_address }
// ============================================================
app.post("/api/admin/add-user", async (req, res) => {
  try {
    const { username, password, ip_address } = req.body;

    if (!username || !password || !ip_address) {
      return res.status(400).json({
        success: false,
        message: "Thiếu dữ liệu",
      });
    }

    const result = await pool.query(
      "INSERT INTO accounts_tool_bcr (username, password, ip_address) VALUES ($1, $2, $3) RETURNING id",
      [username, password, ip_address]
    );

    return res.json({
      success: true,
      message: "Thêm user thành công",
      userId: result.rows[0].id,
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "Username đã tồn tại",
      });
    }

    console.error("🔥 /api/admin/add-user error:", err);
    return res.status(500).json({
      success: false,
      message: "Lỗi server",
    });
  }
});

// ============================================================
// 👑 Admin - List Users cho Tool BCR (bảng: accounts_tool_bcr)
//   GET /api/admin/users
// ============================================================
app.get("/api/admin/users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, password, ip_address, created_at FROM accounts_tool_bcr ORDER BY id DESC"
    );

    return res.json({
      success: true,
      users: result.rows,
    });
  } catch (err) {
    console.error("🔥 /api/admin/users error:", err);
    return res.status(500).json({
      success: false,
      message: "Lỗi server",
    });
  }
});

// ============================================================
// ✅ BOT: RESOLVE (Tool gọi để lấy bot_token thật theo bot_username)
// POST /bot/resolve
// Header: x-api-key
// Body: { bot_username }  // @Boss_BCR_bot, @live_casino_helper_bot, ... (chuẩn Railway)
// Response: { ok: true, bot_token, bot_id, bot_username }
// ============================================================
app.post("/bot/resolve", requireApiKey, async (req, res) => {
  const { bot_username } = req.body || {};

  if (!bot_username || typeof bot_username !== "string") {
    return res.status(400).json({ ok: false, message: "Missing or invalid bot_username" });
  }

  try {
    const rs = await pool.query(
      `
      SELECT bot_token, bot_id, bot_username
      FROM bot_master
      WHERE bot_username = $1
      LIMIT 1
      `,
      [bot_username.trim()]
    );

    if (rs.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        message: "Bot token not found for this bot_username",
      });
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
// ✅ BOT: UPSERT (Admin cập nhật token thật theo bot_username)
// POST /bot/upsert
// Header: x-api-key
// Body: { bot_username, bot_token, bot_id? }
// ============================================================
app.post("/bot/upsert", requireApiKey, async (req, res) => {
  const { bot_username, bot_token, bot_id } = req.body || {};

  if (!bot_username || typeof bot_username !== "string") {
    return res.status(400).json({ ok: false, message: "bot_username required" });
  }

  if (!bot_token || typeof bot_token !== "string" || !bot_token.includes(":")) {
    return res.status(400).json({ ok: false, message: "bot_token invalid (must contain ':')" });
  }

  try {
    await pool.query(
      `
      INSERT INTO bot_master (bot_username, bot_token, bot_id)
      VALUES ($1, $2, $3)
      ON CONFLICT (bot_username)
      DO UPDATE SET
        bot_token = EXCLUDED.bot_token,
        bot_id = EXCLUDED.bot_id,
        updated_at = NOW()
      `,
      [bot_username.trim(), bot_token, bot_id || null]
    );

    return res.json({
      ok: true,
      message: "Bot token updated for bot_username",
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
