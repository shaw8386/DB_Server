// import express from "express";
// import cors from "cors";
// import dotenv from "dotenv";
// import pkg from "pg";
// import bcrypt from "bcryptjs";

// dotenv.config();
// const { Pool } = pkg;

// const app = express();
// app.use(express.json({ limit: "50mb" }));
// app.use(cors());

// // ============================================================
// // 🔧 PostgreSQL Connection
// // ============================================================
// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
//   ssl: { rejectUnauthorized: false },
// });

// pool.connect()
//   .then(() => console.log("✅ Connected to PostgreSQL"))
//   .catch((err) => console.error("❌ Database connection failed:", err));

// // ============================================================
// // 🔐 API KEY middleware
// // ============================================================
// function requireApiKey(req, res, next) {
//   const serverKey = process.env.API_KEY; // Railway Variables: API_KEY
//   const clientKey = req.headers["x-api-key"];

//   if (!serverKey) {
//     return res.status(500).json({ ok: false, message: "Server missing API_KEY (Railway Variables)" });
//   }
//   if (!clientKey || clientKey !== serverKey) {
//     return res.status(401).json({ ok: false, message: "Unauthorized (invalid x-api-key)" });
//   }
//   next();
// }

// // ============================================================
// // 🧱 Schemas & Ensure tables
// //  - accounts: accounts, accounts_tool_bcr, bot_master
// //  - session_db: tool_db_backups
// // ============================================================
// async function ensureTables() {
//   await pool.query("CREATE SCHEMA IF NOT EXISTS accounts");
//   await pool.query("CREATE SCHEMA IF NOT EXISTS session_db");

//   // ---- accounts.bot_master (multi-bot, key = bot_username) ----
//   const sqlBot = `
//   CREATE TABLE IF NOT EXISTS accounts.bot_master (
//     id SERIAL PRIMARY KEY,
//     bot_token TEXT NOT NULL,
//     bot_id BIGINT,
//     bot_username TEXT UNIQUE,
//     created_at TIMESTAMP DEFAULT NOW(),
//     updated_at TIMESTAMP DEFAULT NOW()
//   );
//   `;
//   await pool.query(sqlBot);

//   // Đảm bảo bot_username unique (Railway DB lưu theo bot_username)
//   await pool.query(`
//     CREATE UNIQUE INDEX IF NOT EXISTS idx_bot_master_bot_username
//     ON accounts.bot_master(bot_username)
//     WHERE bot_username IS NOT NULL
//   `);

//   console.log("✅ ensureTables OK (bot_master key = bot_username)");

//   // ---- accounts.accounts_tool_bcr (login giống index_login.js) ----
//   const sqlAccounts = `
//   CREATE TABLE IF NOT EXISTS accounts.accounts_tool_bcr (
//     id SERIAL PRIMARY KEY,
//     username TEXT UNIQUE NOT NULL,
//     password TEXT NOT NULL, -- PLAIN TEXT (giống index_login.js)
//     ip_address TEXT NOT NULL,
//     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//   );
//   `;
//   await pool.query(sqlAccounts);

//   // ---- session_db.tool_db_backups: lưu SQLite snapshot từ Tool BCR ----
//   const sqlToolDb = `
//   CREATE TABLE IF NOT EXISTS session_db.tool_db_backups (
//     id SERIAL PRIMARY KEY,
//     data BYTEA NOT NULL,
//     username TEXT,
//     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//   );
//   `;
//   await pool.query(sqlToolDb);

//   // ---- session_db: các bảng Tool BCR sync từ master.db ----
//   const sessionTables = [
//     `CREATE TABLE IF NOT EXISTS session_db.tool_telegram_config (
//       id SERIAL PRIMARY KEY,
//       telegram_username TEXT,
//       telegram_uid TEXT,
//       group_list_flag INTEGER,
//       bot_username TEXT,
//       bot_token TEXT,
//       main_amount INTEGER DEFAULT 0,
//       tie_min INTEGER DEFAULT 0,
//       tie_max INTEGER DEFAULT 0,
//       tie_step INTEGER DEFAULT 0,
//       label_player TEXT,
//       label_banker TEXT,
//       label_tie TEXT,
//       updated_at TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_list_mess (
//       id SERIAL PRIMARY KEY,
//       msg_type TEXT,
//       message TEXT,
//       pair_key TEXT,
//       pair_role TEXT,
//       updated_at TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_msg_type (
//       msg_type TEXT PRIMARY KEY,
//       description TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_session (
//       id SERIAL PRIMARY KEY,
//       start TEXT,
//       end TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_table (
//       id SERIAL PRIMARY KEY,
//       id_session INTEGER,
//       type TEXT,
//       name TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_round (
//       id SERIAL PRIMARY KEY,
//       id_table INTEGER,
//       round_no INTEGER,
//       focus_tab INTEGER,
//       focus_group INTEGER,
//       tie_sub TEXT,
//       result TEXT,
//       updated_at TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_round_entries (
//       id SERIAL PRIMARY KEY,
//       id_round INTEGER,
//       role TEXT,
//       tab INTEGER,
//       group_list_flag INTEGER,
//       predict_select TEXT,
//       media_result TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_round_bet (
//       id SERIAL PRIMARY KEY,
//       id_round_entries INTEGER,
//       id_telegram_config INTEGER,
//       telegram_uid INTEGER,
//       bot_token TEXT,
//       label_predict_select TEXT,
//       main_amount INTEGER,
//       tie_sub_amount INTEGER,
//       msg_predict TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_round_result (
//       id SERIAL PRIMARY KEY,
//       id_round_bet INTEGER,
//       profit_main INTEGER,
//       profit_tie_sub INTEGER,
//       msg_result TEXT
//     )`,
//     `CREATE TABLE IF NOT EXISTS session_db.tool_msg_send (
//       id SERIAL PRIMARY KEY,
//       id_telegram_config INTEGER,
//       msg_type TEXT,
//       msg_text TEXT,
//       updated_at TEXT
//     )`,
//   ];
//   for (const sql of sessionTables) {
//     await pool.query(sql);
//   }

//   console.log("✅ accounts_tool_bcr, tool_db_backups, session_db tables ready");
// }

// ensureTables().catch((e) => console.error("❌ ensureTables error:", e));

// // ============================================================
// // ✅ Health
// // ============================================================
// app.get("/health", (req, res) => {
//   res.json({ ok: true, ts: new Date().toISOString() });
// });

// // ============================================================
// // 🔐 LOGIN API cũ (bảng: accounts) – giữ nguyên cho các client đang dùng
// // ============================================================
// app.post("/login", async (req, res) => {
//   const { username, password, ip } = req.body;

//   console.log("📥 Login request (accounts):", username, ip);

//   if (!username || !password || !ip) {
//     return res.status(400).json({ success: false, message: "Missing fields" });
//   }

//   try {
//     const result = await pool.query("SELECT * FROM accounts.accounts WHERE username = $1", [username]);
//     if (result.rows.length === 0) {
//       console.warn("⚠️ User not found:", username);
//       return res.status(404).json({ success: false, message: "User not found" });
//     }

//     const user = result.rows[0];

//     let passwordMatch = false;
//     try {
//       passwordMatch = await bcrypt.compare(password, user.password);
//     } catch {
//       passwordMatch = password === user.password;
//     }

//     if (!passwordMatch) {
//       console.warn("⚠️ Invalid password for:", username);
//       return res.status(401).json({ success: false, message: "Invalid password" });
//     }

//     if (user.ip && user.ip !== ip) {
//       console.warn("⚠️ Invalid IP:", username, "Expected:", user.ip, "Got:", ip);
//       return res.status(403).json({ success: false, message: "Invalid IP address" });
//     }

//     console.log("✅ Login successful (accounts):", username);
//     return res.json({
//       success: true,
//       message: "Login successful",
//       user: {
//         username: user.username,
//         ip: user.ip,
//         type: user.type,
//       },
//     });
//   } catch (err) {
//     console.error("🔥 SERVER ERROR:", err);
//     return res.status(500).json({ success: false, message: "Server error", error: err.message });
//   }
// });

// // ============================================================
// // 🔐 LOGIN API mới cho Tool BCR (bảng: accounts_tool_bcr)
// //   - Logic & cấu trúc giống index_login.js nhưng dùng bảng riêng
// //   - PLAIN TEXT PASSWORD + check IP theo ip_address
// // ============================================================
// app.post("/api/login", async (req, res) => {
//   try {
//     const { username, password, ip } = req.body;

//     if (!username || !password || !ip) {
//       return res.status(400).json({
//         success: false,
//         message: "Thiếu username / password / ip",
//       });
//     }

//     const result = await pool.query(
//       "SELECT id, username, password FROM accounts.accounts_tool_bcr WHERE username = $1 AND ip_address = $2",
//       [username, ip]
//     );

//     if (result.rows.length === 0) {
//       return res.status(403).json({
//         success: false,
//         message: "Username hoặc IP không hợp lệ",
//       });
//     }

//     const user = result.rows[0];

//     // PLAIN TEXT COMPARE (giống index_login.js)
//     if (password !== user.password) {
//       return res.status(401).json({
//         success: false,
//         message: "Sai mật khẩu",
//       });
//     }

//     return res.json({
//       success: true,
//       message: "Đăng nhập thành công",
//       user: {
//         id: user.id,
//         username: user.username,
//       },
//     });
//   } catch (err) {
//     console.error("🔥 /api/login error:", err);
//     return res.status(500).json({
//       success: false,
//       message: "Lỗi server",
//     });
//   }
// });

// // ============================================================
// // 👑 Admin - Add User cho Tool BCR (bảng: accounts_tool_bcr)
// //   POST /api/admin/add-user
// //   Body: { username, password, ip_address }
// // ============================================================
// app.post("/api/admin/add-user", async (req, res) => {
//   try {
//     const { username, password, ip_address } = req.body;

//     if (!username || !password || !ip_address) {
//       return res.status(400).json({
//         success: false,
//         message: "Thiếu dữ liệu",
//       });
//     }

//     const result = await pool.query(
//       "INSERT INTO accounts.accounts_tool_bcr (username, password, ip_address) VALUES ($1, $2, $3) RETURNING id",
//       [username, password, ip_address]
//     );

//     return res.json({
//       success: true,
//       message: "Thêm user thành công",
//       userId: result.rows[0].id,
//     });
//   } catch (err) {
//     if (err.code === "23505") {
//       return res.status(409).json({
//         success: false,
//         message: "Username đã tồn tại",
//       });
//     }

//     console.error("🔥 /api/admin/add-user error:", err);
//     return res.status(500).json({
//       success: false,
//       message: "Lỗi server",
//     });
//   }
// });

// // ============================================================
// // 👑 Admin - List Users cho Tool BCR (bảng: accounts_tool_bcr)
// //   GET /api/admin/users
// // ============================================================
// app.get("/api/admin/users", async (req, res) => {
//   try {
//     const result = await pool.query(
//       "SELECT id, username, password, ip_address, created_at FROM accounts.accounts_tool_bcr ORDER BY id DESC"
//     );

//     return res.json({
//       success: true,
//       users: result.rows,
//     });
//   } catch (err) {
//     console.error("🔥 /api/admin/users error:", err);
//     return res.status(500).json({
//       success: false,
//       message: "Lỗi server",
//     });
//   }
// });

// // ============================================================
// // ✅ BOT: RESOLVE (Tool gọi để lấy bot_token thật theo bot_username)
// // POST /bot/resolve
// // Header: x-api-key
// // Body: { bot_username }  // @Boss_BCR_bot, @live_casino_helper_bot, ... (chuẩn Railway)
// // Response: { ok: true, bot_token, bot_id, bot_username }
// // ============================================================
// app.post("/bot/resolve", requireApiKey, async (req, res) => {
//   const { bot_username } = req.body || {};

//   if (!bot_username || typeof bot_username !== "string") {
//     return res.status(400).json({ ok: false, message: "Missing or invalid bot_username" });
//   }

//   try {
//     const rs = await pool.query(
//       `
//       SELECT bot_token, bot_id, bot_username
//       FROM accounts.bot_master
//       WHERE bot_username = $1
//       LIMIT 1
//       `,
//       [bot_username.trim()]
//     );

//     if (rs.rows.length === 0) {
//       return res.status(404).json({
//         ok: false,
//         message: "Bot token not found for this bot_username",
//       });
//     }

//     const bot = rs.rows[0];
//     return res.json({
//       ok: true,
//       bot_token: bot.bot_token,
//       bot_id: bot.bot_id,
//       bot_username: bot.bot_username,
//     });
//   } catch (err) {
//     console.error("🔥 /bot/resolve error:", err);
//     return res.status(500).json({ ok: false, message: "Server error", error: err.message });
//   }
// });

// // ============================================================
// // ✅ BOT: UPSERT (Admin cập nhật token thật theo bot_username)
// // POST /bot/upsert
// // Header: x-api-key
// // Body: { bot_username, bot_token, bot_id? }
// // ============================================================
// app.post("/bot/upsert", requireApiKey, async (req, res) => {
//   const { bot_username, bot_token, bot_id } = req.body || {};

//   if (!bot_username || typeof bot_username !== "string") {
//     return res.status(400).json({ ok: false, message: "bot_username required" });
//   }

//   if (!bot_token || typeof bot_token !== "string" || !bot_token.includes(":")) {
//     return res.status(400).json({ ok: false, message: "bot_token invalid (must contain ':')" });
//   }

//   try {
//     await pool.query(
//       `
//       INSERT INTO accounts.bot_master (bot_username, bot_token, bot_id)
//       VALUES ($1, $2, $3)
//       ON CONFLICT (bot_username)
//       DO UPDATE SET
//         bot_token = EXCLUDED.bot_token,
//         bot_id = EXCLUDED.bot_id,
//         updated_at = NOW()
//       `,
//       [bot_username.trim(), bot_token, bot_id || null]
//     );

//     return res.json({
//       ok: true,
//       message: "Bot token updated for bot_username",
//     });
//   } catch (err) {
//     console.error("🔥 /bot/upsert error:", err);
//     return res.status(500).json({ ok: false, message: "Server error", error: err.message });
//   }
// });

// // ============================================================
// // 📥 SESSION_DB: Export (lấy toàn bộ data schema session_db dạng JSON)
// // GET /api/session-db/export
// // Header: x-api-key
// // Returns: { ok, data: { telegram_config, list_mess, msg_type, session, table_, round, ... } }
// // ============================================================
// const SESSION_DB_TABLES = [
//   { key: "telegram_config", pg: "tool_telegram_config", cols: "id,telegram_username,telegram_uid,group_list_flag as \"groupList_flag\",bot_username,bot_token,main_amount,tie_min,tie_max,tie_step,label_player,label_banker,label_tie,updated_at" },
//   { key: "list_mess", pg: "tool_list_mess", cols: "*" },
//   { key: "msg_type", pg: "tool_msg_type", cols: "*" },
//   { key: "session", pg: "tool_session", cols: "*" },
//   { key: "table_", pg: "tool_table", cols: "*" },
//   { key: "round", pg: "tool_round", cols: "*" },
//   { key: "round_entries", pg: "tool_round_entries", cols: "id,id_round,role,tab,group_list_flag as \"groupList_flag\",predict_select,media_result" },
//   { key: "round_bet", pg: "tool_round_bet", cols: "*" },
//   { key: "round_result", pg: "tool_round_result", cols: "*" },
//   { key: "msg_send", pg: "tool_msg_send", cols: "*" },
// ];

// app.get("/api/session-db/export", requireApiKey, async (req, res) => {
//   try {
//     const data = {};
//     for (const t of SESSION_DB_TABLES) {
//         try {
//           const baseSql = `SELECT ${t.cols} FROM session_db.${t.pg}`;
//           const sql =
//             t.key === "msg_type"
//               ? baseSql                   // không ORDER BY
//               : `${baseSql} ORDER BY id`; // các bảng khác vẫn dùng id
//           const rs = await pool.query(sql);
//           data[t.key] = rs.rows;
//         } catch (e) {
//           if (e.code === "42P01") data[t.key] = [];
//           else throw e;
//         }
//     }
//     return res.json({ ok: true, data });
//   } catch (err) {
//     console.error("🔥 /api/session-db/export error:", err);
//     return res.status(500).json({ ok: false, message: "Server error", error: err.message });
//   }
// });

// // ============================================================
// // 📥 DB SYNC: Download (lấy SQLite blob từ tool_db_backups, fallback)
// // GET /api/db/download
// // Header: x-api-key
// // Returns: application/octet-stream (SQLite file) hoặc 404 nếu chưa có backup
// // ============================================================
// app.get("/api/db/download", requireApiKey, async (req, res) => {
//   try {
//     const rs = await pool.query(
//       "SELECT data FROM session_db.tool_db_backups ORDER BY id DESC LIMIT 1"
//     );
//     if (rs.rows.length === 0 || !rs.rows[0].data) {
//       return res.status(404).json({
//         ok: false,
//         message: "Chưa có dữ liệu DB trên server",
//       });
//     }
//     const buf = Buffer.from(rs.rows[0].data);
//     res.setHeader("Content-Type", "application/octet-stream");
//     res.setHeader("Content-Disposition", "attachment; filename=master.db");
//     res.setHeader("Content-Length", buf.length);
//     res.send(buf);
//   } catch (err) {
//     console.error("🔥 /api/db/download error:", err);
//     return res.status(500).json({ ok: false, message: "Server error", error: err.message });
//   }
// });

// // ============================================================
// // 📤 SESSION_DB: Import (cập nhật session_db từ Tool khi xuống ca)
// // POST /api/session-db/import
// // Header: x-api-key, Content-Type: application/json
// // Body: { data: { telegram_config: [...], list_mess: [...], ... } }
// // ============================================================
// app.post("/api/session-db/import", requireApiKey, async (req, res) => {
//   try {
//     const payload = req.body && req.body.data;
//     if (!payload || typeof payload !== "object") {
//       return res.status(400).json({ ok: false, message: "Thiếu body.data (object)" });
//     }

//     // Debug: log received row counts
//     const counts = {};
//     for (const k of Object.keys(payload)) {
//       const arr = payload[k];
//       counts[k] = Array.isArray(arr) ? arr.length : 0;
//     }
//     console.log("📥 session-db/import received:", counts);

//     const tablesToImport = [
//       { key: "telegram_config", pg: "tool_telegram_config" },
//       { key: "list_mess", pg: "tool_list_mess" },
//       { key: "msg_type", pg: "tool_msg_type" },
//       { key: "session", pg: "tool_session" },
//       { key: "table_", pg: "tool_table" },
//       { key: "round", pg: "tool_round" },
//       { key: "round_entries", pg: "tool_round_entries" },
//       { key: "round_bet", pg: "tool_round_bet" },
//       { key: "round_result", pg: "tool_round_result" },
//       { key: "msg_send", pg: "tool_msg_send" }
//     ];

//     await pool.query(`
//       TRUNCATE session_db.tool_msg_send, session_db.tool_round_result, session_db.tool_round_bet,
//         session_db.tool_round_entries, session_db.tool_round, session_db.tool_table,
//         session_db.tool_session, session_db.tool_msg_type, session_db.tool_list_mess,
//         session_db.tool_telegram_config CASCADE
//     `);

//     let inserted = {};
//     for (const { key, pg } of tablesToImport) {
//       const rows = payload[key] || [];
//       if (rows.length === 0) continue;

//       const rawCols = Object.keys(rows[0]);
//       const pgCols = rawCols.map((c) => (c === "groupList_flag" ? "group_list_flag" : c));
//       const colList = pgCols.map((c) => `"${c}"`).join(", ");
//       const placeholders = pgCols.map((_, i) => "$" + (i + 1)).join(", ");

//       for (const row of rows) {
//         const vals = rawCols.map((c) => row[c]);
//         await pool.query(
//           `INSERT INTO session_db.${pg} (${colList}) VALUES (${placeholders})`,
//           vals
//         );
//       }
//       inserted[pg] = rows.length;
//     }
//     console.log("✅ session-db/import inserted:", inserted);
//     return res.json({ ok: true, message: "Đã cập nhật session_db" });
//   } catch (err) {
//     console.error("🔥 /api/session-db/import error:", err);
//     return res.status(500).json({ ok: false, message: "Server error", error: err.message });
//   }
// });

// // ============================================================
// // 📤 DB SYNC: Upload (đẩy SQLite blob vào tool_db_backups)
// // POST /api/db/upload
// // Header: x-api-key, Content-Type: application/json
// // Body: { "data": "<base64 sqlite>" } hoặc raw binary
// // ============================================================
// app.post("/api/db/upload", requireApiKey, async (req, res) => {
//   try {
//     let data;
//     if (req.body && typeof req.body.data === "string") {
//       data = Buffer.from(req.body.data, "base64");
//     } else if (Buffer.isBuffer(req.body)) {
//       data = req.body;
//     } else {
//       return res.status(400).json({
//         ok: false,
//         message: "Thiếu body.data (base64 SQLite) hoặc raw binary",
//       });
//     }
//     if (!data || data.length === 0) {
//       return res.status(400).json({ ok: false, message: "Dữ liệu rỗng" });
//     }
//     await pool.query(
//       "INSERT INTO session_db.tool_db_backups (data, username) VALUES ($1, $2)",
//       [data, req.body.username || null]
//     );
//     return res.json({
//       ok: true,
//       message: "Đã lưu DB lên server",
//     });
//   } catch (err) {
//     console.error("🔥 /api/db/upload error:", err);
//     return res.status(500).json({ ok: false, message: "Server error", error: err.message });
//   }
// });

// // ============================================================
// // 🚀 Start server

// ====================== IMPORTS ======================
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import * as db from "./db/index.js";
import { XOSO188_HEADERS, pingXoso188, triggerRegionSync } from "./db/lotterySync.js";

process.env.TZ = "Asia/Ho_Chi_Minh";

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// ====================== SIMPLE IN-MEM CACHE ======================
const memCache = new Map(); // key -> { exp, value }
function cacheGet(k) {
  const v = memCache.get(k);
  if (!v) return null;
  if (Date.now() > v.exp) {
    memCache.delete(k);
    return null;
  }
  return v.value;
}
function cacheSet(k, value, ttlMs) {
  memCache.set(k, { exp: Date.now() + ttlMs, value });
}

// ====================== 🔐 AUTH_ACCEPT GUARD (DB) ======================
// - Verify bằng auth_accept.api_key
// - Update last_used_at (+ ip/user_agent nếu chưa có) trong 1 query
app.use(async (req, res, next) => {
  const pathNorm = req.path.replace(/\/$/, "") || "/";

  // ===== WHITELIST (public / không cần key) =====
  if (pathNorm === "/health") return next();
  if (pathNorm === "/" || pathNorm.startsWith("/HTML_XoSo")) return next();
  if (pathNorm.startsWith("/api/lottery/db/")) return next();
  if (pathNorm === "/api/lottery/sync-test") return next();
  if (pathNorm === "/api/lottery/ping-xoso188") return next();

  // Import (POST) và push-kqxs (Genlogin) – whitelist (không cần x-gi8-key)
  if (pathNorm === "/api/lottery/import" && req.method === "POST") return next();
  if (pathNorm === "/api/lottery/push-kqxs" && req.method === "POST") return next();

  // ===== REQUIRE DB =====
  if (!db.pool) {
    return res.status(503).json({
      error: "DB not ready",
      message: "DATABASE_URL not set or init failed",
    });
  }

  // ===== REQUIRE KEY =====
  const key = req.headers["x-gi8-key"];
  if (!key) {
    return res.status(403).json({ error: "Forbidden", message: "Missing x-gi8-key" });
  }

  try {
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket?.remoteAddress ||
      null;

    const ua = req.headers["user-agent"] || null;

    // 1 query: verify + touch last_used
    const { rows } = await db.pool.query(
      `UPDATE auth_accept
       SET last_used_at = now(),
           ip_address   = COALESCE($2, ip_address),
           user_agent   = COALESCE($3, user_agent)
       WHERE api_key = $1 AND is_active = true
       RETURNING id, client_id, scopes`,
      [key, ip, ua]
    );

    if (!rows.length) {
      return res
        .status(403)
        .json({ error: "Forbidden", message: "Invalid or inactive x-gi8-key" });
    }

    req.gi8 = {
      auth_id: rows[0].id,
      client_id: rows[0].client_id,
      scopes: rows[0].scopes,
    };

    return next();
  } catch (e) {
    return res.status(500).json({ error: "Auth error", message: e.message });
  }
});

// ====================== SERVE FRONTEND ======================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));
app.use("/HTML_XoSo", express.static(path.join(__dirname, "HTML_XoSo")));
app.get("/", (_, res) => res.redirect("/HTML_XoSo/index_tructiep_miennam.html"));

// ====================== PROXY: /api/* -> DB hoặc https://xoso188.net/api/* ======================
const TARGET_BASE = "https://xoso188.net";

function formatDrawDate(d) {
  const day = String(d.getDate()).padStart(2, "0");
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const year = d.getFullYear();
  return { turnNum: `${day}/${month}/${year}`, ymd: `${year}-${month}-${day}` };
}

app.use("/api", async (req, res) => {
  const pathNorm = req.path.replace(/\/$/, "") || "/";

  // ======================
  // DB: /api/lottery/db/live, /api/lottery/db/draws (TRƯỚC proxy)
  // ======================
  if (pathNorm === "/lottery/db/live" && req.method === "GET" && db.pool) {
    try {
      const dateStr = req.query.date;
      const region = req.query.region || null;
      if (!dateStr) return res.status(400).json({ error: "Missing date (DD/MM/YYYY)" });
      const [d, m, y] = dateStr.split(/[\/\-]/).map(Number);
      const drawDate = `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const rows = await db.getLiveResults(drawDate, region);
      return res.json({ live: rows });
    } catch (err) {
      console.error("Get live error:", err);
      return res.status(500).json({ error: err.message });
    }
  }
  if (pathNorm === "/lottery/db/draws" && req.method === "GET" && db.pool) {
    try {
      const dateStr = req.query.date;
      const region = req.query.region || null;
      if (!dateStr) return res.status(400).json({ error: "Missing date (DD/MM/YYYY)" });
      const [d, m, y] = dateStr.split(/[\/\-]/).map(Number);
      const drawDate = `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const draws = await db.getDrawsByDate(drawDate, region);
      const withResults = await Promise.all(
        draws.map(async (dr) => {
          const results = await db.getResultsByDrawId(dr.id);
          return { ...dr, results };
        })
      );
      return res.json({ draws: withResults });
    } catch (err) {
      console.error("Get draws error:", err);
      return res.status(500).json({ error: err.message });
    }
  }

  const match = req.path.match(/^\/front\/open\/lottery\/history\/list\/game/);

  // ======================
  // DB READ (HOT PATH): /api/front/open/lottery/history/list/game
  // ======================
  if (match && req.method === "GET" && req.query.gameCode && db.pool) {
    const gameCode = String(req.query.gameCode);
    const limitNum = String(req.query.limitNum || "200");

    // cache 30s–60s tuỳ bạn
    const cacheKey = `history:${gameCode}:${limitNum}`;
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(cached);

    try {
      const data = await db.getLotteryHistoryListGame(gameCode, limitNum);
      if (!data) {
        return res.status(400).json({
          success: false,
          msg: "gameCode không tồn tại",
          code: 400,
        });
      }

      const now = new Date();
      const serverTime =
        `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(
          now.getDate()
        ).padStart(2, "0")} ` +
        `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(
          2,
          "0"
        )}:${String(now.getSeconds()).padStart(2, "0")}`;

      const issueList = [];
      for (const draw of data.draws) {
        const groups = ["", "", "", "", "", "", "", "", ""];
        const prizeMap = {
          DB: 0,
          G1: 1,
          G2: 2,
          G3: 3,
          G4: 4,
          G5: 5,
          G6: 6,
          G7: 7,
          G8: 8,
        };

        for (const r of draw.results) {
          const idx = prizeMap[r.prize_code];
          if (idx !== undefined) {
            groups[idx] = groups[idx] ? groups[idx] + "," + r.result_number : r.result_number;
          }
        }

        const { turnNum, ymd } = formatDrawDate(draw.draw_date);
        const openTime = `${ymd} ${data.openTimeByRegion}`;
        const openTimeStamp = new Date(openTime).getTime();
        const openNum = groups[0] || ""; // giải đặc biệt

        issueList.push({
          turnNum,
          openNum,
          openTime,
          openTimeStamp,
          detail: JSON.stringify(groups),
          status: 2,
          replayUrl: null,
          n11: null,
          jackpot: 0,
        });
      }

      const latestTurn = data.draws.length
        ? formatDrawDate(data.draws[0].draw_date)
        : { turnNum: "", ymd: "" };

      const t = {
        turnNum: latestTurn.turnNum,
        openTime: data.draws.length ? `${latestTurn.ymd} ${data.openTimeByRegion}` : "",
        serverTime,
        name: data.name,
        code: data.code,
        sort: data.sort,
        navCate: data.navCate,
        issueList,
      };

      const payload = { success: true, msg: "ok", code: 0, t };

      cacheSet(cacheKey, payload, 60_000); // 60s
      return res.json(payload);
    } catch (e) {
      console.warn("DB history/list/game error:", e.message);
      return res.status(500).json({
        success: false,
        msg: e.message || "Lỗi server",
        code: 500,
      });
    }
  }

  // ======================
  // FALLBACK PROXY TO xoso188
  // ======================
  const targetUrl = TARGET_BASE + req.originalUrl;
  try {
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: { ...XOSO188_HEADERS, Accept: req.headers.accept || "application/json" },
      timeout: 20000,
    });
    const body = await response.text();
    res.status(response.status);
    const ct = response.headers.get("content-type");
    if (ct) res.setHeader("content-type", ct);
    return res.send(body);
  } catch (err) {
    return res.status(500).json({ error: "Proxy failed", message: err.message });
  }
});

// ====================== HEALTH ======================
app.get("/health", (_, res) => res.send("✅ Railway Lottery Proxy Running"));

// ====================== LOTTERY FETCH (proxy xoso188) ======================
// GET /api/lottery/fetch?gameCode=xxx&limit=200
app.get("/api/lottery/fetch", async (req, res) => {
  const gameCode = req.query.gameCode;
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 500);

  if (!gameCode) return res.status(400).json({ error: "Missing gameCode" });

  const targetUrl = `https://xoso188.net/api/front/open/lottery/history/list/game?limitNum=${limit}&gameCode=${gameCode}`;
  try {
    const response = await fetch(targetUrl, {
      headers: { ...XOSO188_HEADERS, Accept: "application/json" },
      timeout: 20000,
    });
    const body = await response.text();
    res.status(response.status);
    res.setHeader("content-type", response.headers.get("content-type") || "application/json");
    return res.send(body);
  } catch (err) {
    return res.status(500).json({ error: "Fetch failed", message: err.message });
  }
});

// GET /api/lottery/ping-xoso188 (public)
app.get("/api/lottery/ping-xoso188", async (req, res) => {
  try {
    const result = await pingXoso188();
    return res.json(result);
  } catch (err) {
    return res.status(500).json({
      ok: false,
      status: 0,
      message: err?.message || String(err),
      count: 0,
      source: "xoso188",
    });
  }
});

// ====================== LOTTERY DB ======================
// POST /api/lottery/push-kqxs – Nhận kqxs_data từ Genlogin, convert và ghi DB
app.post("/api/lottery/push-kqxs", async (req, res) => {
  if (!db.pool) {
    return res.status(503).json({ error: "DB not configured", message: "DATABASE_URL not set" });
  }
  try {
    const { kqxs_data, region } = req.body;
    if (!kqxs_data || typeof kqxs_data !== "object") {
      return res.status(400).json({
        error: "Invalid payload",
        message: "kqxs_data (object) required. VD: { run, tinh, ntime, kq: { 13: {...}, 14: {...} } }",
      });
    }

    const { kqxsDataToDraws } = await import("./utils/minhNgocToXoso188.js");
    const regionKey = (region || "mn").toLowerCase();
    if (regionKey !== "mn" && regionKey !== "mt" && regionKey !== "mb") {
      return res.status(400).json({ error: "Invalid region", message: "region phải là mn | mt | mb" });
    }

    const draws = kqxsDataToDraws(kqxs_data, regionKey);
    if (draws.length === 0) {
      return res.json({
        ok: true,
        imported: 0,
        skipped: 0,
        message: "Không có dữ liệu hợp lệ để ghi (kq rỗng hoặc chưa có số)",
      });
    }

    const result = await db.importLotteryResults({ draws });
    memCache.clear();

    return res.json({ ok: true, ...result });
  } catch (err) {
    console.error("push-kqxs error:", err);
    return res.status(500).json({ error: "Push failed", message: err.message });
  }
});

// POST /api/lottery/import
app.post("/api/lottery/import", async (req, res) => {
  if (!db.pool) {
    return res.status(503).json({ error: "DB not configured", message: "DATABASE_URL not set" });
  }
  try {
    const { draws } = req.body;
    if (!Array.isArray(draws) || draws.length === 0) {
      return res.status(400).json({ error: "Invalid payload", message: "draws array required" });
    }

    const result = await db.importLotteryResults(req.body);

    // DB đã đổi => clear cache để list/game phản ánh ngay
    memCache.clear();

    return res.json({ ok: true, ...result });
  } catch (err) {
    console.error("Import error:", err);
    return res.status(500).json({ error: "Import failed", message: err.message });
  }
});

// GET /api/lottery/sync-test?region=mn|mt|mb (public)
app.get("/api/lottery/sync-test", async (req, res) => {
  try {
    const { runSyncTest } = await import("./db/lotterySync.js");
    const region = (req.query.region || "").toLowerCase();
    const result = await runSyncTest(region);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// GET /api/lottery/trigger-sync?region=mn|mt|mb (requires key by guard)
app.get("/api/lottery/trigger-sync", (req, res) => {
  if (!db.pool) {
    return res.status(503).json({ success: false, msg: "DB chưa sẵn sàng", code: 503 });
  }
  const region = (req.query.region || "").toLowerCase();
  if (region !== "mn" && region !== "mt" && region !== "mb") {
    return res.status(400).json({ success: false, msg: "region phải là mn | mt | mb", code: 400 });
  }
  triggerRegionSync(region, db.pool, db.importLotteryResults, db.importLiveResults);
  const label = { mn: "Miền Nam (16:15)", mt: "Miền Trung (17:15)", mb: "Miền Bắc (18:15)" }[region];
  return res.status(202).json({
    success: true,
    msg: `Đã kích hoạt sync ${label}. Poll 5 phút + XSTT 10s (nếu trong giờ xổ).`,
    code: 0,
    region,
  });
});

// GET /api/lottery/db/live?date=DD/MM/YYYY&region=MN|MT|MB – Xổ Số Trực Tiếp (kq_tructiep)
app.get("/api/lottery/db/live", async (req, res) => {
  if (!db.pool) return res.status(503).json({ error: "DB not configured" });
  try {
    const dateStr = req.query.date;
    const region = req.query.region || null;
    if (!dateStr) return res.status(400).json({ error: "Missing date (DD/MM/YYYY)" });

    const [d, m, y] = dateStr.split(/[\/\-]/).map(Number);
    const drawDate = `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;

    const rows = await db.getLiveResults(drawDate, region);
    return res.json({ live: rows });
  } catch (err) {
    console.error("Get live error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/lottery/db/draws?date=DD/MM/YYYY&region=MB|MT|MN (public by whitelist)
app.get("/api/lottery/db/draws", async (req, res) => {
  if (!db.pool) return res.status(503).json({ error: "DB not configured" });
  try {
    const dateStr = req.query.date;
    const region = req.query.region || null;
    if (!dateStr) return res.status(400).json({ error: "Missing date (DD/MM/YYYY)" });

    const [d, m, y] = dateStr.split(/[\/\-]/).map(Number);
    const drawDate = `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;

    const draws = await db.getDrawsByDate(drawDate, region);
    const withResults = await Promise.all(
      draws.map(async (dr) => {
        const results = await db.getResultsByDrawId(dr.id);
        return { ...dr, results };
      })
    );
    return res.json({ draws: withResults });
  } catch (err) {
    console.error("Get draws error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/lottery/db/history/:gameCode?limit=200 (public by whitelist)
app.get("/api/lottery/db/history/:gameCode", async (req, res) => {
  if (!db.pool) return res.status(503).json({ error: "DB not configured" });
  try {
    const gameCode = req.params.gameCode;
    const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 500);

    const { rows } = await db.pool.query(
      `SELECT d.draw_date, d.id as draw_id, p.api_game_code, p.code as province_code, r.code as region_code
       FROM lottery_draws d
       JOIN lottery_provinces p ON d.province_id = p.id
       JOIN regions r ON d.region_id = r.id
       WHERE p.api_game_code = $1
       ORDER BY d.draw_date DESC
       LIMIT $2`,
      [gameCode, limit]
    );

    const issueList = [];
    for (const row of rows) {
      const resRows = await db.getResultsByDrawId(row.draw_id);
      const groups = ["", "", "", "", "", "", "", "", ""];
      const prizeMap = { DB: 0, G1: 1, G2: 2, G3: 3, G4: 4, G5: 5, G6: 6, G7: 7, G8: 8 };

      for (const r of resRows) {
        const idx = prizeMap[r.prize_code];
        if (idx !== undefined) {
          groups[idx] = groups[idx] ? groups[idx] + "," + r.result_number : r.result_number;
        }
      }

      const turnNum = row.draw_date.toISOString().slice(0, 10).split("-").reverse().join("/");
      issueList.push({ turnNum, detail: JSON.stringify(groups) });
    }

    return res.json({ t: { issueList } });
  } catch (err) {
    console.error("History error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// ====================== START ======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Server chạy port", PORT);

  db
    .initDb()
    .then(async (pool) => {
      if (pool) {
        db.scheduleLotterySync(pool, db.importLotteryResults, db.importLiveResults);
        console.log(
          "[Startup] LotterySync: MN/MT/MB 16:15/17:15/18:15 (poll 5 phút); XSTT poll 10s. Nếu Railway sleep, gọi GET /api/lottery/trigger-sync?region=mn|mt|mb."
        );
      } else {
        console.warn(
          "[Startup] DB init trả null → không chạy scheduleLotterySync. Kiểm tra DATABASE_URL và log lỗi phía trên."
        );
      }

      const ping = await pingXoso188();
      console.log(
        "[Startup] xoso188:",
        ping.ok ? "OK (count=" + ping.count + ")" : "FAIL",
        ping.message || ""
      );
    })
    .catch((e) => console.warn("DB init:", e.message));
});
// // ============================================================
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
