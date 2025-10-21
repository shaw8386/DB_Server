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
// 🔧 Database connection
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ Database connection failed:", err));

// ============================================================
// 🔐 LOGIN API
// ============================================================
app.post("/login", async (req, res) => {
  const { username, password, ip } = req.body;

  console.log("📥 Login request:", username, ip);

  if (!username || !password || !ip) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    // 1️⃣ Tìm user
    const result = await pool.query("SELECT * FROM accounts WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      console.warn("⚠️ User not found:", username);
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const user = result.rows[0];

    // 2️⃣ So khớp password (nếu hash thì compare, nếu không thì so trực tiếp)
    let passwordMatch = false;
    try {
      passwordMatch = await bcrypt.compare(password, user.password);
    } catch (e) {
      passwordMatch = (password === user.password);
    }

    if (!passwordMatch) {
      console.warn("⚠️ Invalid password for user:", username);
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    // 3️⃣ Kiểm tra IP (nếu user có ip cụ thể trong DB)
    if (user.ip && user.ip !== ip) {
      console.warn("⚠️ Invalid IP for user:", username, "Expected:", user.ip, "Got:", ip);
      return res.status(403).json({ success: false, message: "Invalid IP address" });
    }

    // ✅ Thành công
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
// 🚀 Start server
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
