import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcrypt";

dotenv.config();
const { Pool } = pkg;
const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// 🧩 LOGIN API (check username + password + ip)
app.post("/login", async (req, res) => {
  const { username, password, ip } = req.body;

  try {
    // 1️⃣ Tìm user theo username
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: "User not found" });
    }

    const user = result.rows[0];

    // 2️⃣ So khớp password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    // 3️⃣ Kiểm tra IP
    if (user.ip && user.ip !== ip) {
      return res.status(403).json({ success: false, message: "Invalid IP address" });
    }

    // ✅ Login thành công
    res.json({
      success: true,
      message: "Login successful",
      user: {
        username: user.username,
        ip: user.ip,
        type: user.type,
      },
    });
  } catch (err) {
    console.error("❌ Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.listen(process.env.PORT || 3000, () =>
  console.log(`✅ Server running on port ${process.env.PORT || 3000}`)
);
