const express = require("express");
const crypto = require("crypto");

const router = express.Router();

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

const okMessage = {
  message:
    "Jeśli konto istnieje, wygenerowano token do resetu hasła.",
};

// POST /api/password/forgot
router.post("/api/password/forgot", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();

    // nie zdradzamy czy email istnieje
    if (!email) return res.status(200).json(okMessage);

    const [rows] = await req.pool.query(
      "SELECT id FROM users WHERE email=? LIMIT 1",
      [email]
    );

    if (!rows.length) return res.status(200).json(okMessage);

    const user = rows[0];

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = sha256(rawToken);
    const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 min

    await req.pool.query(
      "UPDATE users SET reset_token_hash=?, reset_token_expires=? WHERE id=?",
      [tokenHash, expires, user.id]
    );

    const baseUrl = process.env.PUBLIC_BASE_URL || "http://localhost:5173";
    const resetLink = `${baseUrl}/reset-password?token=${rawToken}`;
    console.log("RESET LINK:", resetLink);

    // DEMO: bez maila — zwracamy token w odpowiedzi, gdy env=1
    if (process.env.RESET_TOKEN_IN_RESPONSE === "1") {
      return res.status(200).json({ ...okMessage, token: rawToken });
    }

    return res.status(200).json(okMessage);
  } catch (err) {
    return res.status(200).json(okMessage);
  }
});

// POST /api/password/reset
router.post("/api/password/reset", async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (!token || newPassword.length < 6) {
      return res.status(400).json({ error: "token and newPassword required" });
    }

    const tokenHash = sha256(token);

    const [rows] = await req.pool.query(
      "SELECT id, reset_token_expires FROM users WHERE reset_token_hash=? LIMIT 1",
      [tokenHash]
    );

    if (!rows.length) return res.status(400).json({ error: "Invalid token" });

    const user = rows[0];
    const expires = new Date(user.reset_token_expires);

    if (Number.isNaN(expires.getTime()) || expires.getTime() < Date.now()) {
      return res.status(400).json({ error: "Token expired" });
    }

    // u Was hasła są plaintext — spójnie z login/register
    await req.pool.query(
      "UPDATE users SET password=?, reset_token_hash=NULL, reset_token_expires=NULL WHERE id=?",
      [newPassword, user.id]
    );

    return res.status(200).json({ message: "Password updated" });
  } catch (err) {
    console.error("PASSWORD RESET error:", err);
    return res.status(500).json({ error: "internal error" });
  }
});

module.exports = router;
