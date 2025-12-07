// backend/server.js
// BNBFarm backend (Express + Postgres + ethers)
// Ne mettez JAMAIS la clé privée ici — stockez-la dans les ENV (Railway).

import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import pkg from "pg";
import { ethers } from "ethers";
import axios from "axios";
import CronJob from "cron";

const { Pool } = pkg;
const { CronJob: Cron } = CronJob;

const app = express();
app.use(express.json({ limit: "1mb" }));

/* -----------------------------
   ENV / configuration
   ----------------------------- */
const {
  DATABASE_URL,
  ADMIN_PRIVATE_KEY,
  ADMIN_ADDRESS,
  BSC_RPC,
  JWT_SECRET,
  MIN_USD = "0.1",
  YIELD_PERCENT = "2",
  YIELD_MINUTES = "5",
  REQUIRED_CONFIRMATIONS = "3"
} = process.env;

if (!DATABASE_URL) {
  console.error("FATAL: DATABASE_URL is missing");
  process.exit(1);
}
if (!BSC_RPC) {
  console.error("FATAL: BSC_RPC is missing");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET is missing");
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: false });

/* -----------------------------
   Ethers provider + wallet
   ----------------------------- */
const provider = new ethers.providers.JsonRpcProvider(BSC_RPC);
let wallet = null;
if (ADMIN_PRIVATE_KEY && ADMIN_ADDRESS) {
  const key = ADMIN_PRIVATE_KEY.startsWith("0x") ? ADMIN_PRIVATE_KEY : "0x" + ADMIN_PRIVATE_KEY;
  wallet = new ethers.Wallet(key, provider);
  console.log("Admin wallet loaded for address", ADMIN_ADDRESS);
} else {
  console.warn("Admin wallet NOT configured (ADMIN_PRIVATE_KEY or ADMIN_ADDRESS missing). Withdrawals disabled.");
}

/* -----------------------------
   Helpers
   ----------------------------- */
const query = (text, params) => pool.query(text, params);

const YP = parseFloat(YIELD_PERCENT);
const YM = parseInt(YIELD_MINUTES, 10);
const MIN_USD_F = parseFloat(MIN_USD);
const CONFIRMATIONS = parseInt(REQUIRED_CONFIRMATIONS, 10) || 3;

// Convert USD -> BNB using CoinGecko
async function usdToBnb(usd) {
  try {
    const r = await axios.get(
      "https://api.coingecko.com/api/v3/simple/price",
      { params: { ids: "binancecoin", vs_currencies: "usd" }, timeout: 10000 }
    );
    const price = r.data?.binancecoin?.usd;
    if (!price) throw new Error("Coingecko price missing");
    return parseFloat(usd) / parseFloat(price);
  } catch (e) {
    console.error("usdToBnb error:", e.message);
    throw new Error("Price conversion failed");
  }
}

// Simple response wrapper
const ok = (res, data = {}) => res.json({ ok: true, ...data });
const err = (res, status = 400, message = "error") => res.status(status).json({ ok: false, error: message });

/* -----------------------------
   Authentication helpers
   ----------------------------- */
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return err(res, 401, "no authorization header");
  const token = auth.split(" ")[1];
  if (!token) return err(res, 401, "invalid token format");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return err(res, 401, "invalid token");
  }
}

/* -----------------------------
   Routes
   ----------------------------- */

// Health
app.get("/", (req, res) => res.send("BNBFarm backend running"));

// Signup
app.post("/signup", async (req, res) => {
  const { email, password, referrer } = req.body;
  if (!email || !password) return err(res, 400, "email and password required");
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await query(
      "INSERT INTO users(email,password_hash,referrer_id) VALUES($1,$2,$3) RETURNING id,email",
      [email.toLowerCase(), hash, referrer || null]
    );
    const user = result.rows[0];
    // Optionally insert referrals table rows (application-specific)
    const token = signToken({ id: user.id, email: user.email });
    return ok(res, { token });
  } catch (e) {
    console.error("signup error:", e.message);
    if (e.code === "23505") return err(res, 400, "email already exists");
    return err(res, 500, "signup failed");
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return err(res, 400, "email and password required");
  try {
    const r = await query("SELECT id,email,password_hash FROM users WHERE email=$1", [email.toLowerCase()]);
    if (r.rowCount === 0) return err(res, 400, "invalid credentials");
    const u = r.rows[0];
    const okpass = await bcrypt.compare(password, u.password_hash);
    if (!okpass) return err(res, 400, "invalid credentials");
    const token = signToken({ id: u.id, email: u.email });
    return ok(res, { token });
  } catch (e) {
    console.error("login error:", e.message);
    return err(res, 500, "login failed");
  }
});

// Get balance
app.get("/balance", authMiddleware, async (req, res) => {
  try {
    const r = await query("SELECT balance FROM users WHERE id=$1", [req.user.id]);
    if (r.rowCount === 0) return err(res, 404, "user not found");
    return ok(res, { balance: r.rows[0].balance });
  } catch (e) {
    console.error("balance error:", e.message);
    return err(res, 500, "could not fetch balance");
  }
});

// Report deposit (user provides txHash)
app.post("/deposit/report", authMiddleware, async (req, res) => {
  const { txHash } = req.body;
  if (!txHash) return err(res, 400, "txHash required");
  try {
    // fetch transaction
    const tx = await provider.getTransaction(txHash);
    if (!tx) return err(res, 404, "transaction not found on RPC");
    if (!tx.to) return err(res, 400, "transaction has no recipient");

    if (!ADMIN_ADDRESS || tx.to.toLowerCase() !== ADMIN_ADDRESS.toLowerCase()) {
      return err(res, 400, "transaction not to the service address");
    }

    // Ensure confirmations
    const receipt = await provider.getTransactionReceipt(txHash);
    const confirmations = receipt && receipt.confirmations ? receipt.confirmations : 0;
    if (confirmations < CONFIRMATIONS) {
      return err(res, 400, `transaction has ${confirmations} confirmations, require ${CONFIRMATIONS}`);
    }

    const valueBNB = parseFloat(ethers.formatEther(tx.value));
    const minBnb = await usdToBnb(MIN_USD_F);
    if (valueBNB < minBnb) {
      return err(res, 400, `amount below minimum ${MIN_USD_F}$ (≈ ${minBnb.toFixed(8)} BNB)`);
    }

    // Prevent double processing
    const exist = await query("SELECT id FROM transactions WHERE txhash=$1", [txHash]);
    if (exist.rowCount > 0) return err(res, 400, "transaction already processed");

    // Insert transaction and credit balance (transactional)
    await query("BEGIN");
    await query(
      "INSERT INTO transactions(user_id,txhash,type,amount,status,created_at) VALUES($1,$2,$3,$4,$5,now())",
      [req.user.id, txHash, "deposit", valueBNB, "confirmed"]
    );
    await query("UPDATE users SET balance = balance + $1 WHERE id=$2", [valueBNB, req.user.id]);
    await query("COMMIT");

    return ok(res, { credited: valueBNB });
  } catch (e) {
    await query("ROLLBACK").catch(() => {});
    console.error("deposit.report error:", e.message);
    return err(res, 500, "deposit verification failed");
  }
});

// Withdraw request
app.post("/withdraw", authMiddleware, async (req, res) => {
  const { to, amount } = req.body;
  if (!to || !amount) return err(res, 400, "to and amount are required");
  const amt = parseFloat(amount);
  if (isNaN(amt) || amt <= 0) return err(res, 400, "invalid amount");

  if (!wallet) return err(res, 500, "withdrawals not configured on server");

  try {
    const userRes = await query("SELECT balance FROM users WHERE id=$1", [req.user.id]);
    if (userRes.rowCount === 0) return err(res, 404, "user not found");
    const balance = parseFloat(userRes.rows[0].balance);
    if (amt > balance) return err(res, 400, "insufficient balance");

    // Deduct and send transaction within DB tx
    await query("BEGIN");
    await query("UPDATE users SET balance = balance - $1 WHERE id=$2", [amt, req.user.id]);

    const txResp = await wallet.sendTransaction({ to, value: ethers.parseEther(String(amt)) });
    // wait 1 confirmation before marking as sent/confirmed
    const receipt = await txResp.wait(1);

    await query(
      "INSERT INTO transactions(user_id,txhash,type,amount,to_address,status,created_at) VALUES($1,$2,$3,$4,$5,$6,now())",
      [req.user.id, txResp.hash, "withdraw", amt, to, receipt.status === 1 ? "confirmed" : "failed"]
    );

    await query("COMMIT");
    return ok(res, { txHash: txResp.hash });
  } catch (e) {
    await query("ROLLBACK").catch(() => {});
    console.error("withdraw error:", e.message);
    return err(res, 500, "withdraw failed: " + e.message);
  }
});

/* -----------------------------
   Yield cron job (applies every YIELD_MINUTES)
   ----------------------------- */
if (YM > 0) {
  try {
    const cronPattern = `*/${YM} * * * *`;
    const job = new Cron(
      cronPattern,
      async function () {
        console.log("Yield job starting at", new Date().toISOString());
        try {
          // Select users with positive balance
          const r = await query("SELECT id, balance FROM users WHERE balance > 0");
          for (const user of r.rows) {
            const bal = parseFloat(user.balance);
            if (isNaN(bal) || bal <= 0) continue;
            const gain = bal * (YP / 100);
            // transaction: add yield and record transactions + referral commissions
            await query("BEGIN");
            await query("UPDATE users SET balance = balance + $1 WHERE id=$2", [gain, user.id]);
            await query(
              "INSERT INTO transactions(user_id,type,amount,status,created_at) VALUES($1,$2,$3,$4,now())",
              [user.id, "yield", gain, "applied"]
            );

            // commissions on gain: level1 10%, level2 3%, level3 1%
            // get referrer chain
            const r1 = await query("SELECT referrer_id FROM users WHERE id=$1", [user.id]);
            let level1 = r1.rowCount ? r1.rows[0].referrer_id : null;
            if (level1) {
              const c1 = gain * 0.10;
              await query("UPDATE users SET balance = balance + $1 WHERE id=$2", [c1, level1]);
              await query("INSERT INTO transactions(user_id,type,amount,status,created_at) VALUES($1,$2,$3,$4,now())", [level1, "referral_comm", c1, "applied"]);
              // level2
              const r2 = await query("SELECT referrer_id FROM users WHERE id=$1", [level1]);
              let level2 = r2.rowCount ? r2.rows[0].referrer_id : null;
              if (level2) {
                const c2 = gain * 0.03;
                await query("UPDATE users SET balance = balance + $1 WHERE id=$2", [c2, level2]);
                await query("INSERT INTO transactions(user_id,type,amount,status,created_at) VALUES($1,$2,$3,$4,now())", [level2, "referral_comm", c2, "applied"]);
                // level3
                const r3 = await query("SELECT referrer_id FROM users WHERE id=$1", [level2]);
                let level3 = r3.rowCount ? r3.rows[0].referrer_id : null;
                if (level3) {
                  const c3 = gain * 0.01;
                  await query("UPDATE users SET balance = balance + $1 WHERE id=$2", [c3, level3]);
                  await query("INSERT INTO transactions(user_id,type,amount,status,created_at) VALUES($1,$2,$3,$4,now())", [level3, "referral_comm", c3, "applied"]);
                }
              }
            }

            await query("COMMIT");
          }
          console.log("Yield job completed at", new Date().toISOString());
        } catch (e) {
          await query("ROLLBACK").catch(() => {});
          console.error("Yield job error:", e.message);
        }
      },
      null,
      true,
      null
    );
    job.start();
    console.log(`Cron job scheduled: every ${YM} minute(s)`);
  } catch (e) {
    console.error("Failed to schedule cron job:", e.message);
  }
}

/* -----------------------------
   Start server
   ----------------------------- */
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`BNBFarm backend listening on port ${port}`);
});
