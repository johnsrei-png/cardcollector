import express from "express";
import { DatabaseSync } from "node:sqlite";
import dotenv from "dotenv";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const API_KEY = process.env.THECARDAPI_KEY;
const PORT = process.env.PORT || 3000;
const API_BASE = "https://thecardapi.com/api/v1/market";
// On Render, set DB_PATH to a path on the mounted disk, e.g. /var/data/collection.db
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "collection.db");
// Secret used to sign session cookies. MUST be set in production.
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-insecure-secret-change-me";
// Users seeded as: "alice:password1,bob:password2"
const USERS_RAW = process.env.APP_USERS || "";

if (!API_KEY || API_KEY === "tca_your_key_here") {
  console.error(
    "\n  No API key found. Set THECARDAPI_KEY (in .env locally, or in the host's\n" +
      "  environment variables). Get one free at https://www.thecardapi.com/pricing\n"
  );
  process.exit(1);
}

// ---------- Password hashing (scrypt) ----------
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}
function verifyPassword(password, stored) {
  const [salt, derived] = stored.split(":");
  if (!salt || !derived) return false;
  const check = crypto.scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(check, "hex");
  const b = Buffer.from(derived, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- Database ----------
const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL;");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS cards (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    title         TEXT NOT NULL,
    query         TEXT NOT NULL,
    grader        TEXT,
    grade         TEXT,
    paid          REAL,
    notes         TEXT,
    image_url     TEXT,
    added_at      TEXT NOT NULL,
    latest_price  REAL,
    avg_price     REAL,
    comp_count    INTEGER,
    valued_at     TEXT
  );
`);

// Seed / update users from APP_USERS env var
function seedUsers() {
  if (!USERS_RAW.trim()) {
    const count = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
    if (count === 0) {
      console.warn(
        "\n  WARNING: No APP_USERS set and no users exist. Set APP_USERS like\n" +
          '  "alice:secret1,bob:secret2" so you can log in.\n'
      );
    }
    return;
  }
  const pairs = USERS_RAW.split(",").map((p) => p.trim()).filter(Boolean);
  for (const pair of pairs) {
    const idx = pair.indexOf(":");
    if (idx < 1) continue;
    const username = pair.slice(0, idx).trim().toLowerCase();
    const password = pair.slice(idx + 1);
    if (!username || !password) continue;
    const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
    if (existing) {
      db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(
        hashPassword(password),
        existing.id
      );
    } else {
      db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(
        username,
        hashPassword(password)
      );
    }
  }
  console.log(`  Seeded/updated ${pairs.length} user(s) from APP_USERS.`);
}
seedUsers();

// ---------- Sessions (signed cookie) ----------
function sign(value) {
  const mac = crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
  return `${value}.${mac}`;
}
function unsign(signed) {
  if (!signed) return null;
  const dot = signed.lastIndexOf(".");
  if (dot < 0) return null;
  const value = signed.slice(0, dot);
  const mac = signed.slice(dot + 1);
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return value;
}
function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

// ---------- The Card API helper ----------
async function fetchSales(params) {
  const url = new URL(`${API_BASE}/sales`);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  }
  const res = await fetch(url, { headers: { "x-market-api-key": API_KEY } });
  if (!res.ok) {
    const messages = {
      401: "Invalid or missing API key.",
      403: "Your plan doesn't allow this action.",
      422: "Invalid search parameters.",
      429: "Daily sales limit reached (resets midnight UTC).",
    };
    const msg = messages[res.status] || `API error (${res.status}).`;
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

function summarize(sales) {
  if (!sales.length) return { latest_price: null, avg_price: null, comp_count: 0 };
  const prices = sales.map((s) => s.price).filter((p) => typeof p === "number");
  const latest = sales[0].price ?? null;
  const avg = prices.length ? prices.reduce((a, b) => a + b, 0) / prices.length : null;
  return {
    latest_price: latest,
    avg_price: avg !== null ? Math.round(avg * 100) / 100 : null,
    comp_count: prices.length,
  };
}

// ---------- App ----------
const app = express();
app.set("trust proxy", 1); // behind Render's proxy, for secure cookies
app.use(express.json({ limit: "5mb" }));

// Auth middleware for /api routes (except /api/login and /api/me)
function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const userId = unsign(cookies.session);
  if (!userId) return res.status(401).json({ error: "Not logged in." });
  const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(Number(userId));
  if (!user) return res.status(401).json({ error: "Session invalid." });
  req.user = user;
  next();
}

// ---- Auth endpoints ----
app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: "Wrong username or password." });
  }
  const cookie = sign(String(user.id));
  const secure = process.env.NODE_ENV === "production";
  res.setHeader(
    "Set-Cookie",
    `session=${encodeURIComponent(cookie)}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax${secure ? "; Secure" : ""}`
  );
  res.json({ username: user.username });
});

app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const cookies = parseCookies(req);
  const userId = unsign(cookies.session);
  if (!userId) return res.json({ user: null });
  const user = db.prepare("SELECT username FROM users WHERE id = ?").get(Number(userId));
  res.json({ user: user ? user.username : null });
});

// ---- Search (auth required so public visitors can't spend your quota) ----
app.get("/api/search", requireAuth, async (req, res) => {
  try {
    const data = await fetchSales({
      q: req.query.q,
      platform: req.query.platform,
      listing_type: req.query.listing_type,
      price_min: req.query.price_min,
      price_max: req.query.price_max,
      sort: req.query.sort || "date_desc",
      limit: req.query.limit || 25,
      page: req.query.page || 1,
    });
    res.json(data);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// ---- Collection (scoped to the logged-in user) ----
app.get("/api/collection", requireAuth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM cards WHERE user_id = ? ORDER BY added_at DESC")
    .all(req.user.id);
  res.json(rows);
});

// ---- Export: full backup as JSON ----
app.get("/api/collection/export.json", requireAuth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM cards WHERE user_id = ? ORDER BY added_at DESC")
    .all(req.user.id);
  const payload = {
    format: "card-collection-backup",
    version: 1,
    exported_at: new Date().toISOString(),
    username: req.user.username,
    cards: rows.map(({ id, user_id, ...rest }) => rest), // drop internal ids
  };
  const stamp = new Date().toISOString().slice(0, 10);
  res.setHeader("Content-Type", "application/json");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="collection-${req.user.username}-${stamp}.json"`
  );
  res.send(JSON.stringify(payload, null, 2));
});

// ---- Export: spreadsheet-friendly CSV ----
function csvCell(v) {
  if (v == null) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
app.get("/api/collection/export.csv", requireAuth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM cards WHERE user_id = ? ORDER BY added_at DESC")
    .all(req.user.id);
  const cols = [
    "title", "query", "grader", "grade", "paid", "notes",
    "latest_price", "avg_price", "comp_count", "valued_at", "added_at",
  ];
  const lines = [cols.join(",")];
  for (const r of rows) lines.push(cols.map((c) => csvCell(r[c])).join(","));
  const stamp = new Date().toISOString().slice(0, 10);
  res.setHeader("Content-Type", "text/csv");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="collection-${req.user.username}-${stamp}.csv"`
  );
  res.send(lines.join("\n"));
});

// ---- Import: restore from a JSON backup ----
// mode "merge" (default) adds the cards; mode "replace" wipes this user's
// cards first, then adds. Only ever touches the logged-in user's data.
app.post("/api/collection/import", requireAuth, (req, res) => {
  const body = req.body || {};
  const cards = Array.isArray(body.cards) ? body.cards : null;
  if (!cards) return res.status(400).json({ error: "No cards array in uploaded file." });
  const mode = body.mode === "replace" ? "replace" : "merge";

  const insert = db.prepare(
    `INSERT INTO cards (user_id, title, query, grader, grade, paid, notes, image_url, added_at, latest_price, avg_price, comp_count, valued_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  let imported = 0, skipped = 0;
  try {
    db.exec("BEGIN");
    if (mode === "replace") {
      db.prepare("DELETE FROM cards WHERE user_id = ?").run(req.user.id);
    }
    for (const c of cards) {
      if (!c || !c.title || !c.query) { skipped++; continue; }
      insert.run(
        req.user.id,
        c.title,
        c.query,
        c.grader || null,
        c.grade || null,
        c.paid != null && c.paid !== "" ? Number(c.paid) : null,
        c.notes || null,
        c.image_url || null,
        c.added_at || new Date().toISOString(),
        c.latest_price != null ? Number(c.latest_price) : null,
        c.avg_price != null ? Number(c.avg_price) : null,
        c.comp_count != null ? Number(c.comp_count) : null,
        c.valued_at || null
      );
      imported++;
    }
    db.exec("COMMIT");
    res.json({ ok: true, imported, skipped, mode });
  } catch (e) {
    try { db.exec("ROLLBACK"); } catch {}
    res.status(500).json({ error: "Import failed: " + e.message });
  }
});

app.post("/api/collection", requireAuth, (req, res) => {
  const { title, query, grader, grade, paid, notes, image_url } = req.body;
  if (!title || !query) return res.status(400).json({ error: "title and query are required." });
  const info = db
    .prepare(
      `INSERT INTO cards (user_id, title, query, grader, grade, paid, notes, image_url, added_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      req.user.id,
      title,
      query,
      grader || null,
      grade || null,
      paid != null && paid !== "" ? Number(paid) : null,
      notes || null,
      image_url || null,
      new Date().toISOString()
    );
  const card = db.prepare("SELECT * FROM cards WHERE id = ?").get(info.lastInsertRowid);
  res.json(card);
});

app.patch("/api/collection/:id", requireAuth, (req, res) => {
  const card = db
    .prepare("SELECT * FROM cards WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user.id);
  if (!card) return res.status(404).json({ error: "Not found." });
  const paid =
    req.body.paid != null && req.body.paid !== "" ? Number(req.body.paid) : card.paid;
  const notes = req.body.notes != null ? req.body.notes : card.notes;
  db.prepare("UPDATE cards SET paid = ?, notes = ? WHERE id = ?").run(paid, notes, card.id);
  res.json(db.prepare("SELECT * FROM cards WHERE id = ?").get(card.id));
});

app.delete("/api/collection/:id", requireAuth, (req, res) => {
  db.prepare("DELETE FROM cards WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post("/api/collection/:id/value", requireAuth, async (req, res) => {
  const card = db
    .prepare("SELECT * FROM cards WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user.id);
  if (!card) return res.status(404).json({ error: "Not found." });
  try {
    const data = await fetchSales({ q: card.query, limit: 50, sort: "date_desc" });
    const summary = summarize(data.data || []);
    db.prepare(
      `UPDATE cards SET latest_price = ?, avg_price = ?, comp_count = ?, valued_at = ? WHERE id = ?`
    ).run(summary.latest_price, summary.avg_price, summary.comp_count, new Date().toISOString(), card.id);
    res.json(db.prepare("SELECT * FROM cards WHERE id = ?").get(card.id));
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// Static files last, so /api routes win
const PUBLIC_DIR = path.join(__dirname, "public");
const INDEX_FILE = path.join(PUBLIC_DIR, "index.html");

app.use(express.static(PUBLIC_DIR));

// Explicit root + catch-all for any non-API path -> serve the app shell.
app.get("/", (req, res) => {
  if (fs.existsSync(INDEX_FILE)) return res.sendFile(INDEX_FILE);
  res.status(500).send("index.html not found on server. Check that public/index.html exists in the repo.");
});
app.get(/^\/(?!api\/).*/, (req, res) => {
  if (fs.existsSync(INDEX_FILE)) return res.sendFile(INDEX_FILE);
  res.status(404).send("Not found.");
});

app.listen(PORT, () => {
  console.log(`\n  Card Collection running on port ${PORT}`);
  // Startup diagnostics: what does the server actually see on disk?
  try {
    console.log(`  __dirname: ${__dirname}`);
    console.log(`  cwd: ${process.cwd()}`);
    const here = fs.readdirSync(__dirname);
    console.log(`  files in __dirname: ${JSON.stringify(here)}`);
    console.log(`  public/ exists: ${fs.existsSync(PUBLIC_DIR)}`);
    if (fs.existsSync(PUBLIC_DIR)) {
      console.log(`  public/ contents: ${JSON.stringify(fs.readdirSync(PUBLIC_DIR))}`);
    }
    console.log(`  index.html present: ${fs.existsSync(INDEX_FILE)}\n`);
  } catch (e) {
    console.log(`  diagnostic error: ${e.message}\n`);
  }
});
