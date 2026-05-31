# The Stash — Card Collection Tracker

A web app that tracks your trading card collection and pulls real sold prices from
[thecardapi.com](https://www.thecardapi.com). Each card shows its **latest sale price**
and the **average of recent comps**, side by side. Supports **multiple logins**, with
each person seeing only their own collection.

Your API key stays on the server — never exposed to the browser.

---

## Run it locally

1. Node.js **22.5+** required (`node --version`). Uses Node's built-in SQLite — nothing to compile.
2. Install: `npm install`
3. Set up config: `cp .env.example .env`, then edit `.env`:
   - `THECARDAPI_KEY` — your key from https://www.thecardapi.com/pricing
   - `APP_USERS` — login accounts, e.g. `alice:secret1,bob:secret2`
   - `SESSION_SECRET` — any long random string
4. Start: `npm start` → open http://localhost:3000 and sign in.

---

## Deploy to Render (always-on hosting)

This repo includes `render.yaml`, which provisions everything (web service +
persistent disk + env vars) automatically.

### One-time setup

1. **Push to GitHub.** Create a new repo and push this project to it. (`.env`,
   `node_modules`, and `collection.db` are git-ignored and will not be uploaded.)

2. **Create the service on Render.**
   - Go to https://render.com and sign in with GitHub.
   - Click **New → Blueprint**, pick your repo. Render reads `render.yaml`.
   - It will create a web service with a 1 GB persistent disk mounted at `/var/data`.

3. **Set the two secret values** when prompted (or under the service's **Environment** tab):
   - `THECARDAPI_KEY` — your card API key.
   - `APP_USERS` — your logins, e.g. `alice:longpassword,bob:anotherlongpassword`.

   `SESSION_SECRET`, `NODE_ENV`, and `DB_PATH` are set automatically by the blueprint.

4. Click **Apply / Deploy**. After the build, your app is live at
   `https://<your-service>.onrender.com`. Sign in with any account from `APP_USERS`.

### Good to know

- **Free tier sleeps** after ~15 min idle; the first request afterward takes a few
  seconds to wake. Fine for personal use. Upgrade to a paid instance to keep it always warm.
- **Your data persists** on the mounted disk across redeploys and restarts because
  `DB_PATH=/var/data/collection.db`. (Without a disk, Render's filesystem is wiped on
  every deploy — that's why the blueprint declares one.)
- **Changing users later:** edit the `APP_USERS` variable in the Render dashboard and
  redeploy. Existing usernames have their password updated; new ones are added. Removing
  someone from the variable does not delete their stored cards — it just stops new logins
  being seeded; tell me if you want a hard "remove user + their data" command.

---

## How to use

**Search Sales** — full-text search across sold listings with platform, sale-type, and
price filters. Boolean syntax: `(psa,bgs)` = OR, `-reprint` = exclude, `"topps chrome"` =
exact phrase. Tap **+ Collection** to save a card (you can set the valuation query,
grader, grade, what you paid, and notes).

**My Collection** — your saved cards with latest + average value side by side, plus
unrealized gain/loss if you entered what you paid. **Refresh value** pulls fresh comps
for that card; a summary strip totals your collection.

---

## Data & plan notes

- Free tier: **5,000 sales rows/day**, **3-day lookback**. Valuations reflect only the
  last few days of sales unless you upgrade. "Refresh value" pulls up to 50 comps per card.
- "Average (recent)" is the mean of comps for that card's saved search query — make the
  query specific (include grader + grade) for tighter valuations.
- All prices are true sold prices in USD, including real negotiated Best Offer prices.

---

## Security

- Passwords are hashed with scrypt; never stored in plaintext.
- Login sessions use a signed (HMAC) HttpOnly cookie; tampered cookies are rejected.
- Search and all collection routes require login, so public visitors can't spend your
  API quota or see your data.
- If your API key was ever pasted anywhere public (including a chat), **regenerate it**
  and update `THECARDAPI_KEY`.

## Files

- `server.js` — Express backend: auth, sessions, per-user collections, API proxy, valuations.
- `public/index.html` — entire frontend (login screen + app) in one file.
- `render.yaml` — Render deployment blueprint (service + disk + env vars).
- `.env.example` — template for local config.
