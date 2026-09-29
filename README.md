# Keystone Account Portal

A sign-in and sign-up site with a real backend.

- **Server:** Node.js + Express
- **Database:** SQLite (a single file, `data/keystone.db`)
- **Passwords:** hashed with bcrypt (cost 12). The plain password is never stored.
- **Sessions:** a random token in a secure, HTTP-only, SameSite=Lax cookie, valid for 30 days. Only a SHA-256 hash of the token is kept in the database.
- **Protection:** rate limit of 10 attempts per 15 minutes on sign-in, sign-up and delete; JSON-only API to block cross-site form posts; security headers; the same "wrong email or password" message whether or not the email exists.

## Run it on your computer

You need Node.js 20 or newer (https://nodejs.org).

```bash
npm install
npm start
```

Open http://localhost:3000.

## Put it on the web

### Option A: Railway (recommended, keeps your data)

1. Push this folder to a new GitHub repository.
2. At https://railway.app, choose **New Project → Deploy from GitHub repo** and pick the repository.
3. In the service, open **Settings → Volumes** and add a volume mounted at `/data`.
4. Under **Variables**, add:
   - `NODE_ENV` = `production`
   - `DB_PATH` = `/data/keystone.db`
5. Under **Settings → Networking**, click **Generate Domain**. Your portal is live at that address.

### Option B: Render

1. Push this folder to GitHub.
2. At https://render.com, choose **New → Web Service** and connect the repository.
3. Build command: `npm install`. Start command: `npm start`.
4. Environment variables: `NODE_ENV` = `production`.
5. **Important:** Render's free plan wipes the disk on every deploy or restart, so all accounts would be lost. To keep them, use a paid instance, add a **Disk** mounted at `/data`, and set `DB_PATH` = `/data/keystone.db`.

`NODE_ENV=production` turns on the `Secure` cookie flag, so the site must be served over HTTPS (both hosts do this for you).

## API

| Method | Path | Body | What it does |
|---|---|---|---|
| POST | `/api/signup` | `{name, email, password}` | Creates an account and signs in |
| POST | `/api/login` | `{email, password}` | Signs in |
| POST | `/api/logout` | `{}` | Signs out this browser |
| POST | `/api/logout-all` | `{}` | Signs out every device |
| GET | `/api/me` | — | Returns the signed-in user |
| POST | `/api/delete-account` | `{password}` | Deletes the account |
| GET | `/healthz` | — | Health check |

## Not included yet

Email verification, password reset by email, and "Sign in with Google" need an email or OAuth provider. They can be added on top of this.
