# Production Readiness & Free Deployment Guide

## Part 1 — Production Readiness Analysis

Before deploying publicly, these gaps must be closed. They are ordered by severity.

---

### 🔴 Critical (fix before any public URL)

| # | Issue | Current state | Fix |
|---|---|---|---|
| P1 | Hardcoded admin credentials | `admin:admin` in code | Set `JWT_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` env vars; never commit them |
| P2 | No HTTPS | Plain HTTP | Terminate TLS at reverse proxy (Caddy / Nginx) or use a platform that provides it (Railway, Render, Fly.io) |
| P3 | CORS origin is `*` or `localhost` | Dev default | Set `CORS_ALLOWED_ORIGINS=https://your-domain.com` in production env |
| P4 | MongoDB connection string has no auth | `mongodb://localhost:27017` | Use `mongodb+srv://user:pass@cluster.mongodb.net/cinema` |
| P5 | No rate limiting | All endpoints unprotected | Add `RATE_LIMIT_RPS=50` — middleware exists, needs enabling |

---

### 🟡 Important (fix within first week)

| # | Issue | Current state | Fix |
|---|---|---|---|
| P6 | User identity is `crypto.randomUUID()` in `sessionStorage` | Anyone can spoof any user ID | Add JWT auth to booking endpoints (auth service exists, just not enforced on booking routes) |
| P7 | No Redis persistence | `appendonly no` | Set `appendonly yes` and `appendfsync everysec` in Redis config, or use a managed Redis with persistence |
| P8 | No MongoDB backups | No backup config | Enable MongoDB Atlas free-tier automated backups, or `mongodump` cron |
| P9 | `GIN_MODE` is `debug` | Verbose logs, stack traces in responses | Set `GIN_MODE=release` |
| P10 | No health-check liveness probe | `/health` exists | Wire it to your platform's health check (Railway/Render/Fly all support this) |

---

### 🟢 Nice to have (before scale)

| # | Issue | Fix |
|---|---|---|
| P11 | Seat-map polls every 2 seconds | Replace with Server-Sent Events |
| P12 | No image CDN for posters | Serve via Cloudflare R2 or Cloudflare Images (both free tier) |
| P13 | No structured logging in production | Set `LOG_FORMAT=json` so log aggregators (Logtail, Betterstack free tier) can parse it |
| P14 | No error tracking | Add Sentry free tier (`SENTRY_DSN` env var) |

---

## Part 2 — Free Deployment (No Credit Card Required)

This stack (Go API + Next.js + Redis + MongoDB) can run **100% free** using the platforms below. None require a credit card to sign up.

---

### Architecture on free tiers

```
  Browser
     │
     ▼
┌─────────────────┐     ┌──────────────────────────┐
│   Vercel (free) │────▶│  Railway / Render (free)  │
│   Next.js SSR   │     │  Go API  :8080            │
└─────────────────┘     └──────────────┬───────────┘
                                        │
                          ┌─────────────┴──────────────┐
                          │                            │
                   ┌──────▼──────┐          ┌──────────▼──────┐
                   │ Redis Cloud │          │ MongoDB Atlas   │
                   │  (free 30MB)│          │  (free 512MB)   │
                   └─────────────┘          └─────────────────┘
```

---

### Step 1 — MongoDB Atlas (free, no credit card)

1. Go to **https://cloud.mongodb.com** → click **Try Free**
2. Sign up with GitHub or email
3. Create a **free M0 cluster** (512 MB, shared)
4. Under **Database Access** → Add a database user:
   - Username: `cinema_user`
   - Password: generate a strong one, copy it
5. Under **Network Access** → Add IP address → Allow access from anywhere (`0.0.0.0/0`)
6. Click **Connect** → **Connect your application** → copy the URI:
   ```
   mongodb+srv://cinema_user:<password>@cluster0.xxxxx.mongodb.net/cinema_booking
   ```

---

### Step 2 — Redis Cloud (free, no credit card)

1. Go to **https://redis.io/try-free** → sign up
2. Create a **free 30 MB database** (choose region closest to your API server)
3. From the database details page, copy:
   - **Public endpoint** (e.g. `redis-12345.c1.us-east-1-1.ec2.redns.redis-cloud.com:12345`)
   - **Password**

Set these as:
```
REDIS_ADDR=redis-12345.c1.us-east-1-1.ec2.redns.redis-cloud.com:12345
REDIS_PASSWORD=your-redis-password
```

---

### Step 3 — Deploy the Go Backend to Railway

Railway gives **$5 free credit/month** (no card required). The Go API uses ~$2–3/month on the Hobby plan.

**Option A — via Railway CLI (recommended)**

```bash
npm install -g @railway/cli
railway login           # opens browser
railway init            # creates a new project
railway up              # deploys from current directory
```

**Option B — via GitHub**

1. Push your repo to GitHub
2. Go to **https://railway.app** → New Project → Deploy from GitHub repo
3. Select this repository → set **Root directory** to `backend`
4. Railway auto-detects Go and runs `go build`

**Set environment variables** in Railway dashboard → Variables:

```
SERVER_PORT=8080
GIN_MODE=release
MONGODB_URI=mongodb+srv://cinema_user:<password>@cluster0.xxxxx.mongodb.net/cinema_booking
MONGODB_DATABASE=cinema_booking
REDIS_ADDR=redis-12345.c1.us-east-1-1.ec2.redns.redis-cloud.com:12345
REDIS_PASSWORD=<your-redis-password>
MAX_SEATS_PER_SESSION=4
HOLD_TTL=10m
JWT_SECRET=<random-64-char-string>
CORS_ALLOWED_ORIGINS=https://your-vercel-app.vercel.app
```

After deploy, Railway gives you a URL like `https://cinema-api-production.up.railway.app`.

---

### Alternative: Deploy the Go Backend to Render (also free, no card)

1. Go to **https://render.com** → New → Web Service
2. Connect GitHub repo → set **Root Directory** to `backend`
3. Build command: `go build -o server ./cmd/api/main.go`
4. Start command: `./server`
5. Set the same environment variables as above
6. Render free tier sleeps after 15 min of inactivity (cold start ~30s). Upgrade to Starter ($7/mo) to avoid this.

---

### Step 4 — Deploy the Next.js Frontend to Vercel (completely free)

Vercel is permanently free for personal projects with no usage limits on the free tier.

1. Go to **https://vercel.com** → sign up with GitHub (no card required)
2. Click **Add New Project** → Import your repository
3. Set **Root Directory** to `frontend`
4. Add environment variables:
   ```
   NEXT_PUBLIC_API_URL=https://cinema-api-production.up.railway.app
   NEXT_PUBLIC_MAX_SEATS=4
   ```
5. Click **Deploy** — Vercel builds and deploys automatically

Your app is live at `https://your-project.vercel.app`.

---

### Step 5 — Update CORS on the backend

Once you have your Vercel URL, update `CORS_ALLOWED_ORIGINS` on Railway/Render:

```
CORS_ALLOWED_ORIGINS=https://your-project.vercel.app
```

Redeploy the backend for the change to take effect.

---

### Step 6 — Wire the Next.js API proxy

The frontend rewrites `/api/v1/*` → backend. In `frontend/next.config.ts`, this is already configured:

```ts
async rewrites() {
  return [{ source: "/api/v1/:path*", destination: `${process.env.NEXT_PUBLIC_API_URL}/api/v1/:path*` }];
}
```

This means all API calls go through Vercel's edge, keeping your backend URL private.

---

### Free tier limits summary

| Service | Free allowance | What this covers |
|---|---|---|
| **Vercel** | Unlimited bandwidth, 100 GB-hours/mo compute | Next.js frontend — handles thousands of page views |
| **Railway** | $5 credit/mo (~500 hours) | Go API — runs all month on the smallest instance |
| **Render** | 750 hours/mo (sleeps when idle) | Go API — free if you accept cold starts |
| **MongoDB Atlas** | 512 MB storage, shared cluster | ~50,000 bookings easily fit |
| **Redis Cloud** | 30 MB | ~300,000 seat-lock keys (more than enough) |

---

### Custom domain (free with Vercel)

1. Vercel Dashboard → your project → Domains → Add Domain
2. Enter your domain (e.g. `cinema.yourdomain.com`)
3. Add the CNAME record your DNS provider (Cloudflare free tier works)
4. Vercel provisions a TLS certificate automatically via Let's Encrypt

---

### One-command deployment checklist

Before making your URL public, verify each item:

```bash
# 1. GIN_MODE is release
curl https://your-api.railway.app/health
# → {"status":"ok"}

# 2. HTTPS works
curl -v https://your-api.railway.app/health
# → TLS handshake success

# 3. CORS is correct (should return your Vercel origin)
curl -H "Origin: https://your-project.vercel.app" https://your-api.railway.app/api/v1/movies

# 4. Admin login works
curl -X POST https://your-api.railway.app/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cinema.local","password":"admin"}'
# Change the password after first login!

# 5. Seeder ran (movies exist)
curl https://your-api.railway.app/api/v1/movies | jq '.[].title'
```

---

### Estimated monthly cost

| Scenario | Cost |
|---|---|
| Development / demo (< 100 users/day) | **$0** — all free tiers |
| Small production (< 1,000 users/day) | **$0–$7** — Railway Hobby $5, or Render Starter $7 |
| Growth (1,000–10,000 users/day) | **~$25** — Railway Pro + MongoDB Atlas M2 + Redis 100MB |
