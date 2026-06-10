# Running the Application

A complete guide for running the Cinema Booking System from scratch on a new machine.

---

## Prerequisites

| Tool | Minimum Version | Install |
|---|---|---|
| Go | 1.24 | https://go.dev/dl/ |
| Node.js | 22 | https://nodejs.org |
| npm | 10 | bundled with Node |
| Docker + Compose | 24 / v2 | https://docs.docker.com/get-docker/ |

Check all at once:
```bash
go version && node --version && npm --version && docker --version
```

---

## Option A — Local Development (recommended for active development)

Infrastructure (Redis + MongoDB) runs in Docker. Backend and frontend run directly on your machine for fast iteration.

### Step 1 — Start Databases

```bash
# From the project root
make dev-up
```

This starts Redis 7 and MongoDB 7 containers on their default ports (6379, 27017). Wait ~10 seconds for MongoDB to be healthy:

```bash
docker compose ps   # both should show "(healthy)"
```

### Step 2 — Start the Backend

```bash
cd backend
cp .env.example .env   # only needed the first time
make run
```

The backend will:
- Connect to Redis and MongoDB
- Create database indexes (idempotent)
- Seed 5 demo movies if no movies exist
- Start listening on `http://localhost:8080`

Expected startup log (JSON, ~1 second):
```json
{"level":"INFO","msg":"config loaded","server_port":8080,"redis_addr":"localhost:6379","mongo_host":"localhost:27017","max_seats":4,"hold_ttl":600000000000}
{"level":"INFO","msg":"seed complete","movies":5}
{"level":"INFO","msg":"server started","addr":"0.0.0.0:8080"}
```

> **Note**: `hold_ttl` currently logs as nanoseconds (`600000000000` = 10 minutes). This is a cosmetic log issue.

Verify:
```bash
curl http://localhost:8080/health
# → {"status":"ok"}
```

### Step 3 — Start the Frontend

```bash
cd frontend
cp .env.local.example .env.local   # only needed the first time
npm install                        # only needed the first time
npm run dev
```

Frontend starts at `http://localhost:3000`.

---

## Option B — Full Stack via Docker Compose

Runs everything (databases + backend + frontend + monitoring) in containers.

```bash
# From the project root
make up
```

> **Important**: The frontend Docker image bakes `NEXT_PUBLIC_API_URL=http://backend:8080` at build time (Next.js rewrites are build-time). If you change the backend URL, you must rebuild the frontend image.

Service ports:

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8080 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3001 (admin/admin) |

---

## Option C — Remote Docker Host

If your databases run on a remote server (e.g., a shared team server at `192.168.0.50`):

```bash
cd backend
cat > .env << 'EOF'
SERVER_PORT=8080
GIN_MODE=debug
REDIS_ADDR=192.168.0.50:6379
MONGODB_URI=mongodb://192.168.0.50:27017
MONGODB_DATABASE=movie_ticket_booking
MAX_SEATS_PER_SESSION=4
HOLD_TTL=10m
ADMIN_USER=admin
ADMIN_PASSWORD=changeme
EOF

make run
```

The frontend always connects to the backend via `NEXT_PUBLIC_API_URL` (default `http://localhost:8080`), so no frontend change is needed when only moving the databases.

---

## Configuration Reference

All backend configuration is via environment variables. See `backend/.env.example` for the full list.

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8080` | HTTP listen port |
| `GIN_MODE` | `debug` | `debug` or `release` |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | _(empty)_ | Redis AUTH password |
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection URI |
| `MONGODB_DATABASE` | `movie_ticket_booking` | Database name |
| `MAX_SEATS_PER_SESSION` | `4` | Maximum seats per booking |
| `HOLD_TTL` | `10m` | How long a seat hold is valid |
| `ADMIN_USER` | `admin` | Admin Basic Auth username |
| `ADMIN_PASSWORD` | `changeme` | Admin Basic Auth password — **change in production** |

Frontend variables (`frontend/.env.local`):

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | Backend base URL |
| `NEXT_PUBLIC_MAX_SEATS` | `4` | Max seats shown in UI (must match backend) |

---

## Database Initialization

There are no migration scripts. On first startup the backend:

1. Calls `EnsureIndexes()` on all collections — creates indexes if missing, no-ops if they already exist.
2. Calls `Seed()` — inserts 5 demo movies with showtimes if the movies collection is empty. Safe to run repeatedly.

No manual steps are required.

---

## Monitoring (Prometheus + Grafana)

```bash
# Start databases + monitoring only (backend running locally)
make monitoring-up

# Start backend
cd backend && make run
```

- Prometheus scrapes `http://localhost:8080/metrics` every 15 seconds.
- Grafana at `http://localhost:3001` (admin/admin) has Prometheus pre-wired as a datasource.
- Create dashboards using the `http_requests_total` and `http_request_duration_seconds` metrics.

---

## Running Tests

```bash
# Unit tests (no Docker required)
cd backend && make test-unit

# Integration tests (requires Docker)
cd backend && make test-integration

# Frontend type check
cd frontend && npm run type-check
```

### Running on a Remote Ubuntu 24.04 Server

```bash
# Setup the server (one-time)
scp scripts/setup-test-server.sh server@<IP>:~/
ssh server@<IP> 'bash ~/setup-test-server.sh'

# Copy source and run
rsync -az --exclude='.git' ./backend/ server@<IP>:~/mtb-backend/
ssh server@<IP> 'cd ~/mtb-backend && go test -v -timeout 300s ./tests/integration/'
```

See `docs/integration-test-setup.md` for full details.

---

## Load Tests (k6)

```bash
# Install k6: https://k6.io/docs/get-started/installation/
make load-test-smoke        # quick sanity check (~30s)
make load-test              # normal load scenario
make load-test-concurrent   # 500 VUs fighting for same seats (Redis NX lock test)
```

Load test results are saved to `load-tests/results/summary.json`.

---

## API Documentation

With the backend running: http://localhost:8080/api/v1/docs

Or via the frontend nav: `API Docs ↗`

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `bind: address already in use` | Another process is on port 8080: `lsof -ti:8080 \| xargs kill -9` |
| `dial tcp ... connection refused` (Redis/MongoDB) | Databases not running — `make dev-up` |
| Frontend shows "Demo data — backend offline" | Backend not running or wrong `NEXT_PUBLIC_API_URL` |
| Admin page returns 401 after login | Backend `ADMIN_PASSWORD` env var doesn't match what you entered at login |
| `hold_ttl` shows `600000000000` in logs | Cosmetic — this is 10 minutes in nanoseconds (known log formatting issue) |
| Showtimes appear expired | The seeded demo data uses fixed past dates. Use Admin → Add Movie to add future showtimes. |
