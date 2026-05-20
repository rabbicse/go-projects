# Movie Ticket Booking System

A production-grade, full-stack cinema ticket booking platform built with **Go (Gin, DDD, Clean Architecture)** + **Next.js 15 / React 19** + **Redis + MongoDB**.

Key capabilities:
- Book **1–4 seats per session** (configurable)
- Atomic multi-seat hold via Redis Lua script (all-or-none — no phantom holds)
- 10-minute hold window with real-time countdown
- Persistent booking history in MongoDB (ready for AI recommender analysis)
- Concurrent-safe under 10 000+ simultaneous users (tested with k6)

---

## Architecture

```
┌────────────┐  HTTP/JSON   ┌─────────────────────────────────────────────────┐
│  Next.js   │◄────────────►│               Go Backend (Gin)                  │
│  React 19  │              │  interfaces/http  →  application  →  domain      │
└────────────┘              │           ↓                                      │
                            │     infrastructure                               │
                            │    ┌──────────────┐  ┌────────────────────────┐ │
                            │    │  Redis        │  │  MongoDB               │ │
                            │    │  (seat locks) │  │  (movies, bookings)    │ │
                            │    └──────────────┘  └────────────────────────┘ │
                            └─────────────────────────────────────────────────┘
```

### Layers (Clean Architecture / DDD)

| Layer | Package | Responsibility |
|---|---|---|
| Domain | `internal/domain/` | Entities, value objects, repository interfaces — zero dependencies |
| Application | `internal/application/` | Use cases (HoldSeats, Confirm, Release, GetSeatMap) |
| Infrastructure | `internal/infrastructure/` | Redis (Lua atomic locks) + MongoDB adapters, seeder |
| Interface | `internal/interfaces/http/` | Gin handlers, DTOs, middleware (CORS, logging) |

### Redis key schema

```
seat:{showtimeID}:{seatID}   →  sessionID  (NX, TTL=hold | no TTL=confirmed)
session:{sessionID}          →  JSON(Session)
```

Multi-seat hold uses a **Lua script** so all seats are locked atomically or none — eliminates partial holds under concurrent load.

### MongoDB collections

| Collection | Purpose |
|---|---|
| `movies` | Movie catalog (title, genre, rating, poster, description) |
| `showtimes` | Showtime schedule per hall (rows, seats, price) |
| `bookings` | Full booking history with status transitions — ready for analytics / AI |

---

## Quick Start (Local Development)

### Prerequisites

- Go 1.24+
- Node.js 22+
- Docker & Docker Compose
- k6 (load tests) — [install](https://k6.io/docs/get-started/installation/)

### 1. Start databases

```bash
make dev-up
# Redis on :6379, MongoDB on :27017
```

### 2. Run backend

```bash
cd backend
cp .env.example .env   # adjust if needed
make run
# API at http://localhost:8080
# Movies seeded automatically on first start
```

### 3. Run frontend

```bash
cd frontend
cp .env.local.example .env.local
npm install
npm run dev
# UI at http://localhost:3000
```

---

## Running Tests

### Unit tests (no Docker required)

```bash
cd backend
make test-unit
```

### Integration tests (requires Docker)

```bash
cd backend
make test-integration
# Uses testcontainers-go — spins up real Redis + MongoDB per test
```

### Load tests

Install k6 first, then:

```bash
# Smoke (1 VU, 10s)
make load-test-smoke

# Normal load (50 VUs, 2 min ramp)
make load-test

# Spike (500 VUs, 30s burst)
make load-test-spike

# Concurrency test — 500 VUs race for the same 4 seats
make load-test-concurrent

# Custom base URL
k6 run --env BASE_URL=http://my-server:8080 load-tests/booking.js
```

Results are saved to `load-tests/results/summary.json`.

#### What the load tests measure

| Metric | Threshold |
|---|---|
| p95 response time | < 500 ms |
| p99 response time | < 1 000 ms |
| Hold error rate (non-409) | < 1% |
| Confirm error rate | < 0.5% |

> Note: 409 Conflict is expected under concurrent load (seat already held) and is not counted as an error.

---

## Environment Variables

### Backend

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8080` | HTTP listen port |
| `GIN_MODE` | `debug` | `debug` or `release` |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | `` | Redis auth password |
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGODB_DATABASE` | `movie_ticket_booking` | Database name |
| `MAX_SEATS_PER_SESSION` | `4` | Max tickets per booking session |
| `HOLD_TTL` | `10m` | How long a hold lasts before auto-expiry |

### Frontend

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | Backend API base URL |
| `NEXT_PUBLIC_MAX_SEATS` | `4` | Max seats shown in UI |

---

## API Reference

### Movies

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/movies` | List all movies with showtimes |
| `GET` | `/api/v1/movies/:id` | Get movie by ID |
| `GET` | `/api/v1/showtimes/:id` | Get showtime by ID |

### Booking

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/showtimes/:showtimeId/seats?user_id=X` | Real-time seat map |
| `POST` | `/api/v1/showtimes/:showtimeId/hold` | Hold 1–4 seats |
| `PUT` | `/api/v1/sessions/:sessionId/confirm` | Confirm a hold |
| `DELETE` | `/api/v1/sessions/:sessionId` | Release a hold |
| `GET` | `/api/v1/users/:userId/bookings` | User booking history |

#### Hold seats — Request body

```json
{
  "user_id": "abc123",
  "seat_ids": ["A1", "A2", "B3"]
}
```

#### Hold seats — Response `201`

```json
{
  "session_id": "uuid",
  "showtime_id": "dune2-hall1-1",
  "movie_id": "dune-part-two",
  "seat_ids": ["A1", "A2", "B3"],
  "status": "held",
  "expires_at": 1716000000
}
```

---

## Production Deployment (Linux Server)

### Prerequisites on the server

```bash
# Docker Engine
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Docker Compose plugin
sudo apt-get install docker-compose-plugin

# k6 (optional, for load tests from server)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
```

### 1. Clone and configure

```bash
git clone https://github.com/rabbicse/movie-ticket-booking /opt/movie-ticket-booking
cd /opt/movie-ticket-booking
```

Edit `docker-compose.yml` if you need to change ports or credentials.

### 2. Deploy with Docker Compose

```bash
docker compose up -d --build
docker compose ps        # verify all services are healthy
docker compose logs -f   # follow logs
```

Services:
- Frontend: `http://your-server:3000`
- Backend API: `http://your-server:8080`
- MongoDB: port 27017 (bind to localhost in production!)
- Redis: port 6379 (bind to localhost in production!)

### 3. Bind databases to localhost only (security)

Edit `docker-compose.yml` — change port bindings for Redis and MongoDB:

```yaml
redis:
  ports:
    - "127.0.0.1:6379:6379"   # localhost only

mongodb:
  ports:
    - "127.0.0.1:27017:27017" # localhost only
```

### 4. Reverse proxy with Nginx (recommended)

```nginx
# /etc/nginx/sites-available/cinebook
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/cinebook /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Add SSL with Let's Encrypt:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 5. Useful commands

```bash
# View backend logs
docker compose logs -f backend

# Restart a service
docker compose restart backend

# Update and redeploy
git pull
docker compose up -d --build backend frontend

# MongoDB shell
docker compose exec mongodb mongosh movie_ticket_booking

# Redis CLI
docker compose exec redis redis-cli
```

### 6. MongoDB backup

```bash
# Dump
docker compose exec mongodb mongodump --db movie_ticket_booking --out /tmp/dump
docker cp mtb-mongo:/tmp/dump ./backups/$(date +%Y%m%d)

# Restore
docker cp ./backups/20240101 mtb-mongo:/tmp/restore
docker compose exec mongodb mongorestore /tmp/restore
```

---

## Phase 2 — Observability (Coming Next)

The `docker-compose.yml` includes commented stubs for:

- **OpenTelemetry Collector** — traces from Gin middleware
- **Prometheus** — metrics (RPS, latency histograms, Redis/Mongo pool stats)
- **Grafana** — dashboards
- **Loki** — log aggregation from structured JSON logs

Uncomment the monitoring block in `docker-compose.yml` and add monitoring config when ready.

---

## Project Structure

```
movie-ticket-booking/
├── backend/
│   ├── cmd/api/main.go              # Entry point, wiring
│   ├── internal/
│   │   ├── config/                  # Env-based config
│   │   ├── domain/
│   │   │   ├── booking/             # Booking aggregate, Seat VO, errors, repo interfaces
│   │   │   ├── movie/               # Movie aggregate, Showtime entity, repo interface
│   │   │   └── shared/              # Money value object
│   │   ├── application/
│   │   │   ├── booking/service.go   # HoldSeats, Confirm, Release, GetSeatMap
│   │   │   └── movie/service.go     # ListMovies, GetShowtime
│   │   ├── infrastructure/
│   │   │   ├── persistence/redis/   # Lua atomic seat locks
│   │   │   ├── persistence/mongodb/ # Movie + Booking repositories
│   │   │   └── seeder/              # Default movies + showtimes
│   │   └── interfaces/http/
│   │       ├── handler/             # Gin handlers
│   │       ├── middleware/          # CORS, logger
│   │       └── dto/                 # Request/response types
│   └── tests/
│       ├── integration/             # testcontainers-go: real Redis + MongoDB
│       └── unit/                    # Domain logic, service mocks
├── frontend/
│   └── src/
│       ├── app/                     # Next.js App Router pages
│       ├── components/              # MovieCard, SeatGrid, Checkout, Timer
│       ├── lib/api.ts               # Type-safe API client
│       └── types/index.ts
├── load-tests/booking.js            # k6: smoke / load / spike / concurrent_hold
├── docker-compose.yml
├── Makefile
└── README.md
```
