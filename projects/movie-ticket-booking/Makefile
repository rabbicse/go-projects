.PHONY: up down dev-up dev-down monitoring-up backend-test load-test logs ps

# ── Docker Compose ────────────────────────────────────────────────────────────

# Start the full stack: databases + backend + frontend + monitoring
up:
	docker compose up --build -d

# Stop all services and remove containers
down:
	docker compose down

# Start only databases (Redis + MongoDB) — backend + frontend run locally
dev-up:
	docker compose up redis mongodb -d

# Stop databases
dev-down:
	docker compose down redis mongodb

# Start databases + Prometheus + Grafana (backend runs locally, scraped via host.docker.internal)
monitoring-up:
	docker compose up redis mongodb prometheus grafana -d

# Follow logs
logs:
	docker compose logs -f

ps:
	docker compose ps

# ── Backend ───────────────────────────────────────────────────────────────────

backend-run:
	$(MAKE) -C backend run

backend-test-unit:
	$(MAKE) -C backend test-unit

backend-test-integration:
	$(MAKE) -C backend test-integration

backend-test: backend-test-unit backend-test-integration

# ── Frontend ──────────────────────────────────────────────────────────────────

frontend-install:
	cd frontend && npm install

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build

# ── Load tests ────────────────────────────────────────────────────────────────

# Requires k6: https://k6.io/docs/get-started/installation/
load-test:
	k6 run load-tests/booking.js

load-test-smoke:
	k6 run --env SCENARIO=smoke load-tests/booking.js

load-test-spike:
	k6 run --env SCENARIO=spike load-tests/booking.js

load-test-concurrent:
	k6 run --env SCENARIO=concurrent_hold load-tests/booking.js
