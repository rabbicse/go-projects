# Integration Test Server Setup

This guide explains how to run the Go integration tests on a fresh **Ubuntu 24.04** server. The tests use [testcontainers-go](https://golang.testcontainers.org), which spawns real Redis 7 and MongoDB 7 containers during each test run.

## Requirements

| Software | Version | Why |
|---|---|---|
| Ubuntu | 24.04 LTS | Tested baseline |
| Go | 1.24+ | Build toolchain |
| Docker | 24+ (Engine) | testcontainers-go |

---

## Option A — Automated setup (recommended)

A single script installs everything and pre-pulls the Docker images:

```bash
# On the Ubuntu server
curl -sL https://raw.githubusercontent.com/rabbicse/movie-ticket-booking/main/scripts/setup-test-server.sh \
  | bash
```

Or copy the script from the repo and run it locally:

```bash
# From your Mac/laptop
scp scripts/setup-test-server.sh server@<YOUR_SERVER_IP>:~/
ssh server@<YOUR_SERVER_IP> 'bash ~/setup-test-server.sh'
```

> The script is idempotent — safe to re-run on an already configured server.

---

## Option B — Manual step-by-step

### 1. Install Docker (official repo)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl enable --now docker

# Allow your user to run Docker without sudo
sudo usermod -aG docker $USER
# Log out and back in for the group change to take effect, OR:
newgrp docker
```

### 2. Install Go 1.24

```bash
curl -sL https://go.dev/dl/go1.24.3.linux-amd64.tar.gz -o /tmp/go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
rm /tmp/go.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

go version   # → go version go1.24.3 linux/amd64
```

### 3. Pre-pull Docker images (optional but faster first run)

```bash
docker pull redis:7-alpine
docker pull mongo:7
```

---

## Copying and running the tests

### From your development machine

```bash
# Sync backend source to the server (run from project root)
rsync -az --exclude='.git' --exclude='vendor' \
  ./backend/ server@<YOUR_SERVER_IP>:~/mtb-backend/

# SSH in and run
ssh server@<YOUR_SERVER_IP>
cd ~/mtb-backend
go mod download
go test -v -timeout 300s ./tests/integration/
```

### Expected output

```
--- PASS: TestBookingRepository_SaveAndFind (1.5s)
--- PASS: TestBookingRepository_FindBySessionID (1.1s)
...
--- PASS: TestConcurrentHold_ExactlyOneWins (0.7s)
--- PASS: TestSeatLock_GetSeatStatuses (0.6s)
ok  github.com/rabbicse/movie-ticket-booking/tests/integration  17.4s
```

### Run a single test

```bash
go test -v -timeout 60s -run TestRC01_ReleaseAfterConfirmIsBlocked ./tests/integration/
```

### Skip the slow concurrency test

```bash
go test -short -v -timeout 120s ./tests/integration/
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Cannot connect to the Docker daemon` | `sudo systemctl start docker` or add user to `docker` group and re-login |
| `permission denied while trying to connect to the Docker daemon` | `sudo usermod -aG docker $USER` then log out/in |
| `go: command not found` | Add `/usr/local/go/bin` to PATH: `export PATH=$PATH:/usr/local/go/bin` |
| `SEAT_TAKEN` error not recognized | Fixed in v1 — was a Redis 7 error prefix bug (`strings.HasPrefix` → `strings.Contains`) |
| `CleanConfirmedSeats` returns 0 | Fixed in v1 — was a go-redis v9 TTL representation bug (`-time.Second` → `time.Duration(-1)`) |

---

## What each test covers

| Test | Layer | What it verifies |
|---|---|---|
| `TestBookingRepository_*` | MongoDB | CRUD, unique constraint, sort order |
| `TestBookingIndexes_TTLPartialIndexCreated` | MongoDB | TTL partial index + compound index created correctly |
| `TestMovieRepository_FindAll_NoN1` | MongoDB | FindAll uses 2 queries, not N+1 |
| `TestMovieRepository_FindAll_ShowtimesOrderedByStartTime` | MongoDB | Showtimes returned sorted by start_time |
| `TestRC01_ReleaseAfterConfirmIsBlocked` | Redis | Confirm+release race: release blocked after confirm |
| `TestRC02_ConfirmAfterExpiredHoldFails` | Redis | TTL boundary race: expired hold cannot be confirmed |
| `TestRC03_CleanupSkipsActiveScreening` | Redis | Cleanup is no-op while screening is active |
| `TestRC03_CleanupConfirmedSeatsAfterScreening` | Redis | Confirmed seats removed after screening ends |
| `TestRC03_CleanupOnlyConfirmedSeats` | Redis | Cleanup leaves held seats untouched |
| `TestConcurrentHold_ExactlyOneWins` | Redis | 10k goroutines race for one seat — exactly 1 wins |
