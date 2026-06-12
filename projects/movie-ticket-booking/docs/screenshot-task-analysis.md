# Screenshot Generation Task – Analysis

**Date:** 2026-06-13  
**Task:** Generate real application screenshots via Playwright and embed them in USER_MANUAL.md.

---

## What Was Done

1. **Playwright spec written** — `frontend/tests/e2e/screenshots/user-manual-screenshots.spec.ts`  
   18 tests across 2 describe blocks (Customer Journey + Admin Panel).

2. **Infrastructure setup**  
   - Redis + MongoDB run in Docker on 192.168.0.50 (exposed on 0.0.0.0).
   - Go backend runs locally pointing at remote DBs (`REDIS_ADDR=192.168.0.50:6379`, `MONGODB_URI=mongodb://192.168.0.50:27017`).
   - Next.js frontend runs locally on `:3000`.

3. **Screenshots captured** — 18/18 passed in 17.5 s.  
   Saved to: `frontend/tests/e2e/screenshots/output/` and copied to `docs/screenshots/`.

4. **USER_MANUAL.md rewritten** with real embedded screenshots.

---

## Issues Encountered and Fixes

| Problem | Root Cause | Fix |
|---------|-----------|-----|
| Admin login `getByLabel(/email/i)` timeout | `<label>` has no `htmlFor` — input is connected only by DOM position | Switched to `input[type="email"]` / `input[type="password"]` |
| Admin redirects to `/` not `/admin` | `onSuccess: () => router.push("/")` in login page | Added explicit `page.goto("/admin")` after login |
| `page.request.get` socket hang up | Backend had crashed (`bind: address already in use` — old process on :8080) | `lsof -ti:8080 | xargs kill -9`; restarted backend |
| Movies API returns `[]` | 5 movies existed but were unpublished (prior seeder run left them unpublished) | Called `PUT /api/v1/admin/movies/:id/publish` via JWT for all 5 |
| Tests 03/04 parallel timeout | Tests ran simultaneously with 4 workers; backend was restarting mid-run | Fixed by restarting backend cleanly before re-running |

---

## File Locations

| File | Purpose |
|------|---------|
| `frontend/tests/e2e/screenshots/user-manual-screenshots.spec.ts` | Playwright test spec |
| `frontend/tests/e2e/screenshots/output/*.png` | Raw Playwright output |
| `docs/screenshots/*.png` | Screenshots used in USER_MANUAL.md |
| `docs/USER_MANUAL.md` | End-user manual with embedded screenshots |
| `logs/backend.log` | Go backend runtime log |

---

## Re-running Screenshots

```bash
# 1. Ensure databases are up on 192.168.0.50
ssh server@192.168.0.50 "docker ps"

# 2. Start backend locally
cd backend
SERVER_PORT=8080 REDIS_ADDR=192.168.0.50:6379 REDIS_PASSWORD= REDIS_DB=0 \
MONGODB_URI=mongodb://192.168.0.50:27017 MONGODB_DATABASE=movie_ticket_booking \
MAX_SEATS_PER_SESSION=4 HOLD_TTL=10m ADMIN_USER=admin ADMIN_PASSWORD=changeme \
JWT_SECRET=dev-secret-for-screenshots-only \
go run ./cmd/api/main.go &

# 3. Start frontend
cd ../frontend
NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev &

# 4. Publish movies (only needed if MongoDB was wiped)
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cinebook.local","password":"Admin1234!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
for ID in dune-part-two oppenheimer the-batman inception interstellar; do
  curl -s -X PUT "http://localhost:8080/api/v1/admin/movies/${ID}/publish" -H "Authorization: Bearer $TOKEN"
done

# 5. Run screenshots
PLAYWRIGHT_BASE_URL=http://localhost:3000 \
npx playwright test tests/e2e/screenshots/user-manual-screenshots.spec.ts \
  --project=chromium --reporter=list --timeout=60000

# 6. Copy to docs
cp tests/e2e/screenshots/output/*.png ../docs/screenshots/
```
