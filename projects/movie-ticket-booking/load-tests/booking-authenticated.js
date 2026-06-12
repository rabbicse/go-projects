/**
 * k6 Load Test — Authenticated Booking API
 *
 * Requires AUTH_SERVICE_URL to be set and the auth service to be running.
 * A single token is obtained once per VU (setup phase) and reused across
 * the VU's lifetime, matching how a logged-in browser user behaves.
 *
 * Scenarios (same set as booking.js, but all requests carry a Bearer token):
 *   smoke     — 1 VU, 10 s
 *   load      — ramp to 50 VUs, 2 min
 *   spike     — burst to 200 VUs, 30 s
 *   concurrent_hold — 200 VUs racing for the same seats
 *
 * Usage:
 *   # Register a test user first (only needs to happen once):
 *   curl -s -X POST $AUTH_SERVICE_URL/users/register \
 *        -H 'Content-Type: application/json' \
 *        -d '{"username":"loadtest","email":"lt@test.com","salt":"<b64>","verifier":"<b64>"}'
 *
 *   k6 run --env AUTH_TOKEN=<access_token> load-tests/booking-authenticated.js
 *   k6 run --env SCENARIO=smoke --env AUTH_TOKEN=<token> load-tests/booking-authenticated.js
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";
import { uuidv4 } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const SCENARIO = __ENV.SCENARIO || "load";

// Pre-issued token: generate outside k6 and pass via --env AUTH_TOKEN.
// If not set, the test runs without auth (useful when AUTH_JWKS_ENDPOINT is empty).
const AUTH_TOKEN = __ENV.AUTH_TOKEN || "";

const holdErrorRate = new Rate("hold_error_rate");
const confirmErrorRate = new Rate("confirm_error_rate");
const holdDuration = new Trend("hold_duration_ms", true);
const confirmDuration = new Trend("confirm_duration_ms", true);
const authErrorRate = new Rate("auth_error_rate");

const scenarios = {
  smoke: {
    executor: "constant-vus",
    vus: 1,
    duration: "10s",
    tags: { scenario: "smoke" },
  },
  load: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "30s", target: 50 },
      { duration: "1m", target: 50 },
      { duration: "30s", target: 0 },
    ],
    tags: { scenario: "load" },
  },
  spike: {
    executor: "ramping-vus",
    startVUs: 0,
    stages: [
      { duration: "10s", target: 200 },
      { duration: "20s", target: 200 },
      { duration: "10s", target: 0 },
    ],
    tags: { scenario: "spike" },
  },
  concurrent_hold: {
    executor: "constant-vus",
    vus: 200,
    duration: "30s",
    tags: { scenario: "concurrent_hold" },
  },
};

export const options = {
  scenarios: { [SCENARIO]: scenarios[SCENARIO] },
  thresholds: {
    http_req_duration: ["p(95)<500", "p(99)<1000"],
    hold_error_rate: ["rate<0.01"],
    confirm_error_rate: ["rate<0.005"],
    auth_error_rate: ["rate<0.001"],
  },
};

const SHOWTIMES = [
  "dune2-hall1-1",
  "dune2-hall2-1",
  "oppen-hall2-1",
  "inception-hall1-1",
  "batman-hall2-1",
];

const HOT_SEATS = ["A1", "A2", "A3", "A4", "A5", "B1", "B2"];

function randomShowtime() {
  return SHOWTIMES[Math.floor(Math.random() * SHOWTIMES.length)];
}

function randomSeats(n) {
  const row = ["A", "B", "C", "D", "E"][Math.floor(Math.random() * 5)];
  const seats = [];
  for (let i = 1; i <= n; i++) {
    seats.push(`${row}${i}`);
  }
  return seats;
}

function authHeaders() {
  if (!AUTH_TOKEN) return { "Content-Type": "application/json" };
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${AUTH_TOKEN}`,
  };
}

export default function () {
  const showtimeID =
    SCENARIO === "concurrent_hold" ? "dune2-hall1-1" : randomShowtime();
  const seatIDs =
    SCENARIO === "concurrent_hold"
      ? HOT_SEATS.slice(0, 1 + Math.floor(Math.random() * 4))
      : randomSeats(1 + Math.floor(Math.random() * 4));

  // The booking backend uses the JWT sub as user_id when auth is enabled.
  // When auth is disabled (no AUTH_TOKEN), fall back to a random UUID in the body.
  const holdPayload = AUTH_TOKEN
    ? JSON.stringify({ seat_ids: seatIDs })
    : JSON.stringify({ user_id: uuidv4(), seat_ids: seatIDs });

  // ── 1. Hold seats ──────────────────────────────────────────────────────────
  const holdStart = Date.now();
  const holdRes = http.post(
    `${BASE_URL}/api/v1/showtimes/${showtimeID}/hold`,
    holdPayload,
    { headers: authHeaders() }
  );
  holdDuration.add(Date.now() - holdStart);

  const holdOk = holdRes.status === 201 || holdRes.status === 409;
  check(holdRes, { "hold: 201 or 409": () => holdOk });
  holdErrorRate.add(holdRes.status !== 201 && holdRes.status !== 409);

  // Track auth failures separately from seat-unavailable 409s
  authErrorRate.add(holdRes.status === 401);

  if (holdRes.status !== 201) {
    sleep(0.1);
    return;
  }

  const holdBody = JSON.parse(holdRes.body);
  const sessionID = holdBody.session_id;

  sleep(0.5 + Math.random() * 1);

  // ── 2. Confirm (80%) or Release (20%) ─────────────────────────────────────
  if (Math.random() < 0.8) {
    const confirmPayload = AUTH_TOKEN
      ? JSON.stringify({})
      : JSON.stringify({ user_id: holdBody.user_id });

    const confirmStart = Date.now();
    const confirmRes = http.put(
      `${BASE_URL}/api/v1/sessions/${sessionID}/confirm`,
      confirmPayload,
      { headers: authHeaders() }
    );
    confirmDuration.add(Date.now() - confirmStart);
    check(confirmRes, { "confirm: 200": (r) => r.status === 200 });
    confirmErrorRate.add(confirmRes.status !== 200);
  } else {
    const releasePayload = AUTH_TOKEN
      ? JSON.stringify({})
      : JSON.stringify({ user_id: holdBody.user_id });

    http.del(
      `${BASE_URL}/api/v1/sessions/${sessionID}`,
      releasePayload,
      { headers: authHeaders() }
    );
  }

  sleep(0.2);
}

export function handleSummary(data) {
  const summary = {
    scenario: SCENARIO,
    auth_enabled: !!AUTH_TOKEN,
    timestamp: new Date().toISOString(),
    metrics: {
      http_req_duration_p95: data.metrics.http_req_duration?.values?.["p(95)"],
      http_req_duration_p99: data.metrics.http_req_duration?.values?.["p(99)"],
      hold_error_rate: data.metrics.hold_error_rate?.values?.rate,
      confirm_error_rate: data.metrics.confirm_error_rate?.values?.rate,
      auth_error_rate: data.metrics.auth_error_rate?.values?.rate,
      total_requests: data.metrics.http_reqs?.values?.count,
      rps: data.metrics.http_reqs?.values?.rate,
    },
  };

  console.log("\n=== Authenticated Load Test Summary ===");
  console.log(JSON.stringify(summary, null, 2));

  return {
    "load-tests/results/summary-authenticated.json": JSON.stringify(summary, null, 2),
    stdout: `\n${JSON.stringify(summary, null, 2)}\n`,
  };
}
