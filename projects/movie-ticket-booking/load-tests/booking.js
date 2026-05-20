/**
 * k6 Load Test — Movie Ticket Booking API
 *
 * Scenarios:
 *   1. smoke     — sanity check (1 user, 10s)
 *   2. load      — normal traffic (50 VUs, 2 min)
 *   3. spike     — sudden burst (500 VUs, 30s)
 *   4. concurrent_hold — 500 VUs racing for the SAME seats (tests Redis NX lock)
 *
 * Run:
 *   k6 run load-tests/booking.js
 *   k6 run --env SCENARIO=concurrent_hold load-tests/booking.js
 *   k6 run --env BASE_URL=http://my-server:8080 load-tests/booking.js
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";
import { uuidv4 } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const SCENARIO = __ENV.SCENARIO || "load";

// Custom metrics
const holdErrorRate = new Rate("hold_error_rate");
const confirmErrorRate = new Rate("confirm_error_rate");
const holdDuration = new Trend("hold_duration_ms", true);
const confirmDuration = new Trend("confirm_duration_ms", true);

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
      { duration: "10s", target: 500 },
      { duration: "20s", target: 500 },
      { duration: "10s", target: 0 },
    ],
    tags: { scenario: "spike" },
  },
  concurrent_hold: {
    executor: "constant-vus",
    vus: 500,
    duration: "30s",
    tags: { scenario: "concurrent_hold" },
  },
};

export const options = {
  scenarios: { [SCENARIO]: scenarios[SCENARIO] },
  thresholds: {
    http_req_duration: ["p(95)<500", "p(99)<1000"],
    hold_error_rate: ["rate<0.01"],     // <1% hold errors (excluding 409 conflicts)
    confirm_error_rate: ["rate<0.005"],
  },
};

// Showtime IDs seeded by the backend (see seeder.go)
const SHOWTIMES = [
  "dune2-hall1-1",
  "dune2-hall2-1",
  "oppen-hall2-1",
  "inception-hall1-1",
  "batman-hall2-1",
];

// Seat pool for concurrent_hold scenario (all VUs race for same 4 seats)
const HOT_SEATS = ["A1", "A2", "A3", "A4"];

// Row labels and seat numbers for normal scenarios
const ROWS = "ABCDEFGH".split("");
const ROW_SEATS = 10;

function randomSeat() {
  const row = ROWS[Math.floor(Math.random() * ROWS.length)];
  const num = Math.floor(Math.random() * ROW_SEATS) + 1;
  return `${row}${num}`;
}

function randomSeats(n) {
  const seen = new Set();
  const seats = [];
  while (seats.length < n) {
    const s = randomSeat();
    if (!seen.has(s)) {
      seen.add(s);
      seats.push(s);
    }
  }
  return seats;
}

function randomShowtime() {
  return SHOWTIMES[Math.floor(Math.random() * SHOWTIMES.length)];
}

export default function () {
  const userID = uuidv4();
  const showtimeID =
    SCENARIO === "concurrent_hold" ? "dune2-hall1-1" : randomShowtime();
  const seatIDs =
    SCENARIO === "concurrent_hold"
      ? HOT_SEATS.slice(0, 1 + Math.floor(Math.random() * 4)) // 1-4 seats from hot pool
      : randomSeats(1 + Math.floor(Math.random() * 4));

  // 1. Hold seats
  const holdStart = Date.now();
  const holdRes = http.post(
    `${BASE_URL}/api/v1/showtimes/${showtimeID}/hold`,
    JSON.stringify({ user_id: userID, seat_ids: seatIDs }),
    { headers: { "Content-Type": "application/json" } }
  );
  holdDuration.add(Date.now() - holdStart);

  const holdOk =
    holdRes.status === 201 ||
    holdRes.status === 409; // 409 = seat taken (expected under load)

  check(holdRes, { "hold: 201 or 409": () => holdOk });
  holdErrorRate.add(holdRes.status !== 201 && holdRes.status !== 409);

  if (holdRes.status !== 201) {
    sleep(0.1);
    return;
  }

  const holdBody = JSON.parse(holdRes.body);
  const sessionID = holdBody.session_id;

  sleep(0.5 + Math.random() * 1); // simulate user reviewing

  // 2. Confirm booking (80% confirm, 20% release)
  if (Math.random() < 0.8) {
    const confirmStart = Date.now();
    const confirmRes = http.put(
      `${BASE_URL}/api/v1/sessions/${sessionID}/confirm`,
      JSON.stringify({ user_id: userID }),
      { headers: { "Content-Type": "application/json" } }
    );
    confirmDuration.add(Date.now() - confirmStart);
    check(confirmRes, { "confirm: 200": (r) => r.status === 200 });
    confirmErrorRate.add(confirmRes.status !== 200);
  } else {
    http.del(
      `${BASE_URL}/api/v1/sessions/${sessionID}`,
      JSON.stringify({ user_id: userID }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  sleep(0.2);
}

export function handleSummary(data) {
  const summary = {
    scenario: SCENARIO,
    timestamp: new Date().toISOString(),
    metrics: {
      http_req_duration_p95: data.metrics.http_req_duration?.values?.["p(95)"],
      http_req_duration_p99: data.metrics.http_req_duration?.values?.["p(99)"],
      hold_error_rate: data.metrics.hold_error_rate?.values?.rate,
      confirm_error_rate: data.metrics.confirm_error_rate?.values?.rate,
      total_requests: data.metrics.http_reqs?.values?.count,
      rps: data.metrics.http_reqs?.values?.rate,
    },
  };

  console.log("\n=== Load Test Summary ===");
  console.log(JSON.stringify(summary, null, 2));

  return {
    "load-tests/results/summary.json": JSON.stringify(summary, null, 2),
    stdout: `\n${JSON.stringify(summary, null, 2)}\n`,
  };
}
