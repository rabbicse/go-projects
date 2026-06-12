/**
 * User Manual Screenshot Generator
 *
 * Captures full-page screenshots of every major screen for the user manual.
 * Run with:
 *   cd frontend
 *   PLAYWRIGHT_BASE_URL=http://localhost:3000 npx playwright test \
 *     tests/e2e/screenshots/user-manual-screenshots.spec.ts --project=chromium
 *
 * Prerequisites: backend running on :8080, frontend on :3000, databases up.
 */
import { test, expect, type Page } from "@playwright/test";
import path from "path";
import fs from "fs";

// ── Config ────────────────────────────────────────────────────────────────────

const ADMIN_EMAIL = "admin@cinebook.local";
const ADMIN_PASSWORD = "Admin1234!";
const API_BASE = "http://localhost:8080"; // direct to backend, no proxy timeout

const OUT = path.resolve(__dirname, "output");
if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, { recursive: true });

// ── Helpers ───────────────────────────────────────────────────────────────────

async function shot(page: Page, name: string) {
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(800);
  await page.screenshot({
    path: path.join(OUT, `${name}.png`),
    fullPage: true,
  });
  console.log(`📸 ${name}.png`);
}

/** Login via the /login page, wait for the JWT to land in localStorage, then go to /admin. */
async function adminLogin(page: Page) {
  await page.goto("/login");
  await page.waitForLoadState("domcontentloaded");
  await page.locator('input[type="email"]').fill(ADMIN_EMAIL);
  await page.locator('input[type="password"]').fill(ADMIN_PASSWORD);

  // Capture the login API response and click at the same time so we don't miss it
  const [loginRes] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes("/api/auth/login"),
      { timeout: 15_000 }
    ),
    page.getByRole("button", { name: /sign in/i }).click(),
  ]);

  if (!loginRes.ok()) {
    throw new Error(`Login failed HTTP ${loginRes.status()}: ${await loginRes.text()}`);
  }

  // Wait until the JWT has been written to localStorage by the auth lib
  await page.waitForFunction(
    () => !!window.localStorage.getItem("cinebook_access_token"),
    { timeout: 10_000 }
  );

  // Navigate to admin and wait for the sidebar to prove the guard passed
  await page.goto("/admin");
  await page.waitForSelector("aside", { timeout: 15_000 });
  await page.waitForLoadState("networkidle");
}

/** Fetch movies directly from the backend (avoids Next.js proxy timeout). */
async function getMovies(page: Page): Promise<{ id: string; showtimes?: { id: string }[] }[]> {
  const res = await page.request.get(`${API_BASE}/api/v1/movies`);
  return res.json();
}

// ── Customer screenshots ──────────────────────────────────────────────────────

test.describe("Customer Journey", () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test("01 – Home page (movie list)", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await shot(page, "01-home-movies");
  });

  test("02 – Movie detail page", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    const firstLink = page.locator("a[href*='/movies/']").first();
    if (await firstLink.count() > 0) {
      await firstLink.click();
    } else {
      const movies = await getMovies(page);
      if (movies.length > 0) await page.goto(`/movies/${movies[0].id}`);
    }
    await page.waitForLoadState("networkidle");
    await shot(page, "02-movie-detail");
  });

  test("03 – Seat selection page (empty)", async ({ page }) => {
    const movies = await getMovies(page);
    const showtimes = movies.flatMap((m) => m.showtimes ?? []);
    if (showtimes.length === 0) { test.skip(); return; }
    await page.goto(`/showtimes/${showtimes[0].id}`);
    await page.waitForLoadState("networkidle");
    await shot(page, "03-seat-selection-empty");
  });

  test("04 – Seat map with seats selected", async ({ page }) => {
    const movies = await getMovies(page);
    const showtimes = movies.flatMap((m) => m.showtimes ?? []);
    if (showtimes.length === 0) { test.skip(); return; }
    await page.goto(`/showtimes/${showtimes[0].id}`);
    await page.waitForLoadState("networkidle");

    // Select up to 2 available seats (try multiple selector patterns)
    const availableSeats = page.locator([
      "button[data-status='available']",
      "button.seat-available",
      "[class*='seat'][class*='available']",
      "button[aria-label*='A']",
    ].join(", "));
    const count = await availableSeats.count();
    for (let i = 0; i < Math.min(2, count); i++) {
      await availableSeats.nth(i).click();
      await page.waitForTimeout(400);
    }
    await shot(page, "04-seat-selection-chosen");
  });

  test("05 – Booking history page", async ({ page }) => {
    await page.goto("/bookings");
    await page.waitForLoadState("networkidle");
    await shot(page, "05-booking-history");
  });

  test("06 – Login page", async ({ page }) => {
    await page.goto("/login");
    await page.waitForLoadState("networkidle");
    await shot(page, "06-login-page");
  });
});

// ── Admin screenshots ─────────────────────────────────────────────────────────

test.describe("Admin Panel", () => {
  test.use({ viewport: { width: 1400, height: 900 } });

  test("07 – Admin login (filled)", async ({ page }) => {
    await page.goto("/login");
    await page.waitForLoadState("domcontentloaded");
    await page.locator('input[type="email"]').fill(ADMIN_EMAIL);
    await page.locator('input[type="password"]').fill(ADMIN_PASSWORD);
    await shot(page, "07-admin-login-filled");
  });

  test("08 – Admin dashboard", async ({ page }) => {
    await adminLogin(page);
    await shot(page, "08-admin-dashboard");
  });

  test("09 – Admin movies list", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/movies");
    await page.waitForLoadState("networkidle");
    await shot(page, "09-admin-movies-list");
  });

  test("10 – Admin movies – create modal", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/movies");
    await page.waitForLoadState("networkidle");
    const newBtn = page.getByRole("button", { name: /new movie|add movie|\+ ?movie/i });
    if (await newBtn.count() > 0) {
      await newBtn.click();
      await page.waitForTimeout(500);
    }
    await shot(page, "10-admin-movie-create-modal");
  });

  test("11 – Admin movies – edit modal", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/movies");
    await page.waitForLoadState("networkidle");
    const editBtn = page.getByRole("button", { name: /edit/i }).first();
    if (await editBtn.count() > 0) {
      await editBtn.click();
      await page.waitForTimeout(500);
    }
    await shot(page, "11-admin-movie-edit-modal");
  });

  test("12 – Admin theaters list", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/theaters");
    await page.waitForLoadState("networkidle");
    await shot(page, "12-admin-theaters-list");
  });

  test("13 – Admin theaters – create modal", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/theaters");
    await page.waitForLoadState("networkidle");
    const newBtn = page.getByRole("button", { name: /new theater|\+ ?theater/i });
    if (await newBtn.count() > 0) {
      await newBtn.click();
      await page.waitForTimeout(500);
    }
    await shot(page, "13-admin-theater-create-modal");
  });

  test("14 – Admin theaters – screens expanded", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/theaters");
    await page.waitForLoadState("networkidle");
    // Click the first expand/chevron button to reveal screens sub-table
    const firstRow = page.locator("tbody tr").first();
    if (await firstRow.count() > 0) {
      const btn = firstRow.locator("button").first();
      if (await btn.count() > 0) {
        await btn.click();
        await page.waitForTimeout(700);
      }
    }
    await shot(page, "14-admin-theaters-screens-expanded");
  });

  test("15 – Admin theaters – add screen modal", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/theaters");
    await page.waitForLoadState("networkidle");
    // Expand first theater
    const firstRow = page.locator("tbody tr").first();
    if (await firstRow.count() > 0) {
      const chevron = firstRow.locator("button").first();
      if (await chevron.count() > 0) {
        await chevron.click();
        await page.waitForTimeout(500);
      }
    }
    const addScreenBtn = page.getByRole("button", { name: /add screen|new screen/i });
    if (await addScreenBtn.count() > 0) {
      await addScreenBtn.click();
      await page.waitForTimeout(500);
    }
    await shot(page, "15-admin-screen-create-modal");
  });

  test("16 – Admin shows list", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/shows");
    await page.waitForLoadState("networkidle");
    await shot(page, "16-admin-shows-list");
  });

  test("17 – Admin shows – schedule modal", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/shows");
    await page.waitForLoadState("networkidle");
    const newBtn = page.getByRole("button", { name: /new show|schedule show|\+ ?show/i });
    if (await newBtn.count() > 0) {
      await newBtn.click();
      await page.waitForTimeout(500);
    }
    await shot(page, "17-admin-show-create-modal");
  });

  test("18 – Admin shows – modal with movie selected", async ({ page }) => {
    await adminLogin(page);
    await page.goto("/admin/shows");
    await page.waitForLoadState("networkidle");
    const newBtn = page.getByRole("button", { name: /new show|schedule show|\+ ?show/i });
    if (await newBtn.count() > 0) {
      await newBtn.click();
      await page.waitForTimeout(500);
      const movieSelect = page.locator("select").first();
      if (await movieSelect.count() > 0) {
        await movieSelect.selectOption({ index: 1 });
        await page.waitForTimeout(400);
      }
    }
    await shot(page, "18-admin-show-modal-movie-selected");
  });
});
