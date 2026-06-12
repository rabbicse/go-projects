import { expect, test } from "@playwright/test";

// Shared mock data
const MOCK_MOVIES = [
  {
    id: "movie-e2e-1",
    title: "Playwright Test Film",
    genre: ["Action"],
    rating: 8.5,
    duration_min: 120,
    description: "A movie for E2E testing",
    poster_url: "",
    showtimes: [
      {
        id: "show-e2e-1",
        movie_id: "movie-e2e-1",
        hall: "Hall A",
        start_time: new Date(Date.now() + 2 * 3600 * 1000).toISOString(),
        end_time: new Date(Date.now() + 4 * 3600 * 1000).toISOString(),
        rows: 8,
        seats_per_row: 10,
        price: { cents: 1500, currency: "USD" },
      },
    ],
  },
];

test.describe("Home page — movie list", () => {
  test("renders nav and footer regardless of backend state", async ({ page }) => {
    // Mock API to avoid needing a live backend
    await page.route("/api/v1/movies", (route) =>
      route.fulfill({ contentType: "application/json", body: JSON.stringify(MOCK_MOVIES) })
    );

    await page.goto("/");

    await expect(page.locator("nav")).toBeVisible();
    await expect(page.getByText("Cinema Booking")).toBeVisible();
    await expect(page.locator("footer")).toBeVisible();
  });

  test("nav contains Login and Register links", async ({ page }) => {
    await page.route("/api/v1/movies", (route) =>
      route.fulfill({ contentType: "application/json", body: JSON.stringify([]) })
    );

    await page.goto("/");

    await expect(page.getByRole("link", { name: "Login" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Register" })).toBeVisible();
  });

  test("nav contains My Bookings link pointing to /bookings", async ({ page }) => {
    await page.route("/api/v1/movies", (route) =>
      route.fulfill({ contentType: "application/json", body: JSON.stringify([]) })
    );

    await page.goto("/");

    const bookingsLink = page.getByRole("link", { name: "My Bookings" });
    await expect(bookingsLink).toBeVisible();
    await expect(bookingsLink).toHaveAttribute("href", "/bookings");
  });
});

test.describe("Bookings page", () => {
  test("shows unauthenticated message when no session or JWT token", async ({ page }) => {
    // Clear any stored auth state before test
    await page.addInitScript(() => {
      localStorage.removeItem("cinebook_access_token");
      sessionStorage.removeItem("cinebook_user_id");
    });

    await page.goto("/bookings");

    // Page should show 'My Bookings' heading
    await expect(page.getByRole("heading", { name: "My Bookings" })).toBeVisible();

    // Without a user ID, the page shows a "no session" message
    await expect(
      page.getByText(/no session found|no bookings yet/i)
    ).toBeVisible({ timeout: 5000 });
  });
});
