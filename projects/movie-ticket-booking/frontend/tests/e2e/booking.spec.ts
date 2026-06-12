import { expect, test } from "@playwright/test";

test.describe("Login page", () => {
  test("renders sign-in form", async ({ page }) => {
    await page.goto("/login");

    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();
    await expect(page.getByLabel("Password")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  });

  test("contains a link to the register page", async ({ page }) => {
    await page.goto("/login");

    const registerLink = page.getByRole("link", { name: "Register" });
    await expect(registerLink).toBeVisible();
    await expect(registerLink).toHaveAttribute("href", "/register");
  });

  test("shows error on failed login", async ({ page }) => {
    await page.route("/api/auth/login", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: "Invalid credentials" }),
      })
    );

    await page.goto("/login");
    await page.getByLabel("Username").fill("baduser");
    await page.getByLabel("Password").fill("wrongpass");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByText("Invalid credentials")).toBeVisible();
  });

  test("redirects to home on successful login", async ({ page }) => {
    await page.route("/api/auth/login", (route) =>
      route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ access_token: "header.eyJzdWIiOiJ1c2VyLTEifQ.sig", expires_in: 900 }),
      })
    );

    await page.goto("/login");
    await page.getByLabel("Username").fill("alice");
    await page.getByLabel("Password").fill("secret");
    await page.getByRole("button", { name: "Sign in" }).click();

    await page.waitForURL("/");
  });
});

test.describe("Register page", () => {
  test("renders registration form", async ({ page }) => {
    await page.goto("/register");

    await expect(page.getByRole("heading", { name: "Create account" })).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
    await expect(page.getByRole("button", { name: "Create account" })).toBeVisible();
  });

  test("contains a link to the login page", async ({ page }) => {
    await page.goto("/register");

    const loginLink = page.getByRole("link", { name: "Sign in" });
    await expect(loginLink).toBeVisible();
    await expect(loginLink).toHaveAttribute("href", "/login");
  });

  test("shows error when passwords do not match", async ({ page }) => {
    await page.goto("/register");
    await page.getByLabel("Username").fill("alice");
    await page.getByLabel("Email").fill("alice@example.com");

    // Fill Password and Confirm password with different values
    const passwordInputs = page.getByLabel(/password/i);
    await passwordInputs.nth(0).fill("password123");
    await passwordInputs.nth(1).fill("different456");
    await page.getByRole("button", { name: "Create account" }).click();

    await expect(page.getByText("Passwords do not match")).toBeVisible();
  });

  test("redirects to login on successful registration", async ({ page }) => {
    await page.route("/api/auth/register", (route) =>
      route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({ message: "registered" }),
      })
    );

    await page.goto("/register");
    await page.getByLabel("Username").fill("newuser");
    await page.getByLabel("Email").fill("new@example.com");
    const passwordInputs = page.getByLabel(/password/i);
    await passwordInputs.nth(0).fill("mypassword");
    await passwordInputs.nth(1).fill("mypassword");
    await page.getByRole("button", { name: "Create account" }).click();

    await page.waitForURL("**/login");
  });
});
