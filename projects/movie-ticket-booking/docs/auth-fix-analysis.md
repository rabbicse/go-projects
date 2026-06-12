# Auth Fix Analysis — Admin Screenshots

**Date:** 2026-06-13  
**Problem:** All 12 admin panel screenshots showed the login page with empty fields instead of actual admin content.

---

## Root Cause

Three bugs combined to produce the failure:

### Bug 1: `waitForURL(/.*/)` resolves immediately

```typescript
// BEFORE (broken)
await page.getByRole("button", { name: /sign in/i }).click();
await page.waitForURL(/.*/, { timeout: 10_000 }); // matches current URL instantly
await page.goto("/admin");                         // called before login fetch completes
```

`/.*/ ` matches any URL including the current one (`/login`), so `waitForURL` resolved before the `POST /api/auth/login` network request even fired. `page.goto("/admin")` ran with no token in `localStorage`.

### Bug 2: No wait for localStorage

The `login()` function in `auth.ts` is `async` — it calls `fetch("/api/auth/login")` and then calls `setTokenPair()`. Without waiting for that promise chain to finish, the token was never written before navigation.

### Bug 3: AdminLayout guard reacts to empty localStorage

```typescript
// admin/layout.tsx
useEffect(() => {
  if (!isAuthenticated()) {
    router.replace("/login");   // localStorage empty → immediate redirect
  }
}, [router]);
```

Since the token wasn't there, the guard redirected back to `/login`, which then rendered with fresh empty fields.

---

## Fix Applied

```typescript
// AFTER (fixed) — adminLogin helper in user-manual-screenshots.spec.ts
async function adminLogin(page: Page) {
  await page.goto("/login");
  await page.waitForLoadState("domcontentloaded");
  await page.locator('input[type="email"]').fill(ADMIN_EMAIL);
  await page.locator('input[type="password"]').fill(ADMIN_PASSWORD);

  // 1. Capture the network response and click simultaneously
  const [loginRes] = await Promise.all([
    page.waitForResponse(r => r.url().includes("/api/auth/login"), { timeout: 15_000 }),
    page.getByRole("button", { name: /sign in/i }).click(),
  ]);

  if (!loginRes.ok()) throw new Error(`Login failed HTTP ${loginRes.status()}`);

  // 2. Wait for JWT to land in localStorage
  await page.waitForFunction(
    () => !!window.localStorage.getItem("cinebook_access_token"),
    { timeout: 10_000 }
  );

  // 3. Navigate; wait for <aside> to confirm the guard passed
  await page.goto("/admin");
  await page.waitForSelector("aside", { timeout: 15_000 });
  await page.waitForLoadState("networkidle");
}
```

**Why `Promise.all`:** Playwright's `waitForResponse` must be registered *before* the click that triggers the request. Using `Promise.all` registers the listener and clicks simultaneously, guaranteeing the response is captured.

**Why `waitForFunction` on localStorage:** The `auth.ts` `login()` function writes the token to `localStorage` *after* the fetch resolves. Polling `localStorage` directly is the most reliable signal that the auth state is ready before we navigate away.

**Why `waitForSelector("aside")`:** The AdminLayout starts in `"loading"` state and renders `null`. The `<aside>` sidebar only renders when the guard sets state to `"ok"` (i.e., `isAuthenticated() && hasRole("admin")` both pass). Waiting for it confirms the page is fully authenticated before the screenshot.

---

## Result

| Before | After |
|--------|-------|
| All 12 admin screenshots showed the empty login form | All 12 admin screenshots show fully-authenticated admin panel |
| Backend JWT verification: ✅ working | — |
| Frontend `hasRole("admin")` check: ✅ working (JWT carries `roles: ["admin"]`) | — |
| Playwright timing: ❌ race condition | ✅ fixed |

18/18 tests pass in 21.3 seconds.
