const ACCESS_TOKEN_KEY = "cinebook_access_token";
const REFRESH_TOKEN_KEY = "cinebook_refresh_token";

// ---------- Storage ----------

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setAccessToken(token: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, token);
}

function setTokenPair(accessToken: string, refreshToken: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

export function clearAuth(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return !!getAccessToken();
}

// ---------- JWT decode (client-side only — NOT a security verification) ----------

function decodeJWTPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function getAuthUserID(): string | null {
  const token = getAccessToken();
  if (!token) return null;
  return (decodeJWTPayload(token)?.sub as string) ?? null;
}

export function getAuthEmail(): string | null {
  const token = getAccessToken();
  if (!token) return null;
  return (decodeJWTPayload(token)?.email as string) ?? null;
}

export function getAuthRoles(): string[] {
  const token = getAccessToken();
  if (!token) return [];
  const roles = decodeJWTPayload(token)?.roles;
  return Array.isArray(roles) ? (roles as string[]) : [];
}

export function hasRole(role: string): boolean {
  return getAuthRoles().includes(role);
}

// ---------- Auth actions ----------

export async function login(email: string, password: string): Promise<void> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as { error?: string; message?: string };
    throw new Error(err.message ?? err.error ?? "Login failed");
  }
  const { access_token, refresh_token } = await res.json() as {
    access_token: string;
    refresh_token: string;
  };
  setTokenPair(access_token, refresh_token);
}

// register keeps the same (username, email, password) signature for backward compat with
// the existing register page. The API route shim maps username → first_name.
export async function register(
  username: string,
  email: string,
  password: string
): Promise<void> {
  const res = await fetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as { error?: string; message?: string };
    throw new Error(err.message ?? err.error ?? "Registration failed");
  }
  // Store tokens so the user is automatically signed in after registration.
  const data = await res.json().catch(() => ({})) as {
    tokens?: { access_token: string; refresh_token: string };
  };
  if (data.tokens?.access_token && data.tokens?.refresh_token) {
    setTokenPair(data.tokens.access_token, data.tokens.refresh_token);
  }
}

// refreshAccessToken exchanges the stored refresh token for a new token pair.
// Returns false and clears auth state if the refresh token is missing or rejected.
export async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;
  try {
    const res = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) {
      clearAuth();
      return false;
    }
    const { access_token, refresh_token } = await res.json() as {
      access_token: string;
      refresh_token: string;
    };
    setTokenPair(access_token, refresh_token);
    return true;
  } catch {
    clearAuth();
    return false;
  }
}

export async function logout(): Promise<void> {
  const refreshToken = getRefreshToken();
  try {
    if (refreshToken) {
      await fetch("/api/v1/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    }
  } catch {
    // best-effort: always clear local state even if the network call fails
  } finally {
    clearAuth();
    if (typeof window !== "undefined") {
      window.location.href = "/";
    }
  }
}
