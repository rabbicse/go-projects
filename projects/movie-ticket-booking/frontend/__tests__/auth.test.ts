import { beforeEach, describe, expect, it } from "vitest";
import {
  clearAuth,
  getAccessToken,
  getAuthUserID,
  getAuthEmail,
  isAuthenticated,
  setAccessToken,
} from "@/lib/auth";

// Creates a base64url-encoded JWT with the given payload (signature is fake).
function makeJWT(payload: Record<string, unknown>): string {
  const toB64url = (s: string) =>
    btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const header = toB64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = toB64url(JSON.stringify(payload));
  return `${header}.${body}.fake-signature`;
}

describe("auth library — token storage", () => {
  beforeEach(() => localStorage.clear());

  it("isAuthenticated returns false when storage is empty", () => {
    expect(isAuthenticated()).toBe(false);
  });

  it("setAccessToken / getAccessToken round-trip", () => {
    setAccessToken("tok-abc");
    expect(getAccessToken()).toBe("tok-abc");
  });

  it("isAuthenticated returns true after setAccessToken", () => {
    setAccessToken("tok-abc");
    expect(isAuthenticated()).toBe(true);
  });

  it("clearAuth removes the token and returns false for isAuthenticated", () => {
    setAccessToken("tok-abc");
    clearAuth();
    expect(getAccessToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });
});

describe("auth library — JWT decoding", () => {
  beforeEach(() => localStorage.clear());

  it("getAuthUserID decodes sub from a valid JWT", () => {
    setAccessToken(makeJWT({ sub: "user-42", iss: "test-issuer" }));
    expect(getAuthUserID()).toBe("user-42");
  });

  it("getAuthUserID returns null when no token is stored", () => {
    expect(getAuthUserID()).toBeNull();
  });

  it("getAuthUserID returns null for a malformed token", () => {
    setAccessToken("not-a-real-jwt");
    expect(getAuthUserID()).toBeNull();
  });

  it("getAuthUserID returns null when JWT payload has no sub", () => {
    setAccessToken(makeJWT({ iss: "test", email: "a@b.com" }));
    expect(getAuthUserID()).toBeNull();
  });

  it("getAuthEmail reads email from payload", () => {
    setAccessToken(makeJWT({ sub: "u1", email: "alice@example.com" }));
    expect(getAuthEmail()).toBe("alice@example.com");
  });

  it("getAuthEmail returns null when email claim absent", () => {
    setAccessToken(makeJWT({ sub: "u1" }));
    expect(getAuthEmail()).toBeNull();
  });

  it("handles real base64url encoding (no padding, url-safe chars)", () => {
    // Manually craft a token with URL-safe base64url payload
    const rawPayload = JSON.stringify({ sub: "user-with-urlsafe-chars" });
    const b64url = btoa(rawPayload)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    setAccessToken(`header.${b64url}.sig`);
    expect(getAuthUserID()).toBe("user-with-urlsafe-chars");
  });
});
