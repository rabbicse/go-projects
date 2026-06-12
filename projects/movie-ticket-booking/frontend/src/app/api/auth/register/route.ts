import { NextRequest, NextResponse } from "next/server";

const BACKEND = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

// Compatibility shim: the register page sends {username, email, password}.
// The backend expects {email, first_name, last_name, password}.
export async function POST(req: NextRequest) {
  try {
    const { username, email, password } = await req.json();
    if (!email || !password) {
      return NextResponse.json({ error: "email and password required" }, { status: 400 });
    }
    const res = await fetch(`${BACKEND}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password,
        first_name: username ?? "",
        last_name: "",
      }),
    });
    const data = await res.json().catch(() => ({}));
    return NextResponse.json(data, { status: res.status });
  } catch (e) {
    console.error("[auth/register]", e);
    return NextResponse.json({ error: "Registration failed" }, { status: 500 });
  }
}
