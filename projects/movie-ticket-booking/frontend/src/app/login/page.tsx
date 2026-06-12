"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { login, isAuthenticated, logout, getAuthUserID, getAuthEmail } from "@/lib/auth";

const loginSchema = z.object({
  email: z.string().min(1, "Email is required").email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});
type LoginForm = z.infer<typeof loginSchema>;

const inputStyle: React.CSSProperties = {
  width: "100%", padding: "0.6rem 0.8rem", borderRadius: "7px",
  border: "1px solid var(--border)", background: "var(--surface)",
  color: "var(--text)", fontSize: "0.9rem", boxSizing: "border-box",
};
const labelStyle: React.CSSProperties = {
  display: "block", fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.35rem",
};
const fieldErrStyle: React.CSSProperties = {
  color: "var(--danger)", fontSize: "0.76rem", marginTop: "0.25rem",
};

export default function LoginPage() {
  const router = useRouter();
  const [loggedIn, setLoggedIn] = useState(false);
  const [currentUserID, setCurrentUserID] = useState<string | null>(null);
  const [currentEmail, setCurrentEmail] = useState<string | null>(null);

  useEffect(() => {
    const authed = isAuthenticated();
    setLoggedIn(authed);
    if (authed) {
      setCurrentUserID(getAuthUserID());
      setCurrentEmail(getAuthEmail());
    }
  }, []);

  const { register, handleSubmit, formState: { errors } } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
  });

  const mutation = useMutation({
    mutationFn: ({ email, password }: LoginForm) => login(email, password),
    onSuccess: () => router.push("/"),
  });

  if (loggedIn) {
    return (
      <div className="page-container" style={{ paddingTop: "4rem", maxWidth: "400px" }}>
        <h1 style={{ fontSize: "1.4rem", fontWeight: 700, marginBottom: "1rem" }}>Already signed in</h1>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "0.5rem" }}>
          {currentEmail ?? currentUserID}
        </p>
        <p style={{ color: "var(--text-muted)", fontSize: "0.75rem", marginBottom: "1.5rem" }}>
          ID: <code style={{ fontFamily: "monospace" }}>{currentUserID}</code>
        </p>
        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button
            onClick={() => void logout()}
            style={{
              padding: "0.6rem 1.2rem", borderRadius: "7px", border: "1px solid var(--border)",
              background: "var(--surface)", color: "var(--text)", cursor: "pointer", fontSize: "0.85rem",
            }}
          >
            Sign out
          </button>
          <Link href="/" style={{
            padding: "0.6rem 1.2rem", borderRadius: "7px", background: "var(--accent)",
            color: "#fff", fontSize: "0.85rem", textDecoration: "none",
          }}>
            Browse movies
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container" style={{ paddingTop: "4rem", maxWidth: "400px" }}>
      <h1 style={{ fontSize: "1.4rem", fontWeight: 700, marginBottom: "0.25rem" }}>Sign in</h1>
      <p style={{ color: "var(--text-muted)", fontSize: "0.82rem", marginBottom: "2rem" }}>
        Don&apos;t have an account?{" "}
        <Link href="/register" style={{ color: "var(--accent)" }}>Register</Link>
      </p>

      <form
        onSubmit={handleSubmit((data) => mutation.mutate(data))}
        style={{ display: "flex", flexDirection: "column", gap: "1rem" }}
        noValidate
      >
        <div>
          <label style={labelStyle}>Email</label>
          <input type="email" autoFocus autoComplete="email" style={inputStyle} {...register("email")} />
          {errors.email && <p style={fieldErrStyle}>{errors.email.message}</p>}
        </div>

        <div>
          <label style={labelStyle}>Password</label>
          <input type="password" autoComplete="current-password" style={inputStyle} {...register("password")} />
          {errors.password && <p style={fieldErrStyle}>{errors.password.message}</p>}
        </div>

        {mutation.isError && (
          <p style={{ color: "var(--danger)", fontSize: "0.82rem", margin: 0 }}>
            {mutation.error instanceof Error ? mutation.error.message : "Login failed"}
          </p>
        )}

        <button
          type="submit"
          disabled={mutation.isPending}
          style={{
            padding: "0.65rem", borderRadius: "7px", border: "none",
            background: mutation.isPending ? "var(--border)" : "var(--accent)",
            color: "#fff", fontSize: "0.9rem", fontWeight: 600,
            cursor: mutation.isPending ? "not-allowed" : "pointer", transition: "background 0.15s",
          }}
        >
          {mutation.isPending ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
