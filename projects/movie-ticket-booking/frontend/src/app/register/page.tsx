"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { register as registerUser } from "@/lib/auth";

const registerSchema = z
  .object({
    username: z.string().min(1, "Name is required"),
    email: z.string().min(1, "Email is required").email("Enter a valid email address"),
    password: z.string().min(8, "Password must be at least 8 characters"),
    confirm: z.string().min(1, "Please confirm your password"),
  })
  .refine((d) => d.password === d.confirm, {
    message: "Passwords do not match",
    path: ["confirm"],
  });
type RegisterForm = z.infer<typeof registerSchema>;

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

export default function RegisterPage() {
  const router = useRouter();

  const { register, handleSubmit, formState: { errors } } = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
  });

  const mutation = useMutation({
    mutationFn: ({ username, email, password }: RegisterForm) =>
      registerUser(username, email, password),
    onSuccess: () => router.push("/login"),
  });

  const fields: Array<{
    name: keyof RegisterForm;
    label: string;
    type: string;
    autoComplete?: string;
    autoFocus?: boolean;
  }> = [
    { name: "username", label: "Full name", type: "text", autoComplete: "name", autoFocus: true },
    { name: "email", label: "Email", type: "email", autoComplete: "email" },
    { name: "password", label: "Password", type: "password", autoComplete: "new-password" },
    { name: "confirm", label: "Confirm password", type: "password", autoComplete: "new-password" },
  ];

  return (
    <div className="page-container" style={{ paddingTop: "4rem", maxWidth: "400px" }}>
      <h1 style={{ fontSize: "1.4rem", fontWeight: 700, marginBottom: "0.25rem" }}>Create account</h1>
      <p style={{ color: "var(--text-muted)", fontSize: "0.82rem", marginBottom: "2rem" }}>
        Already have an account?{" "}
        <Link href="/login" style={{ color: "var(--accent)" }}>Sign in</Link>
      </p>

      <form
        onSubmit={handleSubmit((data) => mutation.mutate(data))}
        style={{ display: "flex", flexDirection: "column", gap: "1rem" }}
        noValidate
      >
        {fields.map(({ name, label, type, autoComplete, autoFocus }) => (
          <div key={name}>
            <label style={labelStyle}>{label}</label>
            <input
              type={type}
              autoComplete={autoComplete}
              autoFocus={autoFocus}
              style={inputStyle}
              {...register(name)}
            />
            {errors[name] && <p style={fieldErrStyle}>{errors[name]?.message}</p>}
          </div>
        ))}

        {mutation.isError && (
          <p style={{ color: "var(--danger)", fontSize: "0.82rem", margin: 0 }}>
            {mutation.error instanceof Error ? mutation.error.message : "Registration failed"}
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
          {mutation.isPending ? "Creating account…" : "Create account"}
        </button>
      </form>
    </div>
  );
}
