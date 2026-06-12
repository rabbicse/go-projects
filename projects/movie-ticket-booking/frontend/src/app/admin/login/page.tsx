import { redirect } from "next/navigation";

// Admin now uses JWT auth (RequireRole "admin").
// Sign in at /login with an admin-role account, then visit /admin.
export default function AdminLoginRedirect() {
  redirect("/login");
}
