import { useEffect, useState } from "react";
import AuthLayout from "./AuthLayout";
import { AuthError, devLogin } from "../api/authClient";
import { useAuth } from "./AuthContext";
import { INITIAL_TAB_STORAGE_KEY } from "../tabStorage";

/** Local/dev-only, zero-click sign-in: visiting /dev-login (with the backend's
 * ENABLE_DEV_AUTOLOGIN on and ENVIRONMENT not "production") calls POST /api/auth/dev-login
 * on mount, applies the returned session, and marks the Early Warnings tab as the landing
 * tab (see tabStorage.ts / App.tsx). Never shows a form — nothing to click, nothing to
 * type. If the backend has this disabled (the default, and the ONLY possible state in
 * production), this shows a clear, honest error instead of a broken blank screen. */
export default function DevLoginScreen() {
  const { applySession } = useAuth();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    devLogin()
      .then((response) => {
        if (cancelled) return;
        sessionStorage.setItem(INITIAL_TAB_STORAGE_KEY, "early-warnings");
        applySession(response.user);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(
          err instanceof AuthError && err.status === 404
            ? "Dev auto-login is not enabled on this backend (it's off by default, local-only, " +
                "and structurally disabled in production). Set ENABLE_DEV_AUTOLOGIN=true in a " +
                "local, non-production backend/.env to use this."
            : err instanceof Error
              ? err.message
              : "Something went wrong while signing in."
        );
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (error) {
    return (
      <AuthLayout title="Dev auto-login unavailable" subtitle={error}>
        <a href="/" className="font-medium text-brand-blue hover:underline">
          Go to sign in
        </a>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title="Signing you in…" subtitle="Local dev auto-login, no password needed.">
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200">
        <div className="h-full w-1/3 animate-pulse rounded-full bg-brand-blue" />
      </div>
    </AuthLayout>
  );
}
