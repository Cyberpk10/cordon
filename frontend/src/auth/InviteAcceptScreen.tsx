import { useState } from "react";
import type { FormEvent } from "react";
import AuthLayout from "./AuthLayout";
import { ErrorBanner, FormField, SubmitButton } from "./formFields";
import { AuthError, acceptInvite } from "../api/authClient";
import { useAuth } from "./AuthContext";

const MIN_PASSWORD_LENGTH = 12;

function tokenFromUrl(): string {
  return new URLSearchParams(window.location.search).get("token") ?? "";
}

export default function InviteAcceptScreen() {
  const { applySession } = useAuth();
  const [token] = useState(tokenFromUrl);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      const response = await acceptInvite(token, password);
      applySession(response.user);
    } catch (err) {
      setError(
        err instanceof AuthError ? err.message : "Something went wrong while accepting this invite."
      );
    } finally {
      setIsLoading(false);
    }
  };

  if (!token) {
    return (
      <AuthLayout title="Invite link invalid" subtitle="This invite link is missing its token.">
        <a href="/" className="font-semibold text-accent hover:underline rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface-page">
          Go to sign in
        </a>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout title="Set your password" subtitle="Finish setting up your Cordon account.">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {error && <ErrorBanner message={error} />}

        <FormField
          label="Password"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <p className="-mt-3 text-xs text-fg-secondary">At least {MIN_PASSWORD_LENGTH} characters.</p>

        <SubmitButton isLoading={isLoading}>Join Cordon</SubmitButton>
      </form>
    </AuthLayout>
  );
}
