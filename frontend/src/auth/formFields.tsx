import type { InputHTMLAttributes } from "react";

export function FormField({
  label,
  ...props
}: { label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-semibold text-fg">{label}</span>
      <input
        {...props}
        className="block w-full rounded-lg border border-line-strong px-3 py-2 text-sm text-fg shadow-sm placeholder:text-fg-muted focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/30"
      />
    </label>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-danger/35 bg-danger/10 px-3 py-2 text-sm text-danger">
      {message}
    </div>
  );
}

export function SubmitButton({
  children,
  isLoading,
}: {
  children: React.ReactNode;
  isLoading?: boolean;
}) {
  return (
    <button
      type="submit"
      disabled={isLoading}
      className="flex w-full items-center justify-center rounded-lg bg-accent-fill px-4 py-2.5 text-sm font-semibold text-fg-on-fill transition hover:bg-accent-fill-hover disabled:cursor-not-allowed disabled:opacity-60"
    >
      {isLoading ? "Please wait…" : children}
    </button>
  );
}
