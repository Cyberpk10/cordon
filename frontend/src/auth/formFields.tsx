import type { InputHTMLAttributes } from "react";
import { Alert, Button, Field, Input } from "../components/ui";

export function FormField({
  label,
  ...props
}: { label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <Field label={label}>
      <Input {...props} />
    </Field>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return <Alert tone="danger">{message}</Alert>;
}

export function SubmitButton({
  children,
  isLoading,
}: {
  children: React.ReactNode;
  isLoading?: boolean;
}) {
  return (
    <Button variant="primary" size="lg" fullWidth type="submit" loading={isLoading} loadingText="Please wait…">
      {children}
    </Button>
  );
}
