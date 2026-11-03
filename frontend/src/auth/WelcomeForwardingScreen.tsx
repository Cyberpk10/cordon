import AuthLayout from "./AuthLayout";
import ForwardingAddressCard from "../components/settings/ForwardingAddressCard";
import { useAuth } from "./AuthContext";

interface WelcomeForwardingScreenProps {
  onContinue: () => void;
}

export default function WelcomeForwardingScreen({ onContinue }: WelcomeForwardingScreenProps) {
  const { user } = useAuth();
  if (!user) return null;

  return (
    <AuthLayout
      title="You're all set"
      subtitle="One last thing before your dashboard — here's how your team reports phishing."
    >
      <ForwardingAddressCard forwardingAddress={user.forwarding_address} />
      <button
        type="button"
        onClick={onContinue}
        className="mt-6 flex w-full items-center justify-center rounded-lg bg-accent-fill px-4 py-2.5 text-sm font-semibold text-fg-on-fill transition hover:bg-accent-fill-hover"
      >
        Continue to dashboard
      </button>
      <p className="mt-3 text-center text-xs text-fg-secondary">
        You can always find this address again under Settings.
      </p>
    </AuthLayout>
  );
}
