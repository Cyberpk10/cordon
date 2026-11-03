import AuthLayout from "./AuthLayout";
import ForwardingAddressCard from "../components/settings/ForwardingAddressCard";
import { useAuth } from "./AuthContext";
import { Button } from "../components/ui";

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
      <Button variant="primary" fullWidth className="mt-6" onClick={onContinue}>
        Continue to dashboard
      </Button>
      <p className="mt-3 text-center text-xs text-fg-secondary">
        You can always find this address again under Settings.
      </p>
    </AuthLayout>
  );
}
