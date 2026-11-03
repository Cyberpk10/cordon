import { useEffect, useState } from "react";
import CasesView from "./components/CasesView";
import DashboardView from "./components/dashboard/DashboardView";
import AuditReportsView from "./components/audit/AuditReportsView";
import CopilotView from "./components/copilot/CopilotView";
import DetectionsView from "./components/detections/DetectionsView";
import EarlyWarningsView from "./components/early_warnings/EarlyWarningsView";
import AutonomyView from "./components/autonomy/AutonomyView";
import ControlMonitoringView from "./components/monitoring/ControlMonitoringView";
import SimulationsView from "./components/simulations/SimulationsView";
import SettingsView from "./components/settings/SettingsView";
import { useAuth } from "./auth/AuthContext";
import AegisLogo from "./components/AegisLogo";
import LoginScreen from "./auth/LoginScreen";
import OnboardingScreen from "./auth/OnboardingScreen";
import ForgotPasswordScreen from "./auth/ForgotPasswordScreen";
import InviteAcceptScreen from "./auth/InviteAcceptScreen";
import DevLoginScreen from "./auth/DevLoginScreen";
import WelcomeForwardingScreen from "./auth/WelcomeForwardingScreen";
import { INITIAL_TAB_STORAGE_KEY } from "./tabStorage";
import { isTab, type Tab } from "./navigation";
import AppShell from "./components/shell/AppShell";
import AnalyzeView from "./components/analyze/AnalyzeView";
import { useAnalyzer } from "./components/analyze/useAnalyzer";

/** Reads the one-shot initial-tab marker DevLoginScreen sets, so a dev auto-login lands on
 * Early Warnings without a real router. A plain reload/normal visit never has this key set,
 * so this is a no-op for everyone else.
 *
 * Deliberately READ-ONLY (no sessionStorage.removeItem here): this is passed directly as a
 * useState lazy-initializer, and React.StrictMode (see main.tsx) intentionally invokes
 * initializer functions twice in development to surface exactly this class of bug — an
 * initializer with a side effect would have its SECOND call see the key already cleared by
 * the first, silently falling back to "dashboard" every time. Clearing the key is a
 * separate, idempotent effect below (safe to run twice: removing an already-removed key is
 * a no-op), not part of computing the initial value. */
function readInitialTab(): Tab {
  const stored = sessionStorage.getItem(INITIAL_TAB_STORAGE_KEY);
  return isTab(stored) ? stored : "dashboard";
}

type AuthScreen = "login" | "onboarding" | "forgot-password";

function LoadingScreen() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-page">
      <AegisLogo className="h-8 w-8 animate-pulse" />
    </div>
  );
}

export default function App() {
  const { status, justSignedUp, acknowledgeSignupWelcome } = useAuth();
  const [authScreen, setAuthScreen] = useState<AuthScreen>("login");

  if (status === "loading") {
    return <LoadingScreen />;
  }

  if (status === "unauthenticated") {
    if (window.location.pathname === "/accept-invite") {
      return <InviteAcceptScreen />;
    }
    if (window.location.pathname === "/dev-login") {
      return <DevLoginScreen />;
    }
    if (authScreen === "onboarding") {
      return <OnboardingScreen onSwitchToLogin={() => setAuthScreen("login")} />;
    }
    if (authScreen === "forgot-password") {
      return <ForgotPasswordScreen onBackToLogin={() => setAuthScreen("login")} />;
    }
    return (
      <LoginScreen
        onSwitchToSignup={() => setAuthScreen("onboarding")}
        onForgotPassword={() => setAuthScreen("forgot-password")}
      />
    );
  }

  if (justSignedUp) {
    return <WelcomeForwardingScreen onContinue={acknowledgeSignupWelcome} />;
  }

  return <AnalyzerApp />;
}

function AnalyzerApp() {
  const { user, logout } = useAuth();
  const [tab, setTab] = useState<Tab>(readInitialTab);

  useEffect(() => {
    sessionStorage.removeItem(INITIAL_TAB_STORAGE_KEY);
  }, []);
  const analyzer = useAnalyzer();

  return (
    <AppShell
      tab={tab}
      onSelectTab={setTab}
      user={user}
      onLogout={() => logout()}
      contentWidth={tab === "analyze" ? "medium" : tab === "settings" ? "narrow" : "wide"}
    >
      {tab === "cases" && <CasesView />}

      {tab === "dashboard" && <DashboardView />}

      {tab === "detections" && <DetectionsView />}

      {tab === "early-warnings" && <EarlyWarningsView />}

      {tab === "autonomy" && <AutonomyView />}

      {tab === "monitoring" && <ControlMonitoringView />}

      {tab === "simulations" && <SimulationsView />}

      {(tab === "audit" || tab === "reports") && <AuditReportsView tab={tab} onSelect={setTab} />}

      {tab === "copilot" && <CopilotView />}

      {tab === "settings" && <SettingsView />}

      {tab === "analyze" && <AnalyzeView state={analyzer} />}
    </AppShell>
  );
}
