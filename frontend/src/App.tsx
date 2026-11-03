import { useEffect, useState } from "react";
import UploadForm from "./components/UploadForm";
import PasteEmailForm from "./components/PasteEmailForm";
import ActivityLogForm from "./components/ActivityLogForm";
import VerdictBadge from "./components/VerdictBadge";
import AiAuthoredFlag from "./components/AiAuthoredFlag";
import AIAnalystSummary from "./components/AIAnalystSummary";
import IndicatorList from "./components/IndicatorList";
import FrameworkMappingPanel from "./components/FrameworkMappingPanel";
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
import { postAnalyze, postAnalyzeText, postActivityLog, AnalyzeError } from "./api/client";
import type { AnalyzeResponse, ActivityLogAnalyzeResponse } from "./types/analysis";
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
import { Alert, Card, SectionHeading, SegmentedControl } from "./components/ui";

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
  const [analyzeMode, setAnalyzeMode] = useState<"upload" | "paste">("upload");
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const runAnalyze = async (request: Promise<AnalyzeResponse>) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    try {
      const response = await request;
      setResult(response);
    } catch (err) {
      setError(err instanceof AnalyzeError ? err.message : "Something went wrong while analyzing the email.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyzeFile = (file: File) => runAnalyze(postAnalyze(file));
  const handleAnalyzeText = (text: string) => runAnalyze(postAnalyzeText(text));

  // Activity Log mode — a second, independent input alongside Email above (see
  // inputType below). Kept as separate state/handlers rather than threaded into the email
  // ones so the existing email flow is never touched by this addition.
  const [inputType, setInputType] = useState<"email" | "activity-log">("email");
  const [activityLogResult, setActivityLogResult] = useState<ActivityLogAnalyzeResponse | null>(null);
  const [activityLogError, setActivityLogError] = useState<string | null>(null);
  const [isActivityLogLoading, setIsActivityLogLoading] = useState(false);

  const handleAnalyzeActivityLog = async (rawText: string) => {
    setIsActivityLogLoading(true);
    setActivityLogError(null);
    setActivityLogResult(null);
    try {
      const response = await postActivityLog(rawText);
      setActivityLogResult(response);
    } catch (err) {
      setActivityLogError(
        err instanceof AnalyzeError ? err.message : "Something went wrong while analyzing the activity log."
      );
    } finally {
      setIsActivityLogLoading(false);
    }
  };

  return (
    <AppShell
      tab={tab}
      onSelectTab={setTab}
      user={user}
      onLogout={() => logout()}
      contentWidth={tab === "analyze" || tab === "settings" ? "narrow" : "wide"}
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

      {tab === "analyze" && (
        <>
          <SegmentedControl
            aria-label="Input type"
            className="mb-4"
            items={[
              { value: "email", label: "Email" },
              { value: "activity-log", label: "Activity Log" },
            ]}
            value={inputType}
            onChange={setInputType}
          />
        </>
      )}

      {tab === "analyze" && inputType === "email" && (
        <>
          <Card>
            <SegmentedControl
              aria-label="Email input method"
              size="sm"
              className="mb-4"
              items={[
                { value: "upload", label: "Upload email" },
                { value: "paste", label: "Paste email" },
              ]}
              value={analyzeMode}
              onChange={setAnalyzeMode}
            />

            {analyzeMode === "upload" ? (
              <UploadForm onSubmit={handleAnalyzeFile} isLoading={isLoading} />
            ) : (
              <PasteEmailForm onSubmit={handleAnalyzeText} isLoading={isLoading} />
            )}
          </Card>

          {error && (
            <Alert tone="danger" className="mt-6">
              {error}
            </Alert>
          )}

          {result && (
            <div className="mt-8 flex flex-col gap-6">
              <Card>
                <VerdictBadge verdict={result.verdict} score={result.score} />
                <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-fg-secondary sm:grid-cols-2">
                  <div>
                    <dt className="inline font-semibold text-fg">From: </dt>
                    <dd className="inline">
                      {result.summary.from_display} &lt;{result.summary.from_address}&gt;
                    </dd>
                  </div>
                  <div>
                    <dt className="inline font-semibold text-fg">Subject: </dt>
                    <dd className="inline">{result.summary.subject}</dd>
                  </div>
                  <div>
                    <dt className="inline font-semibold text-fg">SPF/DKIM/DMARC: </dt>
                    <dd className="inline">
                      {result.summary.auth_results.spf} / {result.summary.auth_results.dkim} /{" "}
                      {result.summary.auth_results.dmarc}
                    </dd>
                  </div>
                  <div>
                    <dt className="inline font-semibold text-fg">Links / Attachments: </dt>
                    <dd className="inline">
                      {result.summary.link_count} / {result.summary.attachment_count}
                    </dd>
                  </div>
                </dl>
              </Card>

              <AiAuthoredFlag indicators={result.indicators} />

              <AIAnalystSummary narrative={result.analyst_narrative} model={result.analyst_model} />

              <section>
                <SectionHeading>Indicators</SectionHeading>
                <IndicatorList indicators={result.indicators} />
              </section>

              <section>
                <SectionHeading>Framework Mapping</SectionHeading>
                <FrameworkMappingPanel frameworkMappings={result.framework_mappings} />
              </section>
            </div>
          )}
        </>
      )}

      {tab === "analyze" && inputType === "activity-log" && (
        <>
          <Card>
            <ActivityLogForm onSubmit={handleAnalyzeActivityLog} isLoading={isActivityLogLoading} />
          </Card>

          {activityLogError && (
            <Alert tone="danger" className="mt-6">
              {activityLogError}
            </Alert>
          )}

          {activityLogResult && (
            <div className="mt-8 flex flex-col gap-6">
              <Card>
                <VerdictBadge verdict={activityLogResult.verdict} score={activityLogResult.score} />
                <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-fg-secondary sm:grid-cols-2">
                  <div>
                    <dt className="inline font-semibold text-fg">Primary actor: </dt>
                    <dd className="inline">{activityLogResult.summary.primary_actor ?? "—"}</dd>
                  </div>
                  <div>
                    <dt className="inline font-semibold text-fg">Events analyzed: </dt>
                    <dd className="inline">
                      {activityLogResult.summary.event_count} across{" "}
                      {activityLogResult.summary.distinct_actor_count} account(s)
                    </dd>
                  </div>
                  <div>
                    <dt className="inline font-semibold text-fg">Time range: </dt>
                    <dd className="inline">
                      {new Date(activityLogResult.summary.time_range_start).toLocaleString()} –{" "}
                      {new Date(activityLogResult.summary.time_range_end).toLocaleString()}
                    </dd>
                  </div>
                  <div>
                    <dt className="inline font-semibold text-fg">Source IP(s): </dt>
                    <dd className="inline">
                      {activityLogResult.summary.source_ips.join(", ") || "—"}
                    </dd>
                  </div>
                </dl>
                {activityLogResult.summary.other_incidents_detected > 0 && (
                  <p className="mt-3 text-xs text-warning">
                    {activityLogResult.summary.other_incidents_detected} other incident(s) were
                    also detected in this log — showing the highest-risk result.
                  </p>
                )}
              </Card>

              <AIAnalystSummary
                narrative={activityLogResult.analyst_narrative}
                model={activityLogResult.analyst_model}
              />

              <section>
                <SectionHeading>Findings</SectionHeading>
                <IndicatorList
                  indicators={activityLogResult.indicators}
                  emptyMessage="No intrusion findings were detected in this activity log."
                />
              </section>

              <section>
                <SectionHeading>Framework Mapping</SectionHeading>
                <FrameworkMappingPanel frameworkMappings={activityLogResult.framework_mappings} />
              </section>
            </div>
          )}
        </>
      )}
    </AppShell>
  );
}
