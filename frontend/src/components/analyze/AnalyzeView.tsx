import { useEffect, useRef } from "react";
import { ClipboardPaste, FileUp, Mail, ScrollText } from "lucide-react";
import ActivityLogForm from "../ActivityLogForm";
import AiAuthoredFlag from "../AiAuthoredFlag";
import AIAnalystSummary from "../AIAnalystSummary";
import IndicatorList from "../IndicatorList";
import PasteEmailForm from "../PasteEmailForm";
import UploadForm from "../UploadForm";
import { Alert, Card, SectionHeading, SegmentedControl, TabPanel, Tabs } from "../ui";
import AnalysisResultCard, { AnalysisResultSkeleton, summarizeIndicators } from "./AnalysisResultCard";
import type { AnalyzerState } from "./useAnalyzer";

const EMAIL_ANCHOR = "email-indicator-";
const LOG_ANCHOR = "log-finding-";

function withIcon(Icon: typeof Mail, label: string) {
  return (
    <span className="inline-flex items-center gap-2">
      <Icon aria-hidden="true" className="h-4 w-4" />
      {label}
    </span>
  );
}

/** Moves focus to a freshly rendered result so keyboard and screen-reader users land on
 * the verdict instead of staying on the submit button. */
function useFocusOnArrival(trigger: unknown) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (trigger && ref.current) {
      ref.current.focus({ preventScroll: true });
      ref.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [trigger]);
  return ref;
}

export default function AnalyzeView({ state }: { state: AnalyzerState }) {
  const { inputType, setInputType, analyzeMode, setAnalyzeMode, email, activityLog } = state;
  const emailResultRef = useFocusOnArrival(email.result);
  const logResultRef = useFocusOnArrival(activityLog.result);

  return (
    <div className="flex flex-col gap-6">
      <SegmentedControl
        aria-label="Input type"
        className="self-start"
        items={[
          { value: "email", label: withIcon(Mail, "Email") },
          { value: "activity-log", label: withIcon(ScrollText, "Activity Log") },
        ]}
        value={inputType}
        onChange={setInputType}
      />

      {inputType === "email" && (
        <>
          <Card padding="none">
            <Tabs
              aria-label="Email input method"
              idPrefix="email-input"
              items={[
                { value: "upload", label: withIcon(FileUp, "Upload") },
                { value: "paste", label: withIcon(ClipboardPaste, "Paste") },
              ]}
              value={analyzeMode}
              onChange={setAnalyzeMode}
              className="px-3 sm:px-4"
            />
            <TabPanel idPrefix="email-input" value={analyzeMode} className="p-5 sm:p-6">
              {analyzeMode === "upload" ? (
                <UploadForm onSubmit={email.analyzeFile} isLoading={email.isLoading} />
              ) : (
                <PasteEmailForm onSubmit={email.analyzeText} isLoading={email.isLoading} />
              )}
            </TabPanel>
          </Card>

          {email.error && <Alert tone="danger">{email.error}</Alert>}

          {email.isLoading && <AnalysisResultSkeleton />}

          {email.result && (
            <div ref={emailResultRef} tabIndex={-1} className="flex scroll-mt-24 flex-col gap-6 focus:outline-none">
              <AnalysisResultCard
                verdict={email.result.verdict}
                score={email.result.score}
                summary={summarizeIndicators(email.result.verdict, email.result.indicators, {
                  none: "No phishing indicators were detected in this email.",
                  signal: "indicator",
                })}
                details={[
                  { label: "Subject", value: email.result.summary.subject ?? "—", wide: true },
                  {
                    label: "From",
                    value: (
                      <>
                        {email.result.summary.from_display && (
                          <span className="font-semibold">{email.result.summary.from_display} </span>
                        )}
                        <span className="text-fg-secondary">
                          {email.result.summary.from_address ? `<${email.result.summary.from_address}>` : "—"}
                        </span>
                      </>
                    ),
                  },
                  ...(email.result.summary.reply_to_address &&
                  email.result.summary.reply_to_address !== email.result.summary.from_address
                    ? [{ label: "Reply-To", value: email.result.summary.reply_to_address }]
                    : []),
                  {
                    label: "Sent",
                    value: email.result.summary.date ? new Date(email.result.summary.date).toLocaleString() : "—",
                  },
                  {
                    label: "Links / Attachments",
                    value: `${email.result.summary.link_count} / ${email.result.summary.attachment_count}`,
                  },
                ]}
                authResults={email.result.summary.auth_results}
                indicators={email.result.indicators}
                indicatorAnchorPrefix={EMAIL_ANCHOR}
                frameworkMappings={email.result.framework_mappings}
              />

              <AiAuthoredFlag indicators={email.result.indicators} />

              <AIAnalystSummary narrative={email.result.analyst_narrative} model={email.result.analyst_model} />

              {email.result.indicators.length > 0 && (
                <section>
                  <SectionHeading>All indicators ({email.result.indicators.length})</SectionHeading>
                  <IndicatorList indicators={email.result.indicators} idPrefix={EMAIL_ANCHOR} />
                </section>
              )}
            </div>
          )}
        </>
      )}

      {inputType === "activity-log" && (
        <>
          <Card>
            <ActivityLogForm onSubmit={activityLog.analyze} isLoading={activityLog.isLoading} />
          </Card>

          {activityLog.error && <Alert tone="danger">{activityLog.error}</Alert>}

          {activityLog.isLoading && <AnalysisResultSkeleton />}

          {activityLog.result && (
            <div ref={logResultRef} tabIndex={-1} className="flex scroll-mt-24 flex-col gap-6 focus:outline-none">
              <AnalysisResultCard
                verdict={activityLog.result.verdict}
                score={activityLog.result.score}
                summary={summarizeIndicators(activityLog.result.verdict, activityLog.result.indicators, {
                  none: "No intrusion findings were detected in this activity log.",
                  signal: "finding",
                })}
                footnote={
                  activityLog.result.summary.other_incidents_detected > 0 && (
                    <Alert tone="warning">
                      {activityLog.result.summary.other_incidents_detected} other incident(s) were also
                      detected in this log — showing the highest-risk result.
                    </Alert>
                  )
                }
                details={[
                  { label: "Primary actor", value: activityLog.result.summary.primary_actor ?? "—" },
                  {
                    label: "Events analyzed",
                    value: `${activityLog.result.summary.event_count} across ${activityLog.result.summary.distinct_actor_count} account(s)`,
                  },
                  {
                    label: "Time range",
                    value: `${new Date(activityLog.result.summary.time_range_start).toLocaleString()} – ${new Date(activityLog.result.summary.time_range_end).toLocaleString()}`,
                  },
                  { label: "Source IP(s)", value: activityLog.result.summary.source_ips.join(", ") || "—" },
                ]}
                indicators={activityLog.result.indicators}
                indicatorAnchorPrefix={LOG_ANCHOR}
                indicatorsLabel="Top findings"
                frameworkMappings={activityLog.result.framework_mappings}
              />

              <AIAnalystSummary
                narrative={activityLog.result.analyst_narrative}
                model={activityLog.result.analyst_model}
              />

              {activityLog.result.indicators.length > 0 && (
                <section>
                  <SectionHeading>All findings ({activityLog.result.indicators.length})</SectionHeading>
                  <IndicatorList indicators={activityLog.result.indicators} idPrefix={LOG_ANCHOR} />
                </section>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
