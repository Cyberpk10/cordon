import { useState } from "react";
import { AnalyzeError, postActivityLog, postAnalyze, postAnalyzeText } from "../../api/client";
import type { ActivityLogAnalyzeResponse, AnalyzeResponse } from "../../types/analysis";

/** All Analyze-screen state. Owned by the app shell (not AnalyzeView) so a result
 * survives switching to another tab and back, exactly as before this was extracted. */
export function useAnalyzer() {
  const [inputType, setInputType] = useState<"email" | "activity-log">("email");
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

  const analyzeFile = (file: File) => runAnalyze(postAnalyze(file));
  const analyzeText = (text: string) => runAnalyze(postAnalyzeText(text));

  // Activity Log mode — a second, independent input alongside Email. Kept as separate
  // state/handlers rather than threaded into the email ones so the email flow is never
  // touched by this addition.
  const [activityLogResult, setActivityLogResult] = useState<ActivityLogAnalyzeResponse | null>(null);
  const [activityLogError, setActivityLogError] = useState<string | null>(null);
  const [isActivityLogLoading, setIsActivityLogLoading] = useState(false);

  const analyzeActivityLog = async (rawText: string) => {
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

  return {
    inputType,
    setInputType,
    analyzeMode,
    setAnalyzeMode,
    email: { result, error, isLoading, analyzeFile, analyzeText },
    activityLog: {
      result: activityLogResult,
      error: activityLogError,
      isLoading: isActivityLogLoading,
      analyze: analyzeActivityLog,
    },
  };
}

export type AnalyzerState = ReturnType<typeof useAnalyzer>;
