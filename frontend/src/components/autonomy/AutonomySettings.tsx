import { useEffect, useState } from "react";
import { getAutonomyPolicy, haltAutonomy, putAutonomyPolicy } from "../../api/client";
import type { AutonomyLevel, AutonomyPolicy, AutonomyPolicyRule } from "../../types/analysis";

const LEVELS: { level: AutonomyLevel; label: string; description: string }[] = [
  { level: "L0", label: "L0 — Recommend only", description: "Cordon never acts automatically. Every finding stays a human-approved recommendation." },
  { level: "L1", label: "L1 — Low-impact auto-execute", description: "Auto-executes reversible, non-containment actions (quarantine email, flag account) above their confidence threshold." },
  { level: "L2", label: "L2 — Containment auto-execute", description: "Adds containment actions (disable session, block sender domain) above a (typically higher) confidence threshold." },
  { level: "L3", label: "L3 — Full auto (opt-in per rule)", description: "A rule marked \"full auto\" executes without a confidence check. Exclusions and reversibility still always apply." },
];

const ACTION_TYPES = [
  { type: "QUARANTINE_EMAIL", title: "Quarantine email", containment: false },
  { type: "FLAG_ACCOUNT_FOR_REVIEW", title: "Flag account for review", containment: false },
  { type: "DISABLE_SESSION", title: "Disable session", containment: true },
  { type: "BLOCK_SENDER_DOMAIN", title: "Block sender domain", containment: true },
];

export default function AutonomySettings() {
  const [policy, setPolicy] = useState<AutonomyPolicy | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isHalting, setIsHalting] = useState(false);
  const [exclusionsText, setExclusionsText] = useState("");

  const load = () => {
    getAutonomyPolicy()
      .then((data) => {
        setPolicy(data);
        setExclusionsText(data.exclusions.join("\n"));
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load policy."));
  };

  useEffect(load, []);

  const updateRule = (actionType: string, patch: Partial<AutonomyPolicyRule>) => {
    if (!policy) return;
    const existing = policy.rules.find((r) => r.action_type === actionType);
    const rules = existing
      ? policy.rules.map((r) => (r.action_type === actionType ? { ...r, ...patch } : r))
      : [...policy.rules, { action_type: actionType, min_confidence: 0.7, scopes: null, full_auto: false, ...patch }];
    setPolicy({ ...policy, rules });
  };

  const removeRule = (actionType: string) => {
    if (!policy) return;
    setPolicy({ ...policy, rules: policy.rules.filter((r) => r.action_type !== actionType) });
  };

  const handleSave = async () => {
    if (!policy) return;
    setIsSaving(true);
    setError(null);
    try {
      const saved = await putAutonomyPolicy({
        level: policy.level,
        rules: policy.rules,
        exclusions: exclusionsText.split("\n").map((s) => s.trim()).filter(Boolean),
        blast_radius_limit: policy.blast_radius_limit,
        blast_radius_window_minutes: policy.blast_radius_window_minutes,
      });
      setPolicy(saved);
      setExclusionsText(saved.exclusions.join("\n"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save policy.");
    } finally {
      setIsSaving(false);
    }
  };

  const handleHalt = async () => {
    if (!window.confirm("Halt autonomy? This drops to L0 and stops all pending autonomous actions immediately.")) {
      return;
    }
    setIsHalting(true);
    setError(null);
    try {
      await haltAutonomy();
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to halt.");
    } finally {
      setIsHalting(false);
    }
  };

  if (!policy) {
    return (
      <div className="rounded-xl border border-line bg-surface-card p-6 text-sm text-fg-secondary shadow-sm">
        {error ?? "Loading policy…"}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="rounded-xl border-2 border-danger/35 bg-danger/10 p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-danger">Kill switch</h2>
            <p className="text-sm text-danger">
              Immediately drops autonomy to L0 and halts every pending autonomous action.
              {policy.halted_at && (
                <span className="block text-xs">
                  Last halted: {new Date(policy.halted_at).toLocaleString()}
                </span>
              )}
            </p>
          </div>
          <button
            onClick={handleHalt}
            disabled={isHalting}
            className="whitespace-nowrap rounded-lg bg-danger-fill px-5 py-2 text-sm font-semibold text-fg-on-fill shadow-sm transition hover:bg-danger-fill-hover disabled:cursor-not-allowed disabled:bg-line-strong"
          >
            {isHalting ? "Halting…" : "Halt autonomy"}
          </button>
        </div>
      </section>

      {error && (
        <div className="rounded-lg border border-danger/35 bg-danger/10 p-4 text-sm text-danger">{error}</div>
      )}

      <section className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-fg">Autonomy level</h2>
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
          {LEVELS.map((l) => (
            <label
              key={l.level}
              className={`cursor-pointer rounded-lg border p-4 transition ${
                policy.level === l.level
                  ? "border-accent bg-accent/10"
                  : "border-line hover:border-line-strong"
              }`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name="autonomy-level"
                  checked={policy.level === l.level}
                  onChange={() => setPolicy({ ...policy, level: l.level })}
                />
                <span className="font-semibold text-fg">{l.label}</span>
              </div>
              <p className="mt-1 text-xs text-fg-secondary">{l.description}</p>
            </label>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-fg">Action rules</h2>
        <p className="mt-1 text-sm text-fg-secondary">
          Which action types may auto-run, and above what confidence. Containment actions
          (marked) need L2+; non-containment actions need L1+ regardless of these settings.
        </p>
        <div className="mt-4 flex flex-col gap-3">
          {ACTION_TYPES.map(({ type, title, containment }) => {
            const rule = policy.rules.find((r) => r.action_type === type);
            return (
              <div key={type} className="rounded-lg border border-line p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <label className="flex items-center gap-2 font-semibold text-fg">
                    <input
                      type="checkbox"
                      checked={!!rule}
                      onChange={(e) =>
                        e.target.checked ? updateRule(type, {}) : removeRule(type)
                      }
                    />
                    {title}
                    {containment && (
                      <span className="rounded-full border border-warning/35 bg-warning/10 px-2 py-0.5 text-xs text-warning">
                        containment
                      </span>
                    )}
                  </label>
                  {rule && (
                    <div className="flex items-center gap-4">
                      <label className="flex items-center gap-2 text-sm text-fg-secondary">
                        Min confidence
                        <input
                          type="number"
                          min={0}
                          max={1}
                          step={0.05}
                          value={rule.min_confidence}
                          onChange={(e) =>
                            updateRule(type, { min_confidence: Number(e.target.value) })
                          }
                          className="w-20 rounded border border-line-strong px-2 py-1 text-sm"
                        />
                      </label>
                      <label className="flex items-center gap-2 text-sm text-fg-secondary">
                        <input
                          type="checkbox"
                          checked={rule.full_auto}
                          onChange={(e) => updateRule(type, { full_auto: e.target.checked })}
                        />
                        Full auto (L3 only)
                      </label>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-fg">Exclusion list</h2>
        <p className="mt-1 text-sm text-fg-secondary">
          Protected identities/assets (one per line) — never auto-actioned, at any level, above
          any confidence.
        </p>
        <textarea
          value={exclusionsText}
          onChange={(e) => setExclusionsText(e.target.value)}
          rows={4}
          placeholder="ceo@corp.com&#10;partner.example.com"
          className="mt-3 w-full rounded-lg border border-line-strong px-3 py-2 text-sm font-mono"
        />
      </section>

      <section className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-fg">Blast-radius rate limit</h2>
        <p className="mt-1 text-sm text-fg-secondary">
          After this many autonomous actions within the window, further actions require human
          confirmation until the window rolls off.
        </p>
        <div className="mt-3 flex gap-4">
          <label className="flex flex-col gap-1 text-sm text-fg-secondary">
            Limit
            <input
              type="number"
              min={1}
              value={policy.blast_radius_limit}
              onChange={(e) => setPolicy({ ...policy, blast_radius_limit: Number(e.target.value) })}
              className="w-24 rounded border border-line-strong px-2 py-1"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm text-fg-secondary">
            Window (minutes)
            <input
              type="number"
              min={1}
              value={policy.blast_radius_window_minutes}
              onChange={(e) =>
                setPolicy({ ...policy, blast_radius_window_minutes: Number(e.target.value) })
              }
              className="w-24 rounded border border-line-strong px-2 py-1"
            />
          </label>
        </div>
      </section>

      <button
        onClick={handleSave}
        disabled={isSaving}
        className="self-start rounded-lg bg-accent-fill px-6 py-2 text-sm font-semibold text-fg-on-fill shadow-sm transition hover:bg-accent-fill-hover disabled:cursor-not-allowed disabled:bg-line-strong"
      >
        {isSaving ? "Saving…" : "Save policy"}
      </button>
    </div>
  );
}
