"""Executive summary for the Security & Compliance Report — same grounding architecture and
discipline as app.investigation.llm_summary and app.reasoning.llm_analyst, applied to the
report's own aggregated metrics instead of a single email or investigation.

Grounding, structurally enforced rather than merely requested: every metric Cordon computed
is given to the model as a numbered list (EV1, EV2, ...) of plain factual statements, and the
model is forced (via Anthropic tool-use, not free text) to cite which ids its summary
actually relies on. Any id in the response that isn't one Cordon actually supplied fails
strict server-side validation and the WHOLE response is discarded — the model cannot state a
figure that didn't come from the numbered list any more than it can fabricate an
intent_category in llm_analyst or an evidence id in llm_summary.

No untrusted content reaches this module at all: unlike llm_analyst/llm_summary, every
evidence item here is a number Cordon itself already computed (counts, dollar totals,
percentages) — there is no email body, subject line, or other attacker-controlled free text
anywhere in the prompt, so there is structurally no prompt-injection surface here.

Defensive-only: this module never recomputes a metric and never acts on anything; its only
job is to narrate numbers that were already final before it was ever called. On any failure
(no API key, call error, malformed output, a fabricated citation) it returns None, and the
caller (app.api.routes.reports) falls back to generate_deterministic_summary below — an
entirely non-LLM, template-filled summary built from the exact same ReportMetrics, so the
report always has an honest executive summary even with the LLM layer off or unavailable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import anthropic
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.reports.gather import ReportMetrics

_REQUEST_TIMEOUT_SECONDS = 10.0
_MAX_OUTPUT_TOKENS = 500

SYSTEM_PROMPT = (
    "You are writing the executive summary of a board- and auditor-facing security and "
    "compliance report. You will be given a numbered list of metrics Cordon's own "
    "deterministic detection and reporting engines already computed for one account over a "
    "stated period — nothing here is from an external source and none of it is untrusted "
    "free text. Respond ONLY by calling the write_executive_summary tool exactly once. You "
    "may only cite metric ids that appear in the numbered list you were given (e.g. EV1, "
    "EV3) — never invent, rename, or reference an id that was not given to you, and never "
    "state a number that is not one of the given metrics. If the metrics show little or no "
    "activity in the period, say so plainly and do not pad the summary with generic "
    "reassurances or invented achievements. Never provide instructions for conducting "
    "attacks."
)

_REPORT_TOOL_NAME = "write_executive_summary"


def _build_report_tool(max_evidence_id: int) -> dict[str, Any]:
    return {
        "name": _REPORT_TOOL_NAME,
        "description": "Write the report's executive summary, citing the metric ids it relies on.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": (
                        "A concise (3-6 sentence) plain-English executive summary for a board "
                        "member or auditor: what happened in the period, in figures actually "
                        "given below. State plainly when there was little or no activity rather "
                        "than padding with generic reassurance."
                    ),
                },
                "evidence_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": max_evidence_id,
                    "description": (
                        "Every metric id (e.g. 'EV1') the summary actually relies on. Must be a "
                        "subset of the ids you were given — never invent one."
                    ),
                },
            },
            "required": ["summary", "evidence_ids"],
            "additionalProperties": False,
        },
    }


class _ExecutiveSummaryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(min_length=1, max_length=50)


@dataclass(frozen=True)
class ExecutiveSummary:
    text: str
    source: str  # "llm" | "deterministic"
    model: str | None
    evidence_ids: list[str]


def _call_anthropic(
    *,
    model: str,
    api_key: str,
    system: str,
    user_content: str,
    tool: dict[str, Any],
    timeout: float = _REQUEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Isolated so tests can monkeypatch this single call boundary — identical shape to
    app.investigation.llm_summary._call_anthropic."""
    client = anthropic.Anthropic(api_key=api_key)
    response = client.with_options(timeout=timeout).messages.create(
        model=model,
        max_tokens=_MAX_OUTPUT_TOKENS,
        system=system,
        messages=[{"role": "user", "content": user_content}],
        tools=[tool],
        tool_choice={"type": "tool", "name": _REPORT_TOOL_NAME},
    )
    for block in response.content:
        if block.type == "tool_use" and block.name == _REPORT_TOOL_NAME:
            return block.input
    raise ValueError(f"model response did not include a {_REPORT_TOOL_NAME} tool call")


def _build_evidence_list(metrics: ReportMetrics) -> list[tuple[str, str]]:
    """Returns [(evidence_id, evidence_text), ...] — every sentence is a plain factual
    statement of a number Cordon already computed. No free text from any email, case, or
    user-controlled field appears anywhere here."""
    items: list[tuple[str, str]] = []
    n = 0

    def add(text: str) -> None:
        nonlocal n
        n += 1
        items.append((f"EV{n}", text))

    add(
        f"Period: {metrics.period_start:%Y-%m-%d} to {metrics.period_end:%Y-%m-%d}. "
        f"{metrics.emails_analyzed} email(s) were analyzed."
    )
    add(
        f"Verdict breakdown: {metrics.verdict_breakdown.malicious} malicious, "
        f"{metrics.verdict_breakdown.suspicious} suspicious, "
        f"{metrics.verdict_breakdown.safe} safe."
    )
    add(
        f"{metrics.threats_detected} threat(s) were detected (malicious + suspicious), of "
        f"which {metrics.threats_contained} were automatically contained by an executed "
        "autonomous response action."
    )
    add(
        f"Estimated exposure avoided by these detections this period: "
        f"${metrics.exposure_avoided_usd:,.0f} (a deterministic, assumptions-based estimate, "
        "not a guarantee)."
    )
    add(f"{metrics.incidents_detected} intrusion/data-exfiltration incident(s) were detected.")
    add(
        f"{metrics.early_warning_alerts_raised} early-warning alert(s) were raised (an attack "
        "forming, flagged before it became a full incident)."
    )
    hr = metrics.human_risk
    add(
        f"Phishing-simulation / human-risk program: {hr.campaigns_run} campaign(s) run, "
        f"{hr.employees_tested} employee(s) tested, {hr.employees_clicked} clicked the "
        f"simulated lure, {hr.employees_reported} reported it, and "
        f"{hr.employees_flagged_for_training} were flagged for follow-up training."
    )
    for row in metrics.framework_coverage:
        add(
            f"{row.framework_name} control coverage: {row.covered_controls} of "
            f"{row.total_controls} controls ({row.coverage_pct}%) have supporting evidence "
            "from this period's detections."
        )

    return items


def _build_user_content(metrics: ReportMetrics, evidence: list[tuple[str, str]]) -> str:
    evidence_block = "\n".join(f"- {eid}: {text}" for eid, text in evidence)
    activity_note = (
        ""
        if metrics.has_any_activity
        else (
            "\n\nThere was effectively no detection or program activity in this period. Your "
            "summary must say this plainly and must not invent or imply any achievement."
        )
    )
    return (
        "Numbered metrics for this report (cite only these ids; never invent one, never "
        "state a number not listed here):\n"
        f"{evidence_block}"
        f"{activity_note}\n\n"
        "Call write_executive_summary with your summary."
    )


def generate_llm_summary(metrics: ReportMetrics) -> ExecutiveSummary | None:
    """Returns a validated, LLM-authored ExecutiveSummary, or None on any missing API key,
    call failure, malformed output, or a response that states a metric id Cordon never
    actually supplied. Never raises — the caller falls back to
    generate_deterministic_summary on None, exactly like llm_analyst/llm_summary's
    fail-closed contract."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    evidence = _build_evidence_list(metrics)
    model = settings.llm_model
    user_content = _build_user_content(metrics, evidence)
    tool = _build_report_tool(max(len(evidence), 1))

    try:
        raw = _call_anthropic(
            model=model, api_key=api_key, system=SYSTEM_PROMPT, user_content=user_content, tool=tool
        )
        payload = _ExecutiveSummaryPayload.model_validate(raw)
    except Exception:  # noqa: BLE001 - any failure degrades gracefully, never propagates.
        return None

    summary = payload.summary.strip()
    if not summary:
        return None

    valid_ids = {eid for eid, _ in evidence}
    cited_ids = set(payload.evidence_ids)
    if not cited_ids or not cited_ids.issubset(valid_ids):
        # A citation to an id Cordon never supplied is a fabrication, not a shortcut — the
        # whole response is discarded rather than silently filtered down.
        return None

    return ExecutiveSummary(text=summary, source="llm", model=model, evidence_ids=sorted(cited_ids))


def generate_deterministic_summary(metrics: ReportMetrics) -> ExecutiveSummary:
    """A plain, template-filled summary built directly from ReportMetrics with no LLM call
    at all — used whenever the LLM layer is off, unavailable, or failed. Always honest about
    an inactive period rather than padding it."""
    if not metrics.has_any_activity:
        text = (
            f"No email analysis, intrusion detections, early-warning alerts, or phishing-"
            f"simulation activity was recorded for this account between "
            f"{metrics.period_start:%Y-%m-%d} and {metrics.period_end:%Y-%m-%d}. There is no "
            "activity to summarize for this period."
        )
        return ExecutiveSummary(text=text, source="deterministic", model=None, evidence_ids=[])

    hr = metrics.human_risk
    sentences = [
        f"Between {metrics.period_start:%Y-%m-%d} and {metrics.period_end:%Y-%m-%d}, Cordon "
        f"analyzed {metrics.emails_analyzed} email(s), detecting {metrics.threats_detected} "
        f"threat(s) ({metrics.verdict_breakdown.malicious} malicious, "
        f"{metrics.verdict_breakdown.suspicious} suspicious), of which "
        f"{metrics.threats_contained} were automatically contained.",
        f"Estimated exposure avoided by these detections is "
        f"${metrics.exposure_avoided_usd:,.0f}.",
        f"{metrics.incidents_detected} intrusion/data-exfiltration incident(s) and "
        f"{metrics.early_warning_alerts_raised} early-warning alert(s) were detected on "
        "account activity.",
    ]
    if hr.campaigns_run > 0:
        sentences.append(
            f"The phishing-simulation program ran {hr.campaigns_run} campaign(s) against "
            f"{hr.employees_tested} employee(s), with {hr.employees_flagged_for_training} "
            "flagged for follow-up training."
        )
    if metrics.framework_coverage:
        best = max(metrics.framework_coverage, key=lambda r: r.coverage_pct)
        sentences.append(
            f"Control-framework coverage ranged up to {best.coverage_pct}% ({best.framework_name})."
        )

    return ExecutiveSummary(
        text=" ".join(sentences), source="deterministic", model=None, evidence_ids=[]
    )
