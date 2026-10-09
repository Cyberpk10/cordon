"""Pure aggregation for the agentic investigation layer (M10 Stage 1) — no DB/SQLAlchemy
here, same separation as app.baselines.aggregation / app.sender_history.aggregation.
app.investigation.gather is the thin DB-touching glue that queries rows and calls into this
module; app.investigation.build is the top-level orchestrator.

Every function here only ever reorganizes evidence Cordon's own engines already computed and
persisted (case indicators, incident findings, sender history) — nothing here re-runs
detection logic or queries an external source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

# Threat-intel-backed indicator/finding ids (app.indicators.known_bad_sender,
# app.indicators.known_bad_urls, app.detections.known_bad_ip) — the fixed, small set that
# means "a Cordon detection engine already matched this artifact against the threat-intel
# snapshot," as opposed to a heuristic indicator like LOOKALIKE_DOMAIN that never touches
# threat-intel data at all. Kept here (not re-derived from app.threat_intel.loader) so the
# investigation can never disagree with what the detection engines themselves already found.
THREAT_INTEL_EMAIL_INDICATOR_IDS = frozenset(
    {"SENDER_DOMAIN_KNOWN_BAD", "SENDER_IP_KNOWN_MALICIOUS", "LINK_KNOWN_MALICIOUS"}
)
THREAT_INTEL_EVENT_FINDING_IDS = frozenset({"EVENT_IP_KNOWN_MALICIOUS"})


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: datetime
    type: str
    description: str
    source: str  # "case" | "incident" | "event"
    source_id: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "type": self.type,
            "description": self.description,
            "source": self.source,
            "source_id": self.source_id,
        }


@dataclass(frozen=True)
class RelatedCaseRef:
    id: UUID
    created_at: datetime
    verdict: str
    score: int
    subject: str | None
    to_addresses: list[str]

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "created_at": self.created_at.isoformat(),
            "verdict": self.verdict,
            "score": self.score,
            "subject": self.subject,
            "to_addresses": self.to_addresses,
        }


@dataclass(frozen=True)
class RelatedIncidentRef:
    id: UUID
    created_at: datetime
    title: str
    verdict: str
    score: int

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "created_at": self.created_at.isoformat(),
            "title": self.title,
            "verdict": self.verdict,
            "score": self.score,
        }


def build_timeline(entries: list[TimelineEntry], max_entries: int) -> list[TimelineEntry]:
    """Oldest-first, capped to the most recent `max_entries` — same "keep the tail"
    bounded-state discipline as app.threat_level.aggregation._trim_recent_signals."""
    ordered = sorted(entries, key=lambda e: e.timestamp)
    if len(ordered) <= max_entries:
        return ordered
    return ordered[-max_entries:]


def extract_threat_intel_hits(
    case_indicators: list[dict], related_incident_findings: list[dict]
) -> list[dict]:
    """Pulls only the already-computed indicators/findings that represent a real
    threat-intel-feed match — never recomputes a lookup. `case_indicators` is a Case's own
    `indicators` JSON column; `related_incident_findings` is the flattened `findings` of
    every related incident (see app.investigation.gather)."""
    hits: list[dict] = []
    for indicator in case_indicators:
        if indicator.get("id") in THREAT_INTEL_EMAIL_INDICATOR_IDS:
            hits.append(
                {
                    "source": "email_indicator",
                    "id": indicator.get("id"),
                    "title": indicator.get("title"),
                    "evidence": indicator.get("evidence", []),
                }
            )
    for finding in related_incident_findings:
        if finding.get("id") in THREAT_INTEL_EVENT_FINDING_IDS:
            hits.append(
                {
                    "source": "activity_finding",
                    "id": finding.get("id"),
                    "title": finding.get("title"),
                    "actor": finding.get("actor"),
                }
            )
    return hits


def build_scope(
    *,
    targeted_recipients: list[str],
    related_cases: list[RelatedCaseRef],
    subject: str | None,
    related_incident_count: int,
    threat_level_band: str | None,
    ueba_finding_count: int,
) -> dict:
    """Blast-radius / scope assembly — pure dict construction from already-gathered pieces.
    `possible_account_compromise` is a transparent, explainable OR over three concrete,
    already-grounded signals (never a new heuristic score) — the LLM summary (if any) must
    still cite which of these actually applied, never assert compromise on its own."""
    other_recipients = sorted(
        {
            addr
            for rc in related_cases
            for addr in rc.to_addresses
            if addr not in targeted_recipients
        }
    )
    same_subject_siblings = [
        str(rc.id) for rc in related_cases if subject and rc.subject == subject
    ]
    compromise_signals: list[str] = []
    if related_incident_count > 0:
        compromise_signals.append(
            f"{related_incident_count} correlated activity incident(s) for this actor"
        )
    if threat_level_band and threat_level_band != "normal":
        compromise_signals.append(f"early-warning threat level band is '{threat_level_band}'")
    if ueba_finding_count > 0:
        compromise_signals.append(f"{ueba_finding_count} behavioral-anomaly finding(s)")

    return {
        "targeted_recipients": sorted(targeted_recipients),
        "other_recipients_same_sender": other_recipients,
        "likely_same_campaign_case_ids": same_subject_siblings,
        "possible_additional_targets": len(other_recipients) > 0,
        "possible_account_compromise": len(compromise_signals) > 0,
        "compromise_signals": compromise_signals,
    }
