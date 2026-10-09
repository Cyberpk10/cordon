"""DB-touching glue for the agentic investigation layer (M10 Stage 1) — queries Cordon's own
already-persisted tables (never an external SOC source) and hands the raw rows to
app.investigation.aggregation's pure functions. Mirrors the query/aggregate split used
throughout this codebase (app.api.routes.events._load_baseline_snapshot + app.baselines.
aggregation is the closest precedent).

Scope, by design: every query here is a bounded lookback window over ONE account's own data
(cases, incidents, events, sender history, threat-level). There is no code path in this
module that reaches outside app_id-scoped Cordon data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import ActorThreatLevel, Case, Event, Incident, TrustedVendorDomain
from app.indicators.domain_utils import registrable_domain
from app.investigation.aggregation import (
    RelatedCaseRef,
    RelatedIncidentRef,
    TimelineEntry,
    build_scope,
    build_timeline,
    extract_threat_intel_hits,
)
from app.sender_history.aggregation import (
    SenderHistorySnapshot,
    build_sender_history,
    classify_sender,
)
from app.threat_level.aggregation import compute_band, compute_trend


@dataclass(frozen=True)
class SenderIntelligence:
    domain: str
    classification: str
    seen_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    is_trusted_vendor: bool

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "classification": self.classification,
            "seen_count": self.seen_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_trusted_vendor": self.is_trusted_vendor,
        }


@dataclass(frozen=True)
class ThreatLevelSnapshot:
    score: float
    band: str
    trend: str

    def to_dict(self) -> dict:
        return {"score": self.score, "band": self.band, "trend": self.trend}


@dataclass(frozen=True)
class InvestigationContext:
    actor: str | None
    verdict: str
    score: int
    # The triggering case's own subject line — untrusted, attacker-controlled free text
    # whenever the trigger is a case. None for an incident trigger (no email involved).
    subject: str | None
    triggering_indicators: list[dict]
    sender: SenderIntelligence | None
    related_cases: list[RelatedCaseRef]
    related_incidents: list[RelatedIncidentRef]
    threat_intel_hits: list[dict]
    threat_level: ThreatLevelSnapshot | None
    ueba_findings: list[dict]
    timeline: list[TimelineEntry]
    scope: dict


def _load_sender_history_excluding_case(
    db: Session, account_id: UUID, exclude_case_id: UUID, now: datetime
) -> SenderHistorySnapshot:
    """Mirrors app.sender_history.loader.load_sender_history exactly, with one addition:
    excludes `exclude_case_id` itself. That loader is only ever called BEFORE the case being
    analyzed exists (see app.api.routes.analyze), so it never needs this exclusion; an
    investigation runs AFTER the triggering case is already committed, so without excluding
    it, a case would count as its own prior correspondence history — inflating seen_count by
    one and potentially flipping a genuine first-contact sender to "seen_before.\""""
    cutoff = now - timedelta(days=settings.sender_history_lookback_days)
    rows = (
        db.query(Case.from_addr, Case.created_at)
        .filter(
            Case.account_id == account_id,
            Case.channel == "email",
            Case.from_addr.is_not(None),
            Case.created_at >= cutoff,
            Case.id != exclude_case_id,
        )
        .all()
    )
    trusted = frozenset(
        row[0]
        for row in db.query(TrustedVendorDomain.domain)
        .filter(TrustedVendorDomain.account_id == account_id)
        .all()
    )
    return build_sender_history(list(rows), trusted)


def _build_sender_intelligence(
    db: Session, account_id: UUID, case: Case, now: datetime
) -> SenderIntelligence | None:
    if not case.from_addr or "@" not in case.from_addr:
        return None
    domain = registrable_domain(case.from_addr.rsplit("@", 1)[-1].lower())
    snapshot = _load_sender_history_excluding_case(db, account_id, case.id, now)
    classification = classify_sender(snapshot, domain)
    history = snapshot.domains.get(domain)
    return SenderIntelligence(
        domain=domain,
        classification=classification.value,
        seen_count=history.seen_count if history else 0,
        first_seen=history.first_seen if history else None,
        last_seen=history.last_seen if history else None,
        is_trusted_vendor=domain in snapshot.trusted_vendor_domains,
    )


def _query_related_cases(db: Session, account_id: UUID, case: Case, now: datetime) -> list[Case]:
    if not case.from_addr:
        return []
    cutoff = now - timedelta(days=settings.investigation_lookback_days)
    return (
        db.query(Case)
        .filter(
            Case.account_id == account_id,
            Case.from_addr == case.from_addr,
            Case.id != case.id,
            Case.created_at >= cutoff,
        )
        .order_by(Case.created_at.desc())
        .limit(settings.investigation_max_related_cases)
        .all()
    )


def _query_related_incidents(
    db: Session, account_id: UUID, actor: str | None, now: datetime
) -> list[Incident]:
    if not actor:
        return []
    cutoff = now - timedelta(days=settings.investigation_lookback_days)
    rows = (
        db.query(Incident)
        .filter(Incident.account_id == account_id, Incident.created_at >= cutoff)
        .order_by(Incident.created_at.desc())
        .all()
    )
    matched = [
        row for row in rows if row.actor == actor or (row.related_actors and actor in row.related_actors)
    ]
    return matched[: settings.investigation_max_related_incidents]


def _query_related_events(db: Session, account_id: UUID, actor: str | None, now: datetime) -> list[Event]:
    if not actor:
        return []
    cutoff = now - timedelta(days=settings.investigation_lookback_days)
    return (
        db.query(Event)
        .filter(Event.account_id == account_id, Event.actor == actor, Event.timestamp >= cutoff)
        .order_by(Event.timestamp.desc())
        .limit(settings.investigation_max_timeline_events)
        .all()
    )


def _query_threat_level(db: Session, account_id: UUID, actor: str | None) -> ActorThreatLevel | None:
    if not actor:
        return None
    return (
        db.query(ActorThreatLevel)
        .filter(ActorThreatLevel.account_id == account_id, ActorThreatLevel.actor == actor)
        .first()
    )


def _event_description(event: Event) -> str:
    outcome = f" ({event.outcome})" if event.outcome else ""
    source = f" from {event.source_ip}" if event.source_ip else ""
    target = f" on {event.target}" if event.target else ""
    return f"{event.action}{target}{source}{outcome}"


def gather_context(
    db: Session,
    account_id: UUID,
    *,
    case: Case | None = None,
    incident: Incident | None = None,
    now: datetime | None = None,
) -> InvestigationContext:
    """Assembles everything the investigation needs from Cordon's own already-persisted
    data. Exactly one of case/incident must be given (callers — app.investigation.build —
    enforce this); the other half's gather steps simply degrade to empty/None rather than
    raising, so a context is always buildable.

    `now` is normalized to naive UTC up front (app.core.time.to_naive_utc) and threaded
    through every lookback/cutoff calculation below — this codebase's DB-persisted
    timestamps round-trip naive on SQLite (tests) and aware on Postgres (prod), and mixing
    the two raises TypeError on direct Python-side comparison (see app.threat_level.
    aggregation.compute_trend, which does exactly that). Every other hooks/route module in
    this codebase normalizes the same way before touching a stored timestamp."""
    if now is None:
        now = datetime.now(timezone.utc)
    now = to_naive_utc(now)

    if case is not None:
        actor = case.to_addresses[0] if case.to_addresses else None
        verdict, score = case.verdict, case.score
        subject = case.subject
        triggering_indicators = list(case.indicators)
    else:
        assert incident is not None
        actor = incident.actor
        verdict, score = incident.verdict, incident.score
        subject = None
        triggering_indicators = []

    sender = _build_sender_intelligence(db, account_id, case, now) if case is not None else None

    related_case_rows = _query_related_cases(db, account_id, case, now) if case is not None else []
    related_cases = [
        RelatedCaseRef(
            id=row.id,
            created_at=row.created_at,
            verdict=row.verdict,
            score=row.score,
            subject=row.subject,
            to_addresses=list(row.to_addresses),
        )
        for row in related_case_rows
    ]

    related_incident_rows = _query_related_incidents(db, account_id, actor, now)
    # Excludes the triggering incident itself from its own "related" list.
    related_incident_rows = [
        row for row in related_incident_rows if incident is None or row.id != incident.id
    ]
    related_incidents = [
        RelatedIncidentRef(
            id=row.id, created_at=row.created_at, title=row.title, verdict=row.verdict, score=row.score
        )
        for row in related_incident_rows
    ]
    related_incident_findings = [f for row in related_incident_rows for f in row.findings]
    # The triggering incident's OWN findings count as UEBA evidence too — only the triggering
    # CASE's own indicators are excluded from "related" (they're the subject, not corroboration),
    # but an incident's own findings ARE exactly the behavioral-anomaly evidence being
    # investigated, so they belong in ueba_findings regardless of trigger type.
    ueba_findings = list(incident.findings) if incident is not None else []
    ueba_findings = ueba_findings + related_incident_findings

    threat_intel_hits = extract_threat_intel_hits(triggering_indicators, related_incident_findings)
    if incident is not None:
        threat_intel_hits = threat_intel_hits + extract_threat_intel_hits([], incident.findings)

    threat_level_row = _query_threat_level(db, account_id, actor)
    threat_level = None
    if threat_level_row is not None:
        band = compute_band(threat_level_row.current_score, threat_level_row.recent_signals)
        trend = compute_trend(threat_level_row.score_history, threat_level_row.current_score, now)
        threat_level = ThreatLevelSnapshot(score=threat_level_row.current_score, band=band, trend=trend)

    event_rows = _query_related_events(db, account_id, actor, now)

    timeline_entries: list[TimelineEntry] = []
    if case is not None:
        timeline_entries.append(
            TimelineEntry(
                timestamp=case.created_at,
                type="email_delivered",
                description=f"Flagged email delivered: {case.subject or '(no subject)'}",
                source="case",
                source_id=str(case.id),
            )
        )
    for rc in related_cases:
        timeline_entries.append(
            TimelineEntry(
                timestamp=rc.created_at,
                type="related_email_delivered",
                description=f"Related email from the same sender: {rc.subject or '(no subject)'}",
                source="case",
                source_id=str(rc.id),
            )
        )
    for ri in related_incidents:
        timeline_entries.append(
            TimelineEntry(
                timestamp=ri.created_at,
                type="incident_detected",
                description=ri.title,
                source="incident",
                source_id=str(ri.id),
            )
        )
    if incident is not None:
        timeline_entries.append(
            TimelineEntry(
                timestamp=incident.window_start,
                type="incident_detected",
                description=incident.title,
                source="incident",
                source_id=str(incident.id),
            )
        )
    for event in event_rows:
        timeline_entries.append(
            TimelineEntry(
                timestamp=event.timestamp,
                type=event.action,
                description=_event_description(event),
                source="event",
                source_id=str(event.id),
            )
        )

    timeline = build_timeline(timeline_entries, settings.investigation_max_timeline_events)

    targeted_recipients = list(case.to_addresses) if case is not None else ([actor] if actor else [])
    scope = build_scope(
        targeted_recipients=targeted_recipients,
        related_cases=related_cases,
        subject=case.subject if case is not None else None,
        related_incident_count=len(related_incidents),
        threat_level_band=threat_level.band if threat_level else None,
        ueba_finding_count=len(ueba_findings),
    )

    return InvestigationContext(
        actor=actor,
        verdict=verdict,
        score=score,
        subject=subject,
        triggering_indicators=triggering_indicators,
        sender=sender,
        related_cases=related_cases,
        related_incidents=related_incidents,
        threat_intel_hits=threat_intel_hits,
        threat_level=threat_level,
        ueba_findings=ueba_findings,
        timeline=timeline,
        scope=scope,
    )
