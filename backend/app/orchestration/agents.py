"""The five D6 agents. Pure and deterministic: each reads the blackboard (the snapshot plus
every earlier agent's findings) and returns one Contribution. Each wraps an existing Cordon
capability; none performs I/O or takes an action:

    detection      the stored indicator findings, score and verdict (app.indicators)
    threat_intel   the threat-intel matches those findings contain (app.threat_intel)
    identity       sender standing and account takeover (D3: app.sender_history,
                   app.indicators.account_takeover)
    investigation  D4's deterministic assessment (app.investigation.assessment)
    response       what D5 would do under this account's policy (app.autonomy.engine.plan,
                   the pure planner; the runner that writes is never called)

Plus two round-2 cross-checks the conflict catalog (app.orchestration.synthesis) can request.
"""

from __future__ import annotations

from app.autonomy.cordon_actions import ACTION_SPECS
from app.autonomy.engine import plan
from app.indicators.domain_utils import SHARED_LINK_HOSTS
from app.investigation import assessment as A
from app.investigation.aggregation import THREAT_INTEL_EMAIL_INDICATOR_IDS
from app.investigation.tools import untrusted
from app.orchestration.blackboard import CaseBlackboard, Contribution

_EVIDENCE_CHARS = 160

ATO_IDS = {"ACCOUNT_TAKEOVER", "ACCOUNT_TAKEOVER_LATERAL", "AUTHENTICATED_SENDER_CONTENT_MISMATCH"}
SENDER_ANOMALY_IDS = {
    "TRUSTED_SENDER_ANOMALY", "SENDER_REPLYTO_MISMATCH", "DISPLAY_NAME_EMAIL_MISMATCH",
    "IMPERSONATED_DISPLAY_NAME", "AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DMARC_FAIL",
    "LOOKALIKE_OF_KNOWN_SENDER",
}
_IMPERSONATION_IDS = {"LOOKALIKE_DOMAIN", "LOOKALIKE_OF_KNOWN_SENDER", "PUNYCODE_IDN_DOMAIN", "IMPERSONATED_DISPLAY_NAME"}

OUTCOME_LABEL = {
    "performed": "would be done now",
    "shadow": "would have been done (shadow mode: nothing changes)",
    "awaiting_approval": "needs a person's approval",
    "above_tier": "above this account's tier (recorded only)",
    "halted": "halted by the kill switch",
}


def _evidence(ind: dict) -> str:
    ev = ind.get("evidence") or []
    return f" Evidence: {untrusted(str(ev[0]), _EVIDENCE_CHARS)}" if ev else ""


# --- round 1 -----------------------------------------------------------------------------

def detection(board: CaseBlackboard) -> Contribution:
    snap = board.snapshot
    c = Contribution("detection", 1)
    inds = sorted(snap.indicators, key=lambda i: -(i.get("score") or 0))
    c.findings.append(board.new_finding(
        "detection", f"Cordon's rule engine scored this email {snap.score}/100: {snap.verdict}, "
        f"from {len(inds)} finding{'s' if len(inds) != 1 else ''}.", "verdict",
    ))
    for ind in inds:
        c.findings.append(board.new_finding(
            "detection",
            f"{ind.get('title')} [{ind.get('id')}], +{float(ind.get('score') or 0):.0f} points.{_evidence(ind)}",
            "indicator", indicator_id=ind.get("id"), score=ind.get("score"),
        ))
    fams = A.families_hit(snap.indicator_ids)
    if fams:
        c.findings.append(board.new_finding(
            "detection", "Independent signal families: " + ", ".join(A._FAMILY_LABEL[f] for f in fams) + ".",
            "families", refs=[f.id for f in c.findings if f.kind == "indicator"][:8], families=fams,
        ))
    if snap.verdict == "malicious":
        c.stance, c.weight = "supports_threat", "strong"
    elif snap.verdict == "suspicious":
        c.stance, c.weight = "supports_threat", "moderate"
    else:
        c.stance, c.weight = "supports_benign", "moderate"
    c.summary = f"Scored {snap.score}/100 ({snap.verdict})."
    return c


def _hit_host(evidence: str) -> str | None:
    head = evidence.split(" ", 1)[0].strip().lower()
    return head or None


def _hit_url(evidence: str) -> str | None:
    if "(" in evidence and evidence.rstrip().endswith(")"):
        return evidence.rsplit("(", 1)[1].rstrip(")").strip()
    return None


def threat_intel(board: CaseBlackboard) -> Contribution:
    snap = board.snapshot
    c = Contribution("threat_intel", 1)
    hits = 0
    for ind in snap.indicators:
        if ind.get("id") not in THREAT_INTEL_EMAIL_INDICATOR_IDS:
            continue
        det = board.indicator_finding(ind["id"])
        for ev in (ind.get("evidence") or [])[:5]:
            host = _hit_host(str(ev))
            shared = bool(ind["id"] == "LINK_KNOWN_MALICIOUS" and host in SHARED_LINK_HOSTS)
            c.findings.append(board.new_finding(
                "threat_intel",
                f"Known-bad feed match ({ind.get('title')}): {untrusted(str(ev), _EVIDENCE_CHARS)}",
                "intel_match", refs=[det.id] if det else [], indicator_id=ind["id"],
                shared_host=shared, url=_hit_url(str(ev)) if shared else None, confirmed=not shared,
            ))
            hits += 1
    for hit in snap.threat_intel_hits:
        if hit.get("source") == "activity_finding":
            c.findings.append(board.new_finding(
                "threat_intel", f"A related activity alert matched a known-malicious IP ({hit.get('title')}).",
                "intel_activity",
            ))
            hits += 1
    if not hits:
        c.status = "ok"
        c.findings.append(board.new_finding(
            "threat_intel",
            "No match on Cordon's threat-intelligence snapshot for this email's sender, sending IP or "
            "links. That is not evidence of safety: the snapshot misses newer infrastructure.",
            "no_match",
        ))
        c.summary = "No known-bad match."
        return c
    confirmed = [f for f in c.findings if f.kind == "intel_match" and f.meta.get("confirmed")]
    if confirmed or any(f.kind == "intel_activity" for f in c.findings):
        c.stance, c.weight = "supports_threat", "strong"
        c.summary = f"{len(confirmed) or hits} known-bad match(es)."
    else:
        c.stance, c.weight = "neutral", "weak"
        c.summary = "Only shared-host matches, pending an exact-URL check."
    return c


def identity(board: CaseBlackboard) -> Contribution:
    snap = board.snapshot
    c = Contribution("identity", 1)
    intel = snap.sender_intelligence or {}
    classification = intel.get("classification")
    if snap.sender_address or intel:
        seen = intel.get("seen_count") or 0
        standing = {
            "established": "an established correspondent",
            "seen_before": "seen before, but not yet a regular correspondent",
            "first_contact": "a first-time sender to this account",
            "lookalike_of_known": "a look-alike of a known correspondent",
            "known_bad": "on a known-bad list",
        }.get(classification or "", classification or "unknown")
        c.findings.append(board.new_finding(
            "identity",
            f"Sender {untrusted(snap.sender_address or intel.get('domain'), 120)} is {standing}"
            + (f" (seen {seen} time{'s' if seen != 1 else ''} before)." if classification else "."),
            "standing", classification=classification,
            trusted_vendor=bool(intel.get("is_trusted_vendor")),
        ))
    ato = snap.account_takeover or {}
    ato_refs = [f.id for i in ATO_IDS if (f := board.indicator_finding(i))]
    if ato.get("kind") or ato_refs:
        kind = ato.get("kind") or "possible"
        reasons = ato.get("anomalies") or ato.get("reasons") or []
        reason_text = "; ".join(str(r) for r in reasons[:3]) if isinstance(reasons, list) else ""
        c.findings.append(board.new_finding(
            "identity",
            f"The sender's own mailbox looks compromised ({kind} account takeover)"
            + (f": {untrusted(reason_text, 200)}" if reason_text else "."),
            "ato", refs=ato_refs, ato_kind=ato.get("kind"),
        ))
    anomaly_refs = [f.id for i in sorted(SENDER_ANOMALY_IDS) if (f := board.indicator_finding(i))]
    if anomaly_refs:
        c.findings.append(board.new_finding(
            "identity", "Detection found sender anomalies (authentication failures, mismatched "
            "reply-to/display name, or a break from this sender's usual pattern).",
            "anomaly", refs=anomaly_refs,
        ))
    ti_sender = [f.id for f in board.findings("threat_intel", "intel_match")
                 if f.meta.get("indicator_id") in ("SENDER_DOMAIN_KNOWN_BAD", "SENDER_IP_KNOWN_MALICIOUS")]
    if ti_sender:
        c.findings.append(board.new_finding(
            "identity", "Threat intelligence lists the sender's domain or sending IP as known-bad.",
            "known_bad_sender", refs=ti_sender,
        ))
    imp_refs = [f.id for i in sorted(_IMPERSONATION_IDS) if (f := board.indicator_finding(i))]
    if imp_refs:
        c.findings.append(board.new_finding(
            "identity", "The sender's domain or name imitates someone else.", "impersonation", refs=imp_refs,
        ))
    if not c.findings:
        c.status = "no_data"
        c.summary = "No sender information on this case."
        return c
    kinds = {f.kind for f in c.findings}
    if kinds & {"ato", "known_bad_sender", "impersonation"} or classification in ("lookalike_of_known", "known_bad"):
        c.stance, c.weight = "supports_threat", "strong"
        c.summary = "The sender is compromised, impersonated or known-bad."
    elif classification == "established" and not (kinds & {"anomaly"}):
        c.stance, c.weight = "supports_benign", "moderate"
        c.summary = "An established correspondent with no anomalies."
    elif "anomaly" in kinds:
        c.stance, c.weight = "supports_threat", "moderate"
        c.summary = "Sender anomalies present."
    else:
        c.stance, c.weight = "neutral", "weak"
        c.summary = "No strong signal either way about the sender."
    return c


def investigation(board: CaseBlackboard) -> Contribution:
    snap = board.snapshot
    c = Contribution("investigation", 1)
    report = snap.d4 or {}
    if not report:
        c.status = "no_data"
        c.findings.append(board.new_finding(
            "investigation", "No investigation has been run for this case yet.", "missing",
        ))
        c.summary = "No investigation yet."
        return c
    fam_refs = [f.id for f in board.findings("detection", "families")]
    standing_refs = [f.id for f in board.findings("identity", "standing")]
    conf = report.get("confidence") or {}
    level = conf.get("level") or "low"
    c.findings.append(board.new_finding(
        "investigation", f"The investigation rates its confidence {level}: "
        + " ".join(str(r) for r in (conf.get("reasons") or [])[:2]),
        "confidence", refs=fam_refs, level=level,
    ))
    camp = report.get("campaign") or {}
    status = camp.get("status") or "one_off"
    linked = camp.get("linked_case_ids") or []
    camp_text = {
        "wave": f"This email is part of a wave: {len(linked)} linked message(s) hit other recipients.",
        "possible_campaign": f"Possibly part of a campaign: {len(linked)} related message(s).",
    }.get(status, "No linked campaign: a one-off so far.")
    c.findings.append(board.new_finding("investigation", camp_text, "campaign", status=status, linked=len(linked)))

    rules_cat = A.rules_hypothesis(snap.verdict, snap.indicator_ids)
    hyp = report.get("hypothesis") or {}
    d4_cat = hyp.get("category") or rules_cat
    llm_written = report.get("engine") == "agent"
    text = f"Most likely explanation: {A.HYPOTHESIS_LABEL.get(rules_cat, rules_cat)}."
    if llm_written and d4_cat != rules_cat:
        text += f" (The AI-written investigation suggested {A.HYPOTHESIS_LABEL.get(d4_cat, d4_cat)}.)"
    c.findings.append(board.new_finding(
        "investigation", text, "hypothesis", refs=fam_refs,
        rules_category=rules_cat, d4_category=d4_cat, llm_written=llm_written,
    ))

    rec = report.get("recommendation") or {}
    if rec.get("action"):
        c.findings.append(board.new_finding(
            "investigation",
            f"Recommended response: {rec.get('title')} (needs tier {rec.get('suggested_tier') or 'L0'} to run unattended).",
            "recommendation", refs=standing_refs, action=rec.get("action"), tier=rec.get("suggested_tier"),
        ))
    else:
        c.findings.append(board.new_finding(
            "investigation", f"Recommended response: {rec.get('title') or 'none'}.", "recommendation",
            refs=standing_refs, action=None, tier=None,
        ))
    blast = report.get("blast_radius") or {}
    own = set(snap.decision_inputs.recipients) if snap.decision_inputs else set()
    others = [r for r in (blast.get("exposed_recipients") or []) if r not in own]
    if others:
        c.findings.append(board.new_finding(
            "investigation", f"{len(others)} other recipient(s) received related mail.", "blast_radius",
        ))
    if snap.verdict == "safe":
        c.stance, c.weight = "supports_benign", "moderate"
    else:
        c.stance = "supports_threat"
        c.weight = {"high": "strong", "medium": "moderate"}.get(level, "weak")
        if status == "wave":
            c.weight = "strong"
    c.summary = f"Confidence {level}; {status.replace('_', ' ')}."
    return c


def response(board: CaseBlackboard) -> Contribution:
    snap = board.snapshot
    c = Contribution("response", 1)
    pol = snap.policy
    c.findings.append(board.new_finding(
        "response",
        f"Account autonomy policy: tier {pol.tier}, shadow mode {'on' if pol.shadow_mode else 'off'}, "
        f"kill switch {'on' if pol.kill_switch else 'off'}.",
        "policy", tier=pol.tier, shadow=pol.shadow_mode, kill_switch=pol.kill_switch,
    ))
    if snap.decision_inputs is None:
        c.status = "no_data"
        c.summary = "No decision inputs."
        return c
    rec_refs = [f.id for f in board.findings("investigation", "recommendation")]
    planned = plan(snap.decision_inputs, pol, snap.case_id)
    if not planned:
        c.findings.append(board.new_finding(
            "response", "The autonomy engine would take no action on this case.", "no_action", refs=rec_refs,
        ))
    for p in planned:
        c.findings.append(board.new_finding(
            "response",
            f"{ACTION_SPECS[p.action_type].title} ({p.tier}, rule {p.rule_id}): {OUTCOME_LABEL[p.outcome]}.",
            "planned_action", refs=rec_refs if p.rule_id == "R9-MAILBOX" else [],
            action_type=p.action_type, tier=p.tier, outcome=p.outcome, rule_id=p.rule_id,
        ))
    c.stance, c.weight = "neutral", "weak"
    counts: dict[str, int] = {}
    for p in planned:
        counts[p.outcome] = counts.get(p.outcome, 0) + 1
    c.summary = (", ".join(f"{n} {o.replace('_', ' ')}" for o, n in counts.items()) or "no actions") + "."
    return c


ROUND_ONE = {
    "detection": detection,
    "threat_intel": threat_intel,
    "identity": identity,
    "investigation": investigation,
    "response": response,
}


# --- round 2 cross-checks ----------------------------------------------------------------

def cross_check_identity(board: CaseBlackboard, conflict_id: str) -> Contribution:
    """C1: a flagged email from an established sender. Look again, with detection's findings,
    for anything that would explain a trusted sender sending it (compromise or spoofing)."""
    c = Contribution("identity", 2, cross_check_of=conflict_id)
    anomaly_refs = [f.id for i in sorted(SENDER_ANOMALY_IDS | ATO_IDS) if (f := board.indicator_finding(i))]
    if anomaly_refs:
        c.findings.append(board.new_finding(
            "identity", "Cross-check: this established sender's email also shows anomalies, which "
            "points to a compromised or spoofed account rather than a false alarm.",
            "cross_check", refs=anomaly_refs, found=True,
        ))
        c.stance, c.weight, c.summary = "supports_threat", "moderate", "Anomalies explain the flag."
    else:
        c.findings.append(board.new_finding(
            "identity", "Cross-check: nothing in detection's findings suggests this established "
            "sender's account is compromised or spoofed.",
            "cross_check", refs=[f.id for f in board.findings("detection", "verdict")], found=False,
        ))
        c.stance, c.weight, c.summary = "supports_benign", "moderate", "No compromise signal found."
    return c


def cross_check_threat_intel(board: CaseBlackboard, conflict_id: str, match_url) -> Contribution:
    """C2: a feed match on a shared host (shortener, file sharing). Re-check the exact URL
    against the bundled snapshot; a host-level listing of a shared host says nothing."""
    c = Contribution("threat_intel", 2, cross_check_of=conflict_id)
    confirmed = 0
    for f in board.findings("threat_intel", "intel_match"):
        if not f.meta.get("shared_host"):
            continue
        exact = bool(f.meta.get("url") and match_url(f.meta["url"]))
        f.meta["confirmed"] = exact
        confirmed += exact
        c.findings.append(board.new_finding(
            "threat_intel",
            "Cross-check: the exact URL is on the feed, so the match stands." if exact else
            "Cross-check: only the shared host is listed, not this URL; the match is discounted.",
            "cross_check", refs=[f.id], confirmed=exact,
        ))
    c.stance, c.weight = ("supports_threat", "strong") if confirmed else ("neutral", "weak")
    c.summary = f"{confirmed} exact-URL match(es) confirmed."
    return c
