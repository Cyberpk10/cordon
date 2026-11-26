"""Conflict detection, resolution and the consolidated decision for D6. Pure.

Every field of the synthesis is computed here from the agents' structured findings, never
from text, so nothing an email says (and nothing an LLM writes) can move the verdict, the
confidence or the recommended action.

The consolidated verdict IS the detection verdict: D6 never re-scores. What it decides is the
confidence (raised when independent agents corroborate, lowered when one dissents), the
recommended action (D4's, adjusted by the conflict rules), and which conflicts were found and
how each was resolved.

Conflict catalog:
    C1 trusted sender flagged   flagged email, established sender, no ATO, no intel match.
                                Cross-check: identity. Anomalies found -> treated as a
                                compromised/spoofed account, confidence kept. None -> confidence
                                down one level, verify with the sender, never block.
    C2 shared-host intel match  a feed match on a shortener/file-sharing host. Cross-check:
                                threat_intel re-checks the exact URL; unconfirmed is discounted.
    C3 hypothesis disagreement  the AI-written investigation's hypothesis differs from the one
                                detection's findings support. The rules hypothesis is used.
    C4 tier gap                 the recommended action needs a higher tier than the account
                                allows: it needs approval. Informational.
    C5 corroboration            two or more of threat_intel / identity / investigation strongly
                                support a threat on a flagged email: confidence up one level;
                                on a suspicious verdict, escalation is advised.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.autonomy.actions import ACTIONS, BLOCK_SENDER_DOMAIN, QUARANTINE_EMAIL
from app.autonomy.engine import TIERS
from app.investigation import assessment as A
from app.orchestration.blackboard import AGENTS, AGENT_LABEL, CaseBlackboard

_LEVELS = ("low", "medium", "high")
CONFLICT_TITLES = {
    "C1": "Trusted sender flagged",
    "C2": "Threat-intel match on a shared host",
    "C3": "Hypothesis disagreement",
    "C4": "Recommended action is above this account's tier",
    "C5": "Independent agents corroborate the threat",
}


@dataclass
class Conflict:
    id: str
    agents: list[str]
    refs: list[str]
    cross_check: str | None = None  # the agent asked to re-examine in round 2
    resolution: str = ""
    effect: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": CONFLICT_TITLES[self.id],
            "agents": self.agents,
            "refs": self.refs,
            "cross_check": self.cross_check,
            "resolution": self.resolution,
            "effect": self.effect,
        }


def _ids(board: CaseBlackboard, agent: str, kind: str) -> list[str]:
    return [f.id for f in board.findings(agent, kind)]


def detect_conflicts(board: CaseBlackboard) -> list[Conflict]:
    snap = board.snapshot
    flagged = snap.verdict in ("suspicious", "malicious")
    out: list[Conflict] = []
    standing = board.findings("identity", "standing")
    classification = standing[0].meta.get("classification") if standing else None
    has_ato = bool(board.findings("identity", "ato"))
    intel = board.findings("threat_intel", "intel_match")
    confirmed_intel = [f for f in intel if f.meta.get("confirmed")]

    if flagged and classification == "established" and not has_ato and not confirmed_intel:
        out.append(Conflict(
            "C1", ["detection", "identity"],
            _ids(board, "detection", "verdict") + [f.id for f in standing],
            cross_check="identity",
        ))
    shared = [f for f in intel if f.meta.get("shared_host")]
    if shared:
        out.append(Conflict("C2", ["threat_intel", "detection"], [f.id for f in shared], cross_check="threat_intel"))
    for f in board.findings("investigation", "hypothesis"):
        if f.meta.get("llm_written") and f.meta.get("d4_category") != f.meta.get("rules_category"):
            out.append(Conflict("C3", ["investigation", "detection"], [f.id] + _ids(board, "detection", "families")))
    for f in board.findings("investigation", "recommendation"):
        tier = f.meta.get("tier")
        if tier and tier in TIERS and TIERS.index(tier) > TIERS.index(snap.policy.tier):
            out.append(Conflict("C4", ["investigation", "response"], [f.id] + _ids(board, "response", "policy")))
    return out


def corroboration(board: CaseBlackboard) -> Conflict | None:
    if board.snapshot.verdict not in ("suspicious", "malicious"):
        return None
    strong = []
    for agent in ("threat_intel", "identity", "investigation"):
        c = board.latest(agent)
        if c is not None and c.status == "ok" and c.stance == "supports_threat" and c.weight == "strong":
            strong.append(agent)
    if len(strong) < 2:
        return None
    refs = [f.id for a in strong for f in (board.latest(a).findings if board.latest(a) else [])][:8]
    return Conflict("C5", strong, refs)


def _shift(level: str, by: int) -> str:
    return _LEVELS[max(0, min(len(_LEVELS) - 1, _LEVELS.index(level) + by))]


def _base_confidence(board: CaseBlackboard) -> tuple[str, list[str]]:
    snap = board.snapshot
    conf = (snap.d4 or {}).get("confidence")
    if conf and conf.get("level") in _LEVELS:
        return conf["level"], _ids(board, "investigation", "confidence")
    # No investigation: the same family count D4 would use, without campaign data.
    level = A.assess_confidence(snap.verdict, snap.indicator_ids, {"status": "one_off"}, True, None)["level"]
    return level, _ids(board, "detection", "families") or _ids(board, "detection", "verdict")


def synthesize(board: CaseBlackboard, conflicts: list[Conflict]) -> dict:
    snap = board.snapshot
    verdict_refs = _ids(board, "detection", "verdict")
    base_level, conf_refs = _base_confidence(board)
    level = base_level
    reasons: list[str] = []
    escalation_advised = False

    rec = (snap.d4 or {}).get("recommendation") or {}
    action = rec.get("action")
    tier = rec.get("suggested_tier")
    rationale = rec.get("rationale") or ""
    action_refs = _ids(board, "investigation", "recommendation")
    action_source = "investigation" if snap.d4 else "none"
    hypothesis = A.rules_hypothesis(snap.verdict, snap.indicator_ids)
    hyp_refs = _ids(board, "investigation", "hypothesis") or _ids(board, "detection", "families")

    for c in conflicts:
        if c.id == "C1":
            check = [f for f in board.findings("identity", "cross_check")]
            found = any(f.meta.get("found") for f in check)
            c.refs += [f.id for f in check]
            if not check:
                c.resolution = "Not cross-checked (round budget reached); the flag stands as scored."
            elif found:
                hypothesis = "account_takeover"
                hyp_refs = hyp_refs + [f.id for f in check]
                c.resolution = ("The established sender's email shows anomalies: treated as a compromised "
                                "or spoofed account. Confidence kept.")
                c.effect = {"hypothesis": "account_takeover"}
                if action == BLOCK_SENDER_DOMAIN:
                    action, action_source = QUARANTINE_EMAIL, "adjusted:C1"
            else:
                level = _shift(level, -1)
                reasons.append("An established correspondent with no sign of compromise sent this, so "
                               "the flag may be a false alarm.")
                c.resolution = ("No compromise signal for this established sender: confidence lowered one "
                                "level. Verify with the sender through a channel you already trust; never "
                                "block a known correspondent's domain.")
                c.effect = {"confidence": -1}
                if action == BLOCK_SENDER_DOMAIN:
                    action, action_source = QUARANTINE_EMAIL, "adjusted:C1"
                rationale = (rationale + " Confirm with the sender out of band before acting.").strip()
            conf_refs = conf_refs + c.refs
            action_refs = action_refs + c.refs
        elif c.id == "C2":
            checks = board.findings("threat_intel", "cross_check")
            c.refs += [f.id for f in checks]
            kept = sum(1 for f in checks if f.meta.get("confirmed"))
            if not checks:
                c.resolution = "Not cross-checked (round budget reached); shared-host matches treated as unconfirmed."
            else:
                c.resolution = (f"{kept} of {len(checks)} shared-host match(es) confirmed by exact URL; "
                                "unconfirmed matches are discounted.")
            c.effect = {"confirmed": kept}
        elif c.id == "C3":
            f = board.findings("investigation", "hypothesis")[0]
            c.resolution = (f"The AI-written investigation suggested "
                            f"{A.HYPOTHESIS_LABEL.get(f.meta['d4_category'], f.meta['d4_category'])}; "
                            f"Cordon uses the hypothesis its findings support "
                            f"({A.HYPOTHESIS_LABEL.get(f.meta['rules_category'], f.meta['rules_category'])}).")
        elif c.id == "C4":
            c.resolution = (f"Needs tier {tier}, the account allows {snap.policy.tier}: it would wait for a "
                            "person's approval. Nothing runs on its own.")

    c5 = corroboration(board)
    if c5 is not None:
        new_level = _shift(level, +1)
        c5.effect = {"confidence": +1 if new_level != level else 0}
        level = new_level
        reasons.append(f"{len(c5.agents)} independent agents ("
                       + ", ".join(AGENT_LABEL[a] for a in c5.agents) + ") strongly support a threat.")
        if snap.verdict == "suspicious":
            escalation_advised = True
            c5.effect["escalation_advised"] = True
        c5.resolution = "Confidence raised one level" + (" (already high)" if c5.effect["confidence"] == 0 else "") + (
            "; escalation advised: review this as malicious." if escalation_advised else ".")
        conflicts = conflicts + [c5]
        conf_refs = conf_refs + c5.refs

    if snap.verdict == "safe":
        action, tier, action_source = None, None, action_source
        title = "No action needed: keep monitoring"
    else:
        if action is None:
            action = QUARANTINE_EMAIL
            action_source = "default"
        definition = ACTIONS[action]
        # Same tier rule as D4's recommend(), applied to the consolidated confidence.
        if level == "low" or A.CONFIDENCE_SCORE[level] < definition.min_confidence_floor:
            tier = "L0"
            title = f"Review: {definition.title}"
        else:
            tier = "L2" if definition.containment else "L1"
            title = definition.title

    planned = board.findings("response", "planned_action")
    outcomes: dict[str, int] = {}
    for f in planned:
        outcomes[f.meta["outcome"]] = outcomes.get(f.meta["outcome"], 0) + 1
    pol = snap.policy
    if pol.kill_switch:
        d5_line = "The kill switch is on: the autonomy engine would do nothing."
    elif not planned:
        d5_line = "The autonomy engine would take no action."
    elif pol.shadow_mode:
        d5_line = f"In shadow mode the autonomy engine would record {len(planned)} would-have action(s) and change nothing."
    else:
        d5_line = ("The autonomy engine would: " + ", ".join(f"{n} {o.replace('_', ' ')}" for o, n in outcomes.items()) + ".")

    agreement = {}
    for agent in AGENTS:
        c = board.latest(agent)
        agreement[agent] = {"stance": c.stance, "weight": c.weight, "status": c.status} if c else {"status": "missing"}

    return {
        "verdict": snap.verdict,
        "score": snap.score,
        "confidence": {
            "level": level,
            "score": A.CONFIDENCE_SCORE[level],
            "base_level": base_level,
            "change": _LEVELS.index(level) - _LEVELS.index(base_level),
            "reasons": reasons,
        },
        "hypothesis": {"category": hypothesis, "label": A.HYPOTHESIS_LABEL[hypothesis]},
        "recommended_action": {
            "action": action,
            "title": title,
            "suggested_tier": tier,
            "rationale": rationale if snap.verdict != "safe" else "Rated safe.",
            "source": action_source,
            "executed": False,
        },
        "escalation_advised": escalation_advised,
        "would_d5_act": {"summary": d5_line, "outcomes": outcomes, "mode": "shadow" if pol.shadow_mode else "active"},
        "conflicts": [c.as_dict() for c in conflicts],
        "agreement": agreement,
        "citations": {
            "verdict": verdict_refs,
            "confidence": list(dict.fromkeys(conf_refs)),
            "hypothesis": list(dict.fromkeys(hyp_refs)),
            "recommended_action": list(dict.fromkeys(action_refs)),
            "would_d5_act": [f.id for f in board.findings("response")],
        },
    }


def rules_narrative(board: CaseBlackboard, synthesis: dict) -> dict:
    """Template sentences, one per agent plus a synthesis paragraph, each citing ids."""
    summaries = []
    for agent in AGENTS:
        c = board.latest(agent)
        if c is None:
            continue
        ids = [f.id for f in c.findings][:4]
        summaries.append({"agent": agent, "text": c.summary or AGENT_LABEL[agent], "finding_ids": ids})
    conf = synthesis["confidence"]
    rec = synthesis["recommended_action"]
    parts = [
        f"Verdict {synthesis['verdict']} ({synthesis['score']}/100), consolidated confidence {conf['level']}"
        + (f" ({'up' if conf['change'] > 0 else 'down'} from {conf['base_level']})" if conf["change"] else "") + "."
    ]
    for c in synthesis["conflicts"]:
        parts.append(f"{c['title']}: {c['resolution']}")
    parts.append(f"Recommended: {rec['title']}" + (f" (tier {rec['suggested_tier']})." if rec["suggested_tier"] else "."))
    parts.append(synthesis["would_d5_act"]["summary"])
    cited = list(dict.fromkeys(synthesis["citations"]["verdict"] + synthesis["citations"]["confidence"]
                               + synthesis["citations"]["recommended_action"]))
    return {"agent_summaries": summaries, "synthesis": {"text": " ".join(parts), "finding_ids": cited}}
