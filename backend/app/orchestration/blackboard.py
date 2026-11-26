"""The shared case context (blackboard) the D6 agents read from and write to. Pure.

A CaseSnapshot holds only data Cordon already computed and stored: the verdict and score,
the indicator findings, D3's sender intelligence and account-takeover result, the threat-intel
hits, D4's deterministic assessment, and the account's D5 policy. There is no email body field
at all. Strings that originate in the email (indicator evidence such as URLs, the sender
address) are wrapped by app.investigation.tools.untrusted() before they become finding text,
so a downstream reader (the LLM synthesis) sees them as delimited data.

Agents append Contributions. Each finding has a stable, citable id (DET-1, TI-1, ID-1, INV-1,
RSP-1, ...) and `refs`: the earlier findings it used. That is the audit trail of who said what
and on what basis.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.autonomy.engine import DecisionInputs, PolicyView

AGENTS = ("detection", "threat_intel", "identity", "investigation", "response")
PREFIX = {
    "detection": "DET",
    "threat_intel": "TI",
    "identity": "ID",
    "investigation": "INV",
    "response": "RSP",
}
AGENT_LABEL = {
    "detection": "Detection",
    "threat_intel": "Threat intelligence",
    "identity": "Sender & identity",
    "investigation": "Investigation",
    "response": "Response policy",
}
STANCES = ("supports_threat", "supports_benign", "neutral")
WEIGHTS = ("strong", "moderate", "weak")


@dataclass(frozen=True)
class CaseSnapshot:
    case_id: str
    verdict: str
    score: int
    indicators: tuple[dict, ...] = ()  # the Case's stored indicator dicts
    sender_address: str | None = None
    sender_domain: str | None = None
    account_takeover: dict | None = None
    sender_intelligence: dict | None = None
    threat_intel_hits: tuple[dict, ...] = ()
    d4: dict = field(default_factory=dict)  # Investigation.report, {} when none
    decision_inputs: DecisionInputs | None = None
    policy: PolicyView = field(default_factory=PolicyView)

    @property
    def indicator_ids(self) -> list[str]:
        return [i.get("id") for i in self.indicators if i.get("id")]


@dataclass
class Finding:
    id: str
    text: str
    kind: str
    refs: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"id": self.id, "text": self.text, "kind": self.kind, "refs": list(self.refs), "meta": dict(self.meta)}


@dataclass
class Contribution:
    agent: str
    round: int
    status: str = "ok"  # "ok" | "no_data" | "error" | "skipped"
    stance: str = "neutral"
    weight: str = "weak"
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    cross_check_of: str | None = None  # conflict id, for round-2 cross-checks

    def as_dict(self) -> dict:
        return {
            "agent": self.agent,
            "label": AGENT_LABEL[self.agent],
            "round": self.round,
            "status": self.status,
            "stance": self.stance,
            "weight": self.weight,
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
            "cross_check_of": self.cross_check_of,
        }


class CaseBlackboard:
    """The snapshot plus the append-only contributions. Finding ids are numbered per agent
    across rounds, so a cross-check's findings continue the agent's sequence."""

    def __init__(self, snapshot: CaseSnapshot) -> None:
        self.snapshot = snapshot
        self.contributions: list[Contribution] = []
        self._counters: dict[str, int] = {a: 0 for a in AGENTS}

    def new_finding(self, agent: str, text: str, kind: str, refs: list[str] | None = None, **meta) -> Finding:
        self._counters[agent] += 1
        return Finding(f"{PREFIX[agent]}-{self._counters[agent]}", text, kind, list(refs or []), meta)

    def add(self, contribution: Contribution) -> Contribution:
        self.contributions.append(contribution)
        return contribution

    def latest(self, agent: str) -> Contribution | None:
        for c in reversed(self.contributions):
            if c.agent == agent and c.status not in ("skipped",):
                return c
        return None

    def findings(self, agent: str | None = None, kind: str | None = None) -> list[Finding]:
        out = []
        for c in self.contributions:
            if agent and c.agent != agent:
                continue
            out.extend(f for f in c.findings if kind is None or f.kind == kind)
        return out

    def finding_ids(self) -> set[str]:
        return {f.id for c in self.contributions for f in c.findings}

    def finding_text(self) -> dict[str, str]:
        return {f.id: f.text for c in self.contributions for f in c.findings}

    def indicator_finding(self, indicator_id: str) -> Finding | None:
        for f in self.findings("detection", "indicator"):
            if f.meta.get("indicator_id") == indicator_id:
                return f
        return None
