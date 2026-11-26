"""D6 multi-agent orchestrator: the only I/O layer for app.orchestration.

Routes a case through the five agents over one blackboard, runs the cross-checks the conflict
catalog asks for, synthesizes, and optionally has the LLM word the result. Bounded by hard caps
(settings.orchestrator_*): rounds, agent steps, LLM calls, projected tokens, projected cost and
a wall-clock deadline. Hitting a cap records `stop_reason` and degrades; it never raises.

Recommend-only: nothing here writes anything but Investigation.multi_agent /
multi_agent_fingerprint. The response agent calls the pure D5 planner, never the runner.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.autonomy.engine import PolicyView
from app.autonomy.runner import _performed_in_window, decision_inputs
from app.core.config import settings
from app.db.models import AutonomyPolicy, Case, Investigation
from app.indicators.domain_utils import registrable_domain
from app.orchestration import agents as AG
from app.orchestration import llm_synthesis as L
from app.orchestration.blackboard import AGENTS, CaseBlackboard, CaseSnapshot, Contribution
from app.orchestration.synthesis import detect_conflicts, rules_narrative, synthesize
from app.threat_intel.loader import match_url

logger = logging.getLogger(__name__)
ENGINE_VERSION = "d6.1"
_CROSS_CHECKS = {"identity", "threat_intel"}


def _policy_view(db: Session, account_id: uuid.UUID, now: datetime) -> PolicyView:
    row = db.query(AutonomyPolicy).filter(AutonomyPolicy.account_id == account_id).first()
    if row is None:
        return PolicyView()  # the defaults a new account gets: L1, shadow on
    return PolicyView(
        tier=row.tier, shadow_mode=row.shadow_mode, kill_switch=row.kill_switch,
        exclusions=frozenset(row.exclusions or []), blast_radius_limit=row.blast_radius_limit,
        performed_in_window=_performed_in_window(db, account_id, row, now),
    )


def build_snapshot(db: Session, case: Case, investigation: Investigation | None, now: datetime) -> CaseSnapshot:
    sender = (case.from_addr or "").strip().lower() or None
    domain = registrable_domain(sender.rsplit("@", 1)[1]) if sender and "@" in sender else None
    return CaseSnapshot(
        case_id=str(case.id),
        verdict=case.verdict,
        score=int(case.score or 0),
        indicators=tuple(case.indicators or []),
        sender_address=sender,
        sender_domain=domain,
        account_takeover=case.account_takeover,
        sender_intelligence=(investigation.sender_intelligence if investigation is not None else None) or None,
        threat_intel_hits=tuple((investigation.threat_intel_hits if investigation is not None else None) or []),
        d4=(investigation.report if investigation is not None else None) or {},
        decision_inputs=decision_inputs(case, investigation),
        policy=_policy_view(db, case.account_id, now),
    )


class _Budget:
    def __init__(self) -> None:
        self.steps = 0
        self.rounds = 0
        self.started = time.monotonic()
        self.stop_reason: str | None = None

    def take_step(self) -> bool:
        if time.monotonic() - self.started > settings.orchestrator_deadline_seconds:
            self.stop_reason = self.stop_reason or "deadline"
            return False
        if self.steps >= settings.orchestrator_max_agent_steps:
            self.stop_reason = self.stop_reason or "max_steps"
            return False
        self.steps += 1
        return True


def _run_agent(board: CaseBlackboard, agent: str, fn, budget: _Budget, round_no: int, *args) -> None:
    if not budget.take_step():
        board.add(Contribution(agent, round_no, status="skipped", summary=f"Skipped: {budget.stop_reason}."))
        return
    try:
        board.add(fn(board, *args))
    except Exception as exc:  # noqa: BLE001 - one agent failing must not stop the others
        logger.warning("D6 agent %s failed: %s", agent, type(exc).__name__)
        board.add(Contribution(agent, round_no, status="error", summary=f"Failed ({type(exc).__name__})."))


def run_agents(snapshot: CaseSnapshot) -> tuple[CaseBlackboard, dict, dict]:
    """Rounds + synthesis, pure apart from the offline threat-intel snapshot lookup.
    Returns (board, synthesis, usage)."""
    board = CaseBlackboard(snapshot)
    budget = _Budget()

    budget.rounds = 1
    for agent in AGENTS:
        _run_agent(board, agent, AG.ROUND_ONE[agent], budget, 1)

    conflicts = detect_conflicts(board)
    wanted = [c for c in conflicts if c.cross_check in _CROSS_CHECKS]
    if wanted:
        if settings.orchestrator_max_rounds >= 2 and budget.stop_reason is None:
            budget.rounds = 2
            for c in wanted:
                if c.cross_check == "identity":
                    _run_agent(board, "identity", AG.cross_check_identity, budget, 2, c.id)
                else:
                    _run_agent(board, "threat_intel", AG.cross_check_threat_intel, budget, 2, c.id, match_url)
        else:
            budget.stop_reason = budget.stop_reason or "max_rounds"
    # Never a third round: conflicts are resolved from whatever the cross-checks found.
    synthesis = synthesize(board, conflicts)
    usage = {"rounds": budget.rounds, "steps": budget.steps, "llm_calls": 0, "tokens": 0, "est_cost_usd": 0.0}
    return board, synthesis, {"usage": usage, "stop_reason": budget.stop_reason, "started": budget.started}


def _fingerprint(board: CaseBlackboard, synthesis: dict) -> str:
    payload = {
        "findings": sorted(board.finding_text().items()),
        "synthesis": {k: synthesis[k] for k in ("verdict", "confidence", "recommended_action", "conflicts")},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:32]


def _project(content: str) -> tuple[int, float]:
    tokens_in = (len(L.SYSTEM_PROMPT) + len(content) + len(json.dumps(L.submit_tool()))) // 4 + 1
    tokens_out = L.MAX_OUTPUT_TOKENS
    cost = tokens_in * settings.llm_price_input_per_mtok_usd / 1e6 + tokens_out * settings.llm_price_output_per_mtok_usd / 1e6
    return tokens_in + tokens_out, cost


def _llm_narrative(board: CaseBlackboard, synthesis: dict, usage: dict, started: float) -> tuple[dict | None, str]:
    if not settings.enable_llm_reasoning:
        return None, "disabled"
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None, "no_api_key"
    if settings.orchestrator_max_llm_calls < 1:
        return None, "skipped: llm_call_cap"
    findings = {a: [f.as_dict() for f in board.findings(a)] for a in AGENTS}
    content = L.build_user_content(findings, synthesis)
    projected_tokens, projected_cost = _project(content)
    if projected_tokens > settings.orchestrator_max_tokens:
        return None, "skipped: token_cap"
    if projected_cost > settings.orchestrator_max_cost_usd:
        return None, "skipped: cost_cap"
    remaining = settings.orchestrator_deadline_seconds - (time.monotonic() - started)
    if remaining <= 1:
        return None, "skipped: deadline"
    try:
        usage["llm_calls"] += 1
        resp = L._call_anthropic(
            api_key=api_key, model=settings.llm_model, system=L.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": content}],
            tools=[L.submit_tool()], tool_choice={"type": "tool", "name": L.SUBMIT},
            timeout=min(L.PER_CALL_TIMEOUT_SECONDS, remaining),
        )
    except Exception as exc:  # noqa: BLE001
        return None, f"failed: {type(exc).__name__}"
    u = getattr(resp, "usage", None)
    t_in, t_out = int(getattr(u, "input_tokens", 0) or 0), int(getattr(u, "output_tokens", 0) or 0)
    usage["tokens"] = t_in + t_out
    usage["est_cost_usd"] = round(
        t_in * settings.llm_price_input_per_mtok_usd / 1e6 + t_out * settings.llm_price_output_per_mtok_usd / 1e6, 6
    )
    block = next((b for b in getattr(resp, "content", []) or [] if getattr(b, "type", None) == "tool_use"
                  and getattr(b, "name", None) == L.SUBMIT), None)
    if block is None:
        return None, "failed: no_submission"
    narrative, reason = L.verify(block.input, synthesis=synthesis, finding_text=board.finding_text())
    if narrative is None:
        return None, f"rejected: {reason}"
    return narrative, "used"


def run_orchestration(
    db: Session, case: Case, *, use_llm: bool, investigation: Investigation | None = None,
    now: datetime | None = None, cached: dict | None = None, cached_fingerprint: str | None = None,
) -> tuple[dict, str]:
    """Build the record. Returns (record, fingerprint). Writes nothing."""
    now = now or datetime.now(timezone.utc)
    snapshot = build_snapshot(db, case, investigation, now)
    board, synthesis, meta = run_agents(snapshot)
    usage = meta["usage"]
    fp = _fingerprint(board, synthesis)
    rules = rules_narrative(board, synthesis)
    narrative, engine, llm_status = rules, "rules", "not_requested"
    if use_llm:
        if cached and cached.get("engine") == "llm" and cached_fingerprint == fp:
            narrative, engine, llm_status = cached["narrative"], "llm", "cached"
        else:
            llm, llm_status = _llm_narrative(board, synthesis, usage, meta["started"])
            if llm is not None:
                by_agent = {s["agent"]: s for s in llm["agent_summaries"]}
                narrative = {
                    # An agent whose LLM sentence was dropped (or missing) keeps its rules sentence.
                    "agent_summaries": [by_agent.get(s["agent"], s) for s in rules["agent_summaries"]],
                    "synthesis": llm["synthesis"],
                    "dropped_agent_summaries": llm["dropped_agent_summaries"],
                }
                engine = "llm"
    elif not settings.enable_llm_reasoning:
        llm_status = "disabled"
    record = {
        "version": ENGINE_VERSION,
        "generated_at": now.isoformat(),
        "agents": [c.as_dict() for c in board.contributions],
        "synthesis": synthesis,
        "narrative": narrative,
        "engine": engine,
        "llm_status": llm_status,
        "model": settings.llm_model if engine == "llm" else None,
        "usage": usage,
        "caps": {
            "max_rounds": settings.orchestrator_max_rounds,
            "max_agent_steps": settings.orchestrator_max_agent_steps,
            "max_llm_calls": settings.orchestrator_max_llm_calls,
            "max_tokens": settings.orchestrator_max_tokens,
            "max_cost_usd": settings.orchestrator_max_cost_usd,
            "deadline_seconds": settings.orchestrator_deadline_seconds,
        },
        "stop_reason": meta["stop_reason"],
        "executed": False,
    }
    return record, fp


def save_orchestration(db: Session, case: Case, *, use_llm: bool) -> dict | None:
    """Run and store on the case's Investigation row. Returns the record, or None when the
    case has no investigation yet (nothing to store on). Does not commit."""
    investigation = (
        db.query(Investigation)
        .filter(Investigation.account_id == case.account_id, Investigation.case_id == case.id)
        .first()
    )
    if investigation is None:
        return None
    use_llm = use_llm and settings.enable_llm_reasoning
    record, fp = run_orchestration(
        db, case, use_llm=use_llm, investigation=investigation,
        cached=investigation.multi_agent, cached_fingerprint=investigation.multi_agent_fingerprint,
    )
    investigation.multi_agent = record
    investigation.multi_agent_fingerprint = fp
    return record


def maybe_orchestrate(db: Session, case: Case, *, use_llm: bool = False) -> None:
    """Trigger hook. Never raises: orchestration must never break analysis."""
    try:
        with db.begin_nested():
            save_orchestration(db, case, use_llm=use_llm)
    except Exception:  # noqa: BLE001
        logger.exception("D6 orchestration failed for case %s", case.id)
