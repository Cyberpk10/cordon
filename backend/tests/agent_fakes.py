"""Offline stand-ins for the investigation agent's one network boundary
(app.investigation.agent._call_anthropic). A script is a list of turns; each turn is a list
of blocks, or a callable(messages) -> blocks so a test can react to what the agent sent."""

from __future__ import annotations

import itertools
from types import SimpleNamespace

_ids = itertools.count(1)


def tool_use(name: str, **inp) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=f"toolu_{next(_ids)}", name=name, input=inp)


def submit(stated_verdict: str, claims: list[tuple[str, list[str]]], *, category="credential_phishing",
           rationale="Credential request (EV1).", hyp_ids=("EV1",), uncertainty="medium") -> SimpleNamespace:
    return tool_use(
        "submit_investigation",
        stated_verdict=stated_verdict,
        claims=[{"text": t, "evidence_ids": list(ids)} for t, ids in claims],
        hypothesis={"category": category, "rationale": rationale, "evidence_ids": list(hyp_ids),
                    "uncertainty": uncertainty},
    )


class Script:
    def __init__(self, turns, *, tokens_per_turn: int = 100):
        self.turns = list(turns)
        self.calls: list[dict] = []
        self.tokens_per_turn = tokens_per_turn

    def __call__(self, **kw):
        self.calls.append(kw)
        turn = self.turns.pop(0) if self.turns else []
        blocks = turn(kw["messages"]) if callable(turn) else turn
        return SimpleNamespace(
            content=blocks,
            usage=SimpleNamespace(input_tokens=self.tokens_per_turn, output_tokens=0),
        )

    @property
    def all_prompt_text(self) -> str:
        """Everything sent to the model, flattened, for "never in the prompt" assertions."""
        out = []
        for call in self.calls:
            out.append(call["system"])
            for m in call["messages"]:
                c = m["content"]
                if isinstance(c, str):
                    out.append(c)
                else:
                    for block in c:
                        out.append(str(block.get("content") or block.get("text") or block.get("input") or ""))
        return "\n".join(out)
