"""Unit tests for app.copilot.intent — the deterministic (LLM-free) copilot router and
narrator. Pure functions; no DB, no network."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.copilot.intent import EXAMPLE_QUESTIONS, describe_result, match_question
from app.copilot.llm import _build_selection_user_content
from app.copilot.templates import TEMPLATE_REGISTRY

NOW = datetime(2026, 11, 18, 15, 30)  # a Wednesday


@pytest.mark.parametrize("question", EXAMPLE_QUESTIONS)
def test_every_example_question_matches_a_whitelisted_template(question):
    selection = match_question(question, NOW)
    assert selection is not None
    name, params = selection
    # Validates exactly as execute_template would (extra="forbid").
    TEMPLATE_REGISTRY[name].param_model(**params)


@pytest.mark.parametrize(
    "question,expected",
    [
        ("how many malicious emails this month", ("verdict_counts", {"date_from": datetime(2026, 11, 1)})),
        ("How many malicious emails this month?", ("verdict_counts", {"date_from": datetime(2026, 11, 1)})),
        ("How many phishing emails have we seen?", ("verdict_counts", {})),
        ("verdict breakdown for last month", (
            "verdict_counts",
            {"date_from": datetime(2026, 10, 1), "date_to": datetime(2026, 11, 1) - timedelta(microseconds=1)},
        )),
        ("how many threats in the last 7 days", ("verdict_counts", {"date_from": NOW - timedelta(days=7)})),
        ("how many malicious emails this week", ("verdict_counts", {"date_from": datetime(2026, 11, 16)})),
        ("how many suspicious emails today", ("verdict_counts", {"date_from": datetime(2026, 11, 18)})),
        ("what's our MITRE coverage", ("framework_coverage", {"framework": "mitre"})),
        ("What’s our MITRE ATT&CK coverage?", ("framework_coverage", {"framework": "mitre"})),
        ("NIST CSF coverage this year", ("framework_coverage", {"framework": "nist", "date_from": datetime(2026, 1, 1)})),
        ("ISO 27001 control coverage", ("framework_coverage", {"framework": "iso"})),
        ("show SOC 2 compliance coverage", ("framework_coverage", {"framework": "soc2"})),
        ("how often was alice@example.com targeted", ("target_lookup", {"recipient": "alice@example.com"})),
        ("Has Bob@Example.com been phished this month?", (
            "target_lookup", {"recipient": "bob@example.com", "date_from": datetime(2026, 11, 1)},
        )),
        ("what are our top indicators", ("top_indicators", {})),
        ("top 3 threats this quarter", ("top_indicators", {"top_n": 3, "date_from": datetime(2026, 10, 1)})),
        ("most common indicators", ("top_indicators", {})),
        ("how many cases for CREDENTIAL_REQUEST", ("indicator_case_count", {"indicator_id": "CREDENTIAL_REQUEST"})),
    ],
)
def test_recognized_question_shapes(question, expected):
    assert match_question(question, NOW) == expected


@pytest.mark.parametrize(
    "question",
    [
        "will it rain tomorrow?",
        "summarize the latest incident",
        # Ambiguous -> left to the LLM rather than guessed.
        "compare MITRE and NIST coverage",
        "was alice@example.com or bob@example.com targeted more?",
        "how many CREDENTIAL_REQUEST vs LOOKALIKE_DOMAIN cases",
        # Narrower than a plain count/ranking -> a verdict count would be a wrong answer.
        "how many cases had credential requests?",
        "how many malicious emails from paypal",
        "how many emails with attachments were malicious",
        "top threats targeting finance",
        # Framework named but no coverage intent.
        "what is MITRE",
        # Address present but no targeting intent.
        "who is alice@example.com",
    ],
)
def test_unrecognized_or_ambiguous_questions_return_none(question):
    assert match_question(question, NOW) is None


def test_describe_verdict_counts_uses_only_result_figures():
    result = {"date_from": "2026-11-01T00:00:00", "date_to": None,
              "counts": {"malicious": 2, "suspicious": 1, "safe": 7}, "total": 10}
    assert describe_result("verdict_counts", result) == (
        "Cordon analyzed 10 emails since 2026-11-01: 2 malicious, 1 suspicious, and 7 safe."
    )


def test_describe_empty_period_says_so_instead_of_inventing():
    result = {"date_from": "2026-11-01T00:00:00", "date_to": None,
              "counts": {"malicious": 0, "suspicious": 0, "safe": 0}, "total": 0}
    assert describe_result("verdict_counts", result) == "No emails were analyzed since 2026-11-01."


def test_describe_framework_coverage():
    result = {"framework": "mitre", "date_from": None, "date_to": None,
              "framework_name": "MITRE ATT&CK", "total_controls": 18,
              "operating_controls": 5, "coverage_pct": 27.78, "controls": []}
    assert describe_result("framework_coverage", result) == (
        "MITRE ATT&CK: 5 of 18 mapped controls (27.78%) have at least one supporting detection."
    )


def test_describe_target_lookup_hit_and_miss():
    miss = {"recipient": "alice@example.com", "date_from": None, "date_to": None, "hit_count": 0}
    assert describe_result("target_lookup", miss) == (
        "alice@example.com has not been targeted by any suspicious or malicious email."
    )
    hit = {**miss, "hit_count": 3, "top_indicator_title": "Credential request",
           "flagged_for_training": True}
    assert describe_result("target_lookup", hit) == (
        "alice@example.com was targeted by 3 suspicious or malicious emails. "
        "Most common indicator: Credential request. They are flagged for micro-training."
    )


def test_describe_top_indicators():
    result = {"date_from": None, "date_to": None, "top_indicators": [
        {"indicator_id": "A", "title": "Urgency", "count": 4},
        {"indicator_id": "B", "title": "SPF fail", "count": 1},
    ]}
    assert describe_result("top_indicators", result) == (
        "Most frequently triggered indicators: Urgency (4); SPF fail (1)."
    )


def test_llm_selection_prompt_states_todays_date():
    content = _build_selection_user_content("how many malicious emails this month", NOW)
    assert "Today's date is 2026-11-18 (UTC)" in content
    # The untrusted-question delimiting is unchanged.
    assert "<user_question>\nhow many malicious emails this month\n</user_question>" in content
