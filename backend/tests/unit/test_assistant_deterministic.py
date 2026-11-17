"""app.assistant.deterministic: the LLM-free answers, intent routing and off-topic redirect."""

from __future__ import annotations

import pytest

from app.assistant.deterministic import OFF_TOPIC_REDIRECT, answer, classify
from app.assistant.facts import EmailFacts
from app.models.schemas import Indicator, Severity


def _ind(category, title, score=30):
    return Indicator(id=title.upper().replace(" ", "_"), category=category, title=title,
                     description=f"{title} details", severity=Severity.HIGH, score=score)


def _facts(verdict="malicious", score=88, indicators=None, **kw) -> EmailFacts:
    inds = indicators if indicators is not None else [
        _ind("domain", "Look-alike domain", 40), _ind("link", "Link to look-alike domain", 30),
        _ind("authentication", "SPF failed", 20),
    ]
    base = dict(
        verdict=verdict, score=score, summary="s", indicators=inds,
        auth={"spf": "fail", "dkim": "fail", "dmarc": "fail"}, frameworks=["MITRE T1566"],
        from_address="service@paypa1.com", from_display="PayPal",
        reply_to_address="x@secure-mailer.net", subject="Verify", link_domains=["paypa1.com"],
        attachment_names=[],
    )
    base.update(kw)
    return EmailFacts(**base)


@pytest.mark.parametrize(
    "question,intent",
    [
        ("Is this phishing?", "verdict"),
        ("is it legit", "verdict"),
        ("Why?", "why"),
        ("What are the red flags", "why"),
        ("What should I do?", "action"),
        ("Should I click the link?", "action"),
        ("Is the link safe?", "links"),
        ("who sent this", "sender"),
        ("Is the sender legit?", "sender"),
        ("what does SPF fail mean", "auth"),
        ("explain the score", "score"),
        ("Why did it get this rating?", "why"),
        ("why is the score so high", "why"),
        ("which MITRE controls", "frameworks"),
        ("is the attachment dangerous", "attachments"),
        ("hello", "help"),
        ("tell me about this", "general"),
        ("What's a good pasta recipe?", None),
        ("Who won the game last night", None),
        ("write me a poem", None),
    ],
)
def test_classify(question, intent):
    assert classify(question) == intent


def test_off_topic_is_refused_with_the_fixed_redirect():
    result = answer(_facts(), "What's a good pasta recipe?")
    assert result.refused and result.answer == OFF_TOPIC_REDIRECT


@pytest.mark.parametrize("verdict,score", [("malicious", 88), ("suspicious", 40), ("clean", 5)])
def test_every_on_topic_answer_states_the_real_verdict(verdict, score):
    facts = _facts(verdict, score, indicators=[] if verdict == "clean" else None)
    for q in ("Is this phishing?", "Why?", "explain the score", "who sent this", "Is the link safe?",
              "what does SPF mean", "tell me about this", "hello"):
        result = answer(facts, q)
        assert not result.refused
        assert verdict in result.answer and f"{score}" in result.answer, (q, result.answer)


def test_suspicious_says_it_is_uncertain():
    assert "not certain" in answer(_facts("suspicious", 40), "is it phishing?").answer


def test_clean_is_not_presented_as_a_guarantee():
    text = answer(_facts("clean", 5, indicators=[]), "is it safe?").answer
    assert "not a guarantee" in text


def test_action_advice_per_verdict():
    assert "Don't click" in answer(_facts("malicious"), "what should I do").answer
    assert "Verify with the sender" in answer(_facts("suspicious", 40), "what should I do").answer
    assert "Nothing suggests" in answer(_facts("clean", 5, indicators=[]), "what should I do").answer


def test_sender_answer_flags_reply_to_mismatch():
    text = answer(_facts(), "who sent this?").answer
    assert "x@secure-mailer.net" in text and "Look-alike domain" in text


def test_why_lists_findings_strongest_first():
    text = answer(_facts(), "why?").answer
    assert text.index("Look-alike domain") < text.index("SPF failed")


def test_sender_answer_includes_cordons_history_with_the_sender():
    text = answer(_facts(sender_baseline="First contact: no baseline for this sender yet."), "who sent this?").answer
    assert "Cordon's history with this sender: First contact: no baseline" in text
    assert "history" not in answer(_facts(), "who sent this?").answer
