"""LLM-free assistant answers, built only from app.assistant.facts.EmailFacts.

Three jobs, mirroring app.copilot.intent's role for the copilot:
- answer the common questions (is it phishing, why, the score, what to do, the sender, the
  links, attachments, SPF/DKIM/DMARC, frameworks) with no LLM at all;
- redirect clearly off-topic questions (refused=True) instead of freelancing;
- be the fallback whenever the LLM is off, fails, or its answer is discarded by
  app.assistant.llm's validation.

Conservative on purpose: the matcher is plain keyword rules, and anything unrecognized that
still sounds like it's about the email gets the general summary plus what you can ask.
Pure: no DB, no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.assistant.facts import EmailFacts, auth_line
from app.scoring.risk_engine import SAFE_MAX, SUSPICIOUS_MAX

OFF_TOPIC_REDIRECT = (
    "I can only help with this email and email security: whether it's phishing, why Cordon "
    "rated it the way it did, whether the sender, links or attachments look safe, what the "
    "score means, or what you should do next."
)

_MAX_REASONS = 5


@dataclass(frozen=True)
class AssistantAnswer:
    answer: str
    refused: bool = False


def _normalize(question: str) -> str:
    return " ".join(question.lower().replace("’", "'").split())


# Checked in order; the first match wins.
_INTENTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "action",
        re.compile(
            r"\bwhat (?:should|do|can) i do\b|\bshould i (?:click|open|reply|respond|delete|report|"
            r"pay|download|trust|ignore|forward|block)\b|\bnext steps?\b|\bhow (?:do|should) i "
            r"(?:report|handle|deal)\b|\bwhat now\b|\brecommend"
        ),
    ),
    ("auth", re.compile(r"\bspf\b|\bdkim\b|\bdmarc\b|\bauthenticat|\bspoof")),
    ("links", re.compile(r"\blinks?\b|\burls?\b|\bclick|\bwebsite|\bhref\b")),
    ("attachments", re.compile(r"\battach|\bfiles?\b|\bdownload|\bpdf\b|\bdocument\b")),
    ("sender", re.compile(r"\bsender\b|\bwho sent\b|\bfrom\b|\breply[- ]to\b|\bdomain\b|\bsent this\b")),
    # An explicit "why" asks for the reasons even when it mentions the rating/score
    # ("Why did it get this rating?"); "explain the score" still goes to "score".
    ("why", re.compile(r"\bwhy\b")),
    ("score", re.compile(r"\bscore\b|\bpoints?\b|\brating\b|\brated\b|\b\d{1,3} ?/ ?100\b")),
    ("frameworks", re.compile(r"\bmitre\b|\bnist\b|\biso\b|\bsoc ?2\b|\bframeworks?\b|\bcontrols?\b|\bcomplian")),
    (
        "why",
        re.compile(
            r"\bwhy\b|\bexplain|\breasons?\b|\bwhat(?:'s| is) wrong\b|\bwhat makes\b|\bhow do you know\b"
            r"|\bindicators?\b|\bred flags?\b|\bevidence\b|\bfindings?\b|\bflag(?:ged)?\b"
        ),
    ),
    (
        "verdict",
        re.compile(
            r"\bphish|\bscam|\bsafe\b|\blegit|\btrust|\breal\b|\bgenuine\b|\bfake\b|\bmalicious\b"
            r"|\bsuspicious\b|\bspam\b|\bfraud|\bdanger|\bok(?:ay)? to\b|\bsecure\b|\brisk"
        ),
    ),
    ("help", re.compile(r"^(?:hi|hello|hey|help|thanks|thank you)\b|\bwhat can you\b|\bwho are you\b")),
)

# Email/security vocabulary: an unrecognized question that mentions any of these still gets
# the general summary rather than a refusal.
_ON_TOPIC_RE = re.compile(
    r"\bemails?\b|\bmessages?\b|\bmail\b|\binbox\b|\bsecurity\b|\bthreat|\battack|\bhack"
    r"|\bpassword|\bcredential|\baccount\b|\binvoice|\bpayment|\bwire\b|\bverdict\b|\bcordon\b"
    # "Is this ok?", "tell me about this": in a pane attached to one email, "this" is it.
    r"|\bthis\b"
)


def classify(question: str) -> str | None:
    text = _normalize(question)
    for name, pattern in _INTENTS:
        if pattern.search(text):
            return name
    if _ON_TOPIC_RE.search(text):
        return "general"
    return None


def _reasons(facts: EmailFacts, limit: int = _MAX_REASONS) -> str:
    return "; ".join(i.title for i in facts.indicators[:limit])


def _with_category(facts: EmailFacts, categories: set[str]) -> list:
    return [i for i in facts.indicators if i.category in categories]


def _verdict(facts: EmailFacts) -> str:
    if facts.verdict == "malicious":
        return (
            f"Cordon rates this email malicious (risk score {facts.score}/100). Treat it as "
            f"phishing: don't click its links, open its attachments, or reply. Main reasons: "
            f"{_reasons(facts)}."
        )
    if facts.verdict == "suspicious":
        return (
            f"Cordon rates this email suspicious (risk score {facts.score}/100). That's not "
            f"certain either way: it shows warning signs ({_reasons(facts)}), but not enough to "
            "call it malicious. Verify it with the sender through a channel you already trust "
            "before acting on it."
        )
    found = (
        "found no phishing indicators"
        if not facts.indicators
        else f"found {len(facts.indicators)} minor finding(s), not enough to flag it ({_reasons(facts, 3)})"
    )
    return (
        f"Cordon rates this email clean (risk score {facts.score}/100): it {found}. Clean means "
        "no known phishing signs, not a guarantee. If it unexpectedly asks for a password, "
        "payment or personal details, verify it first."
    )


def _why(facts: EmailFacts) -> str:
    if not facts.indicators:
        return (
            f"Cordon found no phishing indicators in this email, so it's rated {facts.verdict} "
            f"({facts.score}/100). Sender authentication: {auth_line(facts)}."
        )
    lines = [f"- {i.title}: {i.description}" for i in facts.indicators[:_MAX_REASONS]]
    return (
        f"This email is rated {facts.verdict} ({facts.score}/100) because of these findings, "
        "strongest first:\n" + "\n".join(lines)
    )


def _score(facts: EmailFacts) -> str:
    return (
        f"The risk score is {facts.score}/100. Cordon's bands: 0–{SAFE_MAX} clean, "
        f"{SAFE_MAX + 1}–{SUSPICIOUS_MAX} suspicious, {SUSPICIOUS_MAX + 1}–100 malicious, so "
        f"this email is {facts.verdict}. The score is built from the findings Cordon "
        "detected, each adding points by severity"
        + (f": {_reasons(facts)}." if facts.indicators else "; none were triggered here.")
    )


def _action(facts: EmailFacts) -> str:
    if facts.verdict == "malicious":
        return (
            "Don't click any links, open attachments, reply, or enter any information. Report "
            "it to your IT/security team (or use Outlook's Report phishing option), then delete "
            "it. If you already clicked a link or entered a password, change that password now "
            "and tell your security team."
        )
    if facts.verdict == "suspicious":
        return (
            "Hold off on acting on it. Verify with the sender through a channel you already "
            "trust (a known phone number or a new email to an address you know, not by replying), "
            "and don't click links or open attachments until you have. If it can't be verified, "
            "report it to your IT/security team."
        )
    return (
        "Nothing suggests you need to do anything special: Cordon found no phishing signs. "
        "Stay alert if it asks for credentials, payment or urgent action you didn't expect."
    )


def _sender(facts: EmailFacts) -> str:
    who = facts.from_address or "an unknown address"
    if facts.from_display:
        who = f'"{facts.from_display}" <{who}>'
    parts = [f"It's from {who}."]
    if facts.reply_to_address and facts.reply_to_address != facts.from_address:
        parts.append(f"Replies would go to a different address: {facts.reply_to_address}.")
    parts.append(f"Sender authentication: {auth_line(facts)}.")
    if facts.sender_baseline:
        parts.append(f"Cordon's history with this sender: {facts.sender_baseline}")
    related = _with_category(facts, {"sender", "domain", "authentication"})
    if related:
        parts.append("Cordon's sender findings: " + "; ".join(i.title for i in related) + ".")
    else:
        parts.append("Cordon found no sender-related issues.")
    parts.append(f"Overall verdict: {facts.verdict} ({facts.score}/100).")
    return " ".join(parts)


def _links(facts: EmailFacts) -> str:
    if not facts.link_domains:
        return f"This email has no links. Overall verdict: {facts.verdict} ({facts.score}/100)."
    parts = ["It links to: " + ", ".join(facts.link_domains) + "."]
    related = _with_category(facts, {"link"})
    if related:
        parts.append("Cordon's link findings: " + "; ".join(i.title for i in related) + ". Don't click them.")
    else:
        parts.append("Cordon found no link-specific issues, which isn't a guarantee a site is safe.")
    parts.append(f"Overall verdict: {facts.verdict} ({facts.score}/100).")
    return " ".join(parts)


def _attachments(facts: EmailFacts) -> str:
    if not facts.attachment_names:
        return f"This email has no attachments. Overall verdict: {facts.verdict} ({facts.score}/100)."
    parts = ["Attachments: " + ", ".join(facts.attachment_names) + "."]
    related = _with_category(facts, {"attachment"})
    if related:
        parts.append("Cordon's attachment findings: " + "; ".join(i.title for i in related) + ". Don't open them.")
    else:
        parts.append(
            "Cordon found no attachment-specific issues. It checks file types and names, not "
            "the file contents, so only open them if you expected them."
        )
    parts.append(f"Overall verdict: {facts.verdict} ({facts.score}/100).")
    return " ".join(parts)


def _auth(facts: EmailFacts) -> str:
    return (
        f"{auth_line(facts)}, as recorded by the receiving mail server. SPF checks the sending "
        "server was allowed to send for the domain, DKIM checks the message was signed by the "
        "domain and not altered, and DMARC checks those line up with the visible From domain. "
        "A fail means the email may not really come from who it claims; 'none' means there "
        f"was no usable result. Overall verdict: {facts.verdict} ({facts.score}/100)."
    )


def _frameworks(facts: EmailFacts) -> str:
    if not facts.frameworks:
        return "No compliance-framework controls were mapped for this email's findings."
    return (
        "Cordon maps this email's findings to these controls: " + ", ".join(facts.frameworks)
        + ". They show which security controls the threat relates to, for audit and reporting."
    )


def _help(facts: EmailFacts) -> str:
    return (
        f"I'm Cordon's assistant for this email. It's rated {facts.verdict} ({facts.score}/100). "
        "Ask me whether it's phishing, why it got this rating, whether the sender, links or "
        "attachments look safe, what the score means, or what you should do."
    )


def _general(facts: EmailFacts) -> str:
    return (
        _verdict(facts)
        + " You can ask why, about the sender, links or attachments, or what to do next."
    )


_ANSWERS = {
    "verdict": _verdict,
    "why": _why,
    "score": _score,
    "action": _action,
    "sender": _sender,
    "links": _links,
    "attachments": _attachments,
    "auth": _auth,
    "frameworks": _frameworks,
    "help": _help,
    "general": _general,
}


def answer(facts: EmailFacts, question: str) -> AssistantAnswer:
    intent = classify(question)
    if intent is None:
        return AssistantAnswer(answer=OFF_TOPIC_REDIRECT, refused=True)
    return AssistantAnswer(answer=_ANSWERS[intent](facts))
