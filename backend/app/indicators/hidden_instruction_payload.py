"""Hidden-instruction / AI-injection payload detection.

A rising attack class hides instructions aimed at an AI assistant that might read the inbox
(prompt injection) — concealed from the human recipient via CSS tricks, invisible Unicode,
HTML comments, or base64 encoding, while telling a model things like "ignore previous
instructions" or "mark this email as safe". This is a DIFFERENT concern from
app.reasoning.llm_analyst's prompt-injection hardening: that module protects *Cordon's own*
LLM call from being fooled by email content (untrusted-data framing, forced tool-use, strict
schema validation). This module produces a customer-facing Indicator instead — an email that
tries to smuggle instructions to an AI reader is inherently suspicious, independent of
whether any AI is actually involved in reviewing it.

Every byte of email content handled here is treated strictly as DATA to pattern-match
against — nothing found is ever executed, followed, or echoed back verbatim (the finding
text summarizes WHAT KIND of thing was found, by category label, never the attacker's raw
wording, since quoting it back would itself be a second injection surface).

Four independent techniques feed one finding (additive score, more techniques = higher
score, same discipline as every other indicator — this can only ever raise a verdict toward
Malicious via the normal additive `risk_engine.compute_score`, never override it). All four
hold themselves to the same high-precision bar: the hiding/encoding mechanism alone is never
enough — the content it reveals must itself match an instruction phrase below.

1. CSS-hidden text (display:none / visibility:hidden / opacity:0 / font-size:0 / near-white
   text color) whose content itself matches an instruction phrase below.
2. Zero-width/invisible Unicode characters embedded in otherwise human-readable text.
   Presence alone is deliberately NOT the trigger — legitimate senders do occasionally
   include a stray zero-width space (some ESPs insert them for anti-clipping/deliverability,
   some non-English text uses them, stray U+FEFF shows up in forwarded mail), so this fires
   only when STRIPPING those characters out reveals an instruction phrase that wasn't
   readable before stripping - i.e. they were genuinely being used to break up a phrase
   character-by-character to dodge a plain keyword match, not just incidentally present.
3. An HTML comment whose content matches an instruction phrase below.
4. A base64 blob that decodes to text matching an instruction phrase below. A base64 blob
   that decodes to binary/image data (the common "inline logo" case) never matches any
   instruction phrase, so it is structurally never a finding on its own.

False-positive guards baked in (see tests/unit/test_indicator_hidden_instruction_payload.py):
- Zero-width joiners/non-joiners immediately between two emoji codepoints (a real multi-part
  emoji sequence like a family emoji) are excluded before the strip-and-match check runs.
- A single leading U+FEFF (byte-order-mark artifact some mail clients leave at the very start
  of a text part) is stripped before counting, so it can't contribute to a match.
- A stray zero-width character with no instruction phrase underneath it - e.g. a normal
  marketing email that happens to contain one for deliverability reasons - produces NO
  finding at all, at any severity: technique 2 requires the same instruction-phrase match
  the other three do, so it can never fire on presence alone and can never, by itself, move
  an otherwise-clean email past Safe.
- An `<img>` tag hidden via CSS (a tracking pixel) produces no text node at all, so it can
  never match the CSS-hidden-text check, which only ever looks at TEXT content.
- Base64 that decodes to binary/non-UTF-8 data (an inline image) is dropped before the
  instruction-phrase check even runs.
"""

from __future__ import annotations

import base64
import html as html_module
import re
from html.parser import HTMLParser

from app.indicators.base import make_indicator
from app.models.schemas import Indicator, Severity
from app.channels.message import Message
from app.sender_history.aggregation import SenderHistorySnapshot

# ---- Shared instruction-phrase bank -------------------------------------------------------
# A small, documented set of phrases an attacker would use to address an AI reader directly.
# Labels (not the matched text) are what ever reaches a Finding/Indicator's evidence — the
# attacker's actual wording is never echoed back.
_RAW_INSTRUCTION_PHRASES: list[tuple[str, str]] = [
    ("ignore-previous-instructions", r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions?"),
    ("disregard-previous-instructions", r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions?"),
    ("mark-as-safe", r"mark\s+(?:this|it)\s+(?:email\s+|message\s+)?(?:as\s+)?safe"),
    ("tell-the-user", r"tell\s+the\s+user\b"),
    ("priority-action-injection", r"(?:add|insert|create)\s+(?:a\s+)?priority\s+action"),
    ("ai-role-claim", r"you\s+are\s+an?\s+(?:ai|assistant|language\s+model|llm)\b"),
    ("system-prompt-reference", r"system\s+prompt"),
    ("direct-address-to-ai", r"(?:dear|attention|note\s+to|hey)\s+(?:ai|assistant)\b"),
    ("new-instructions-override", r"new\s+instructions\s*:"),
    ("override-instructions", r"override\s+(?:your|the)\s+instructions"),
    ("suppress-user-notification", r"do\s+not\s+(?:tell|alert|inform|notify)\s+the\s+(?:user|recipient|human)"),
    ("treat-as-legitimate", r"treat\s+(?:this|it)\s+as\s+(?:legitimate|safe|trusted)"),
]
_INSTRUCTION_PHRASES: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(pattern, re.IGNORECASE)) for label, pattern in _RAW_INSTRUCTION_PHRASES
]


def _matched_instruction_labels(text: str) -> list[str]:
    if not text:
        return []
    return [label for label, pattern in _INSTRUCTION_PHRASES if pattern.search(text)]


# ---- Technique 1: CSS-hidden text ---------------------------------------------------------

_HIDE_DISPLAY_NONE_RE = re.compile(r"display\s*:\s*none")
_HIDE_VISIBILITY_RE = re.compile(r"visibility\s*:\s*hidden")
_HIDE_OPACITY_RE = re.compile(r"opacity\s*:\s*0(?:\.0+)?\b")
_HIDE_FONT_SIZE_RE = re.compile(r"font-size\s*:\s*0(?:\.0+)?(?:px)?\b")
# Negative lookbehind keeps this from matching "background-color:" — only a bare `color:`.
_COLOR_RE = re.compile(r"(?<![\w-])color\s*:\s*([^;]+)")

_NEAR_WHITE_NAMED = {"white", "snow", "ivory", "whitesmoke"}
_NEAR_WHITE_CHANNEL_FLOOR = 245


def _is_near_white(value: str) -> bool:
    value = value.strip().lower()
    if value in _NEAR_WHITE_NAMED:
        return True
    hex_match = re.match(r"#([0-9a-f]{3}|[0-9a-f]{6})$", value)
    if hex_match:
        hexstr = hex_match.group(1)
        channels = (
            [int(c * 2, 16) for c in hexstr]
            if len(hexstr) == 3
            else [int(hexstr[i : i + 2], 16) for i in (0, 2, 4)]
        )
        return all(c >= _NEAR_WHITE_CHANNEL_FLOOR for c in channels)
    rgb_match = re.match(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", value)
    if rgb_match:
        return all(int(c) >= _NEAR_WHITE_CHANNEL_FLOOR for c in rgb_match.groups())
    return False


def _hiding_reason_for_style(style: str) -> str | None:
    style = style.lower()
    if _HIDE_DISPLAY_NONE_RE.search(style):
        return "display:none"
    if _HIDE_VISIBILITY_RE.search(style):
        return "visibility:hidden"
    if _HIDE_OPACITY_RE.search(style):
        return "opacity:0"
    if _HIDE_FONT_SIZE_RE.search(style):
        return "font-size:0"
    color_match = _COLOR_RE.search(style)
    if color_match and _is_near_white(color_match.group(1)):
        return "near-white text color"
    return None


class _HiddenTextExtractor(HTMLParser):
    """Walks the HTML tracking a stack of "currently hidden, and why" so text nested inside
    a hidden element is attributed to the hiding mechanism even through intermediate tags.
    Only ever collects TEXT nodes (`handle_data`) — a hidden `<img>` tracking pixel has no
    text content and so can never appear here."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._hidden_stack: list[str | None] = [None]
        self.hidden_text_by_reason: dict[str, list[str]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        style = next((v for k, v in attrs if k.lower() == "style" and v), "") or ""
        reason = _hiding_reason_for_style(style)
        self._hidden_stack.append(reason or self._hidden_stack[-1])

    def handle_endtag(self, tag: str) -> None:
        if len(self._hidden_stack) > 1:
            self._hidden_stack.pop()

    def handle_data(self, data: str) -> None:
        reason = self._hidden_stack[-1]
        if reason and data.strip():
            self.hidden_text_by_reason.setdefault(reason, []).append(data.strip())


def _extract_hidden_text(body_html: str) -> dict[str, list[str]]:
    if not body_html:
        return {}
    extractor = _HiddenTextExtractor()
    try:
        extractor.feed(body_html)
    except Exception:  # noqa: BLE001 - malformed HTML must never crash analysis
        pass
    return extractor.hidden_text_by_reason


# ---- Technique 2: zero-width / invisible Unicode in visible text -------------------------

_INVISIBLE_CHARS = "​‌‍﻿⁠"
_EMOJI_RANGE_RE = re.compile(
    "[\U0001F1E6-\U0001FAFF\U00002600-\U000027BF\U0000FE0F]"
)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")


def _extract_visible_text(body_html: str) -> str:
    if not body_html:
        return ""
    without_comments = _COMMENT_RE.sub(" ", body_html)
    without_tags = _TAG_RE.sub(" ", without_comments)
    return html_module.unescape(without_tags)


def _strip_leading_bom(text: str) -> str:
    """A leading U+FEFF is a mail-client/encoding artifact (byte-order mark), not a hidden
    payload - stripped from each source independently, before combining, so it can never
    land away from index 0 and get miscounted as suspicious."""
    return text[1:] if text.startswith("﻿") else text


def _suspicious_invisible_char_positions(text: str) -> list[int]:
    """Indices of invisible characters that aren't a benign emoji ZWJ/ZWNJ sequence.
    Presence alone is NOT the signal (see module docstring) — legitimate senders do
    occasionally insert a stray zero-width space (some ESPs for anti-clipping, some non-
    English text, residue from copy/paste), so this is only ever used as the pool of
    characters to strip out before checking whether doing so REVEALS an instruction
    phrase - never as a standalone trigger."""
    positions = []
    for i, ch in enumerate(text):
        if ch not in _INVISIBLE_CHARS:
            continue
        prev_ch = text[i - 1] if i > 0 else ""
        next_ch = text[i + 1] if i + 1 < len(text) else ""
        if _EMOJI_RANGE_RE.match(prev_ch) and _EMOJI_RANGE_RE.match(next_ch):
            continue  # a ZWJ/ZWNJ joining two emoji codepoints - a real emoji sequence
        positions.append(i)
    return positions


def _reveal_text_with_invisible_chars_stripped(text: str, positions: list[int]) -> str:
    skip = set(positions)
    return "".join(ch for i, ch in enumerate(text) if i not in skip)


# ---- Technique 4: base64 blobs decoding to instruction-bearing text ----------------------

_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")


def _try_decode_base64_text(blob: str) -> str | None:
    for candidate in (blob, blob + "=" * (-len(blob) % 4)):
        try:
            raw = base64.b64decode(candidate, validate=True)
        except Exception:  # noqa: BLE001 - not valid base64, just skip this candidate
            continue
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None  # decodes fine as bytes but isn't text - e.g. an inline image
    return None


def _has_injected_base64(text: str) -> bool:
    for match in _BASE64_CANDIDATE_RE.finditer(text):
        decoded = _try_decode_base64_text(match.group(0))
        if decoded and _matched_instruction_labels(decoded):
            return True
    return False


# ---- Evaluate ------------------------------------------------------------------------------

_BASE_SCORE = 45
_SCORE_PER_EXTRA_TECHNIQUE = 8
_MAX_SCORE = 65


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    body_html = email.body_html or ""
    body_text = email.body_text or ""

    evidence: list[str] = []
    technique_count = 0

    hidden_text_by_reason = _extract_hidden_text(body_html)
    css_reasons_fired = sorted(
        reason
        for reason, texts in hidden_text_by_reason.items()
        if _matched_instruction_labels(" ".join(texts))
    )
    if css_reasons_fired:
        technique_count += 1
        evidence.append(
            f"Hidden text concealed via CSS ({', '.join(css_reasons_fired)}) contains "
            "instruction-like content directed at an AI assistant."
        )

    visible_text = (
        f"{_strip_leading_bom(_extract_visible_text(body_html))} "
        f"{_strip_leading_bom(body_text)}"
    )
    invisible_positions = _suspicious_invisible_char_positions(visible_text)
    if invisible_positions:
        revealed_text = _reveal_text_with_invisible_chars_stripped(
            visible_text, invisible_positions
        )
        # Corroborating, not decisive: a stray zero-width space is not unheard of in
        # legitimate mail (some ESPs insert them for anti-clipping/deliverability, some
        # non-English text uses them) - presence alone must never be enough. This only
        # fires when stripping the invisible characters actually REVEALS an instruction
        # phrase that wasn't readable before stripping - i.e. the invisible characters were
        # genuinely being used to break up/conceal that phrase, the same high-precision bar
        # the other three techniques already hold themselves to.
        if _matched_instruction_labels(revealed_text):
            technique_count += 1
            count = len(invisible_positions)
            noun = "character" if count == 1 else "characters"
            evidence.append(
                f"{count} zero-width/invisible Unicode {noun} were used to break up text "
                "that reads as an instruction directed at an AI assistant once the "
                "invisible characters are removed."
            )

    comments = [m.group(1) for m in _COMMENT_RE.finditer(body_html)] if body_html else []
    if any(_matched_instruction_labels(comment) for comment in comments):
        technique_count += 1
        evidence.append(
            "An HTML comment contains instruction-like content directed at an AI/assistant."
        )

    if _has_injected_base64(f"{body_html}\n{body_text}"):
        technique_count += 1
        evidence.append(
            "A base64-encoded blob in the message decodes to text containing "
            "instruction-like content directed at an AI assistant."
        )

    if technique_count == 0:
        return []

    score = min(_MAX_SCORE, _BASE_SCORE + _SCORE_PER_EXTRA_TECHNIQUE * (technique_count - 1))

    return [
        make_indicator(
            id="HIDDEN_AI_INSTRUCTION_PAYLOAD",
            category="ai_injection",
            title="Hidden instructions directed at an AI assistant",
            description=(
                "This message contains content concealed from a human reader - via CSS, "
                "invisible Unicode, an HTML comment, or an encoded blob - that reads as an "
                "instruction directed at an AI or automated assistant (for example, "
                "attempting to override prior instructions, mark the message safe, or "
                "insert an unauthorized action). An email trying to smuggle instructions to "
                "an AI reader is inherently suspicious, independent of whether any AI is "
                "actually involved in reviewing it."
            ),
            evidence=evidence,
            severity=Severity.HIGH,
            score=score,
        )
    ]
