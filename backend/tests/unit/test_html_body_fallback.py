"""HTML-only email: the text rules must see the HTML part's text (they used to see an empty
body_text, so a payment-change email scored 8/Safe). Mail that has a plain-text part must be
untouched: the expected values below were pinned from the code before the fallback existed."""

from __future__ import annotations

from email.message import EmailMessage

from app.indicators.engine import run_indicators
from app.models.schemas import Verdict
from app.parsing.eml_parser import html_to_text, parse_eml
from app.scoring.risk_engine import fuse

AUTH = "mx; spf=pass smtp.mailfrom=x; dkim=pass header.d=x; dmarc=pass"

PAYMENT_HTML = (
    "<html><head><style>.x{color:#333}</style></head><body>"
    "<p>Hello,</p><p>Please process the payment for the outstanding invoice to our new bank account "
    "details below. This is urgent, kindly process it as soon as possible.</p>"
    "<table><tr><td>Bank:</td><td>First Example Bank</td></tr></table><p>Regards,<br>Billing</p></body></html>"
)
PLAIN_TEXT = (
    "Hi Sam,\n\nOur records show an outstanding invoice for October. Please arrange the wire transfer "
    "as soon as possible. Details: https://portal.northwind-supplies.com/invoices/4471\n\nThanks,\nDana"
)


def _eml(sender, subject, *, text=None, html=None) -> bytes:
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "ap@example.com"
    m["Subject"] = subject
    m["Date"] = "Tue, 24 Nov 2026 10:00:00 +0000"
    m["Authentication-Results"] = AUTH
    if text is not None:
        m.set_content(text)
        if html is not None:
            m.add_alternative(html, subtype="html")
    else:
        m.set_content(html, subtype="html")
    return bytes(m)


def _run(raw):
    parsed = parse_eml(raw)
    inds = run_indicators(parsed)
    score, verdict = fuse(inds)
    return parsed, sorted((i.id, i.score) for i in inds), score, verdict


def test_html_only_payment_change_now_flags():
    parsed, inds, score, verdict = _run(
        _eml("Billing <billing@partner-logistics.com>", "Updated bank details for invoice 4471", html=PAYMENT_HTML)
    )
    assert "process the payment for the outstanding invoice" in parsed.body_text
    ids = {i for i, _ in inds}
    assert {"PAYMENT_REQUEST", "URGENCY_LANGUAGE"} <= ids
    assert verdict != Verdict.SAFE  # was 8 / Safe before the fallback
    assert (score, verdict) == (65, Verdict.MALICIOUS)


def test_plain_text_email_scores_exactly_as_before():
    parsed, inds, score, verdict = _run(_eml("Dana <dana@northwind-supplies.com>", "October invoice", text=PLAIN_TEXT))
    assert parsed.body_text.strip() == PLAIN_TEXT
    # Pinned from the parser before the HTML fallback was added.
    assert (score, verdict) == (61, Verdict.MALICIOUS)
    assert inds == [("FIRST_CONTACT_SENDER", 8.0), ("PAYMENT_REQUEST", 30.0),
                    ("UNKNOWN_VENDOR_CLAIM", 19.0), ("URGENCY_LANGUAGE", 4.0)]


def test_text_part_wins_when_both_parts_exist():
    html = "<p>Please process the payment urgently, wire transfer as soon as possible.</p>"
    parsed, _, _, _ = _run(_eml("a@example.com", "hi", text="See you at lunch.", html=html))
    assert parsed.body_text.strip() == "See you at lunch."


def test_anchor_text_does_not_become_a_phantom_link():
    html = '<p>Verify now: <a href="https://login-paypa1.top/verify">https://www.paypal.com/verify</a></p>'
    parsed, _, _, _ = _run(_eml("a@example.com", "hi", html=html))
    assert [l.href for l in parsed.links] == ["https://login-paypa1.top/verify"]
    assert "https://www.paypal.com/verify" in parsed.body_text  # the reader-visible text is scored


def test_html_to_text_drops_script_style_and_decodes_entities():
    text = html_to_text(
        "<html><head><title>T</title><style>p{}</style></head><body><p>Pay&nbsp;now &amp; quickly</p>"
        "<script>ignore()</script><div>line two<br>line three</div></body></html>"
    )
    assert text == "Pay now & quickly\nline two\nline three"


def test_html_to_text_survives_malformed_html():
    assert html_to_text("<p>unclosed <b>bold <div><<<>>> text") .startswith("unclosed")
    assert html_to_text("") == ""
