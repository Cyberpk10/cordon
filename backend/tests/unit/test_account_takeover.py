"""Account-takeover detection (app.indicators.account_takeover + app.sender_baseline): fires only
for an established, authenticating sender showing a real anomaly AND making a sensitive ask.

IPs are real addresses the bundled offline geo snapshot resolves: 8.8.8.8 -> United States,
105.112.0.1 -> Nigeria, 81.2.69.142 -> United Kingdom, 40.107.22.91 -> Netherlands.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.geo.countries import COUNTRY_NAMES
from app.indicators import account_takeover
from app.indicators.engine import run_indicators
from app.parsing.eml_parser import parse_eml
from app.scoring.risk_engine import fuse
from app.models.schemas import Verdict
from app.sender_baseline.aggregation import ObservationRow, build_baseline, summary_line
from app.sender_baseline.signals import authenticates_as_sender, extract_signals
from app.sender_history.aggregation import SenderHistorySnapshot, build_sender_history

SENDER = "ap@acme-supplies.com"
US, NG, GB = "8.8.8.8", "105.112.0.1", "81.2.69.142"
NOW = datetime(2026, 11, 10, 12, 0, 0)

PAYMENT_CHANGE = (
    "Hi, please note we have moved banks. Kindly update your records with our new bank account "
    "details below before you pay this month's invoice. Thanks, Accounts"
)
BENIGN = "Hi! I'm at the trade show in Lagos this week. I'll send the meeting notes when I'm back. Thanks"


def _eml(
    *,
    sender: str = SENDER,
    body: str = BENIGN,
    origin_ip: str | None = US,
    spf_ip: str | None = None,
    auth: str = "pass",
    reply_to: str | None = None,
    return_path: str | None = None,
    date: str = "Tue, 10 Nov 2026 15:00:00 +0000",
    subject: str = "Hello",
    link: str | None = None,
):
    domain = sender.rsplit("@", 1)[1]
    smtp = f" smtp.mailfrom={domain}" + (f" (client-ip={spf_ip})" if spf_ip else "")
    lines = [
        f"Return-Path: <{return_path or 'bounce@' + domain}>",
        f"Received: from mail.{domain} (mail.{domain} [{spf_ip or US}]) by mx.example.com with ESMTPS; {date}",
        f"Authentication-Results: mx.example.com; spf={auth}{smtp}; dkim={auth} header.d={domain}; "
        f"dmarc={auth} header.from={domain}",
        f"From: Accounts <{sender}>",
        "To: me@example.com",
        f"Subject: {subject}",
        f"Date: {date}",
        "Message-ID: <x@acme>",
    ]
    if origin_ip:
        lines.append(f"X-Originating-IP: [{origin_ip}]")
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    text = body + (f"\n{link}" if link else "")
    lines += ['Content-Type: text/plain; charset="utf-8"', "", text]
    return parse_eml("\r\n".join(lines).encode())


def _row(days_ago: float, *, country="US", source="originating", provider="acme-supplies.com",
         hour=15, auth=True, verdict="safe", reply_to=None, return_path="acme-supplies.com"):
    return ObservationRow(
        observed_at=NOW - timedelta(days=days_ago), message_hour_utc=hour, sending_country=country,
        country_source=source, sending_provider=provider, reply_to_domain=reply_to,
        return_path_domain=return_path, auth_pass=auth, verdict=verdict,
    )


def _established(n: int = 5, **kw):
    return [_row(30 - i * 5, hour=13 + (i % 4), **kw) for i in range(n)]


def _snapshot(rows, *, sender=SENDER, account_domains=frozenset(), cases=()):
    return SenderHistorySnapshot(
        domains=build_sender_history(list(cases)).domains if cases else {},
        sender_baseline=build_baseline(sender, rows),
        account_domains=frozenset(account_domains),
    )


def _ids(email, snapshot):
    return {i.id for i in run_indicators(email, snapshot)}


ATO_IDS = {account_takeover.EXTERNAL_ID, account_takeover.LATERAL_ID}


# ---- the required scenarios ------------------------------------------------------------------


def test_established_sender_new_country_payment_change_fires_with_grounded_explanation():
    email = _eml(origin_ip=NG, body=PAYMENT_CHANGE)
    indicators = run_indicators(email, _snapshot(_established()))
    ato = [i for i in indicators if i.id == account_takeover.EXTERNAL_ID]
    assert len(ato) == 1
    text = ato[0].description
    assert "Known sender ap@acme-supplies.com" in text
    assert "5 prior messages" in text and "normally from United States" in text
    assert "was sent from Nigeria" in text and NG in text
    assert "change payment or bank details" in text
    assert text.endswith("consistent with a compromised account.")
    assert any("New sending country: Nigeria" in e for e in ato[0].evidence)
    assert ato[0].score == account_takeover.EXTERNAL_SCORE


@pytest.mark.parametrize(
    "body",
    [
        BENIGN,
        "URGENT: can you look at the agenda before tomorrow? Thanks",  # one pressure phrase, no link
    ],
)
def test_traveller_new_country_with_benign_content_does_not_fire(body):
    email = _eml(origin_ip=NG, body=body)
    snapshot = _snapshot(_established())
    indicators = run_indicators(email, snapshot)
    assert not ({i.id for i in indicators} & ATO_IDS)
    assert account_takeover.assess(email, snapshot) is None
    # And the traveller stays clean overall: no false positive anywhere in the score.
    assert fuse(indicators)[1] == Verdict.SAFE


def test_first_contact_sender_never_raises_ato_and_says_so():
    email = _eml(origin_ip=NG, body=PAYMENT_CHANGE)
    snapshot = _snapshot([])
    assert not (_ids(email, snapshot) & ATO_IDS)
    assert snapshot.sender_baseline.status == "first_contact"
    assert summary_line(snapshot.sender_baseline, COUNTRY_NAMES.get) == "First contact: no baseline for this sender yet."
    # No account context at all: same.
    assert not (_ids(email, SenderHistorySnapshot()) & ATO_IDS)


def test_internal_compromised_colleague_is_labelled_lateral():
    email = _eml(origin_ip=NG, body=PAYMENT_CHANGE)
    snapshot = _snapshot(_established(), account_domains={"acme-supplies.com"})
    indicators = run_indicators(email, snapshot)
    lateral = [i for i in indicators if i.id == account_takeover.LATERAL_ID]
    assert len(lateral) == 1 and account_takeover.EXTERNAL_ID not in {i.id for i in indicators}
    assert lateral[0].title == "Internal phishing from a likely compromised colleague"
    assert lateral[0].description.startswith("Known colleague")
    assert "internal phishing" in lateral[0].description
    assert account_takeover.assess(email, snapshot).kind == "lateral"


def test_lookalike_impersonation_stays_with_phishing_logic_not_ato():
    # acme-supplies.com is an established correspondent (domain-level history from Cases),
    # and the exact address has a strong baseline. The look-alike address has none.
    cases = [(SENDER, NOW - timedelta(days=d)) for d in (20, 10, 2)]
    lookalike = "ap@acme-suppl1es.com"
    email = _eml(sender=lookalike, origin_ip=NG, body=PAYMENT_CHANGE)
    snapshot = _snapshot([], sender=lookalike, cases=cases)
    ids = _ids(email, snapshot)
    assert "LOOKALIKE_OF_KNOWN_SENDER" in ids
    assert not (ids & ATO_IDS)


# ---- guards against false positives ------------------------------------------------------------


def test_failed_authentication_is_spoofing_not_takeover():
    email = _eml(origin_ip=NG, body=PAYMENT_CHANGE, auth="fail")
    assert not (_ids(email, _snapshot(_established())) & ATO_IDS)


def test_sensitive_ask_without_any_anomaly_is_normal_business():
    email = _eml(origin_ip=US, body=PAYMENT_CHANGE)
    assert not (_ids(email, _snapshot(_established())) & ATO_IDS)


def test_below_threshold_is_building_and_never_fires():
    rows = _established(2)
    snapshot = _snapshot(rows)
    assert snapshot.sender_baseline.status == "building"
    assert not (_ids(_eml(origin_ip=NG, body=PAYMENT_CHANGE), snapshot) & ATO_IDS)
    assert summary_line(snapshot.sender_baseline, COUNTRY_NAMES.get).startswith("Building a baseline: 2 clean")


def test_all_in_one_burst_is_not_established():
    rows = [_row(1.0 + i / 1000) for i in range(6)]  # six messages within minutes
    assert build_baseline(SENDER, rows).status == "building"


def test_mostly_malicious_history_means_no_trusted_baseline():
    rows = _established(3) + [_row(3 - i * 0.1, country="NG", verdict="malicious") for i in range(3)]
    snapshot = _snapshot(rows)
    assert snapshot.sender_baseline.status == "flagged"
    assert not (_ids(_eml(origin_ip=NG, body=PAYMENT_CHANGE), snapshot) & ATO_IDS)
    assert "3 of them malicious" in summary_line(snapshot.sender_baseline, COUNTRY_NAMES.get)


def test_a_flagged_first_strike_does_not_hide_the_next_takeover_email():
    # Found in the live run: the attacker's first email was flagged malicious; their next one
    # from the same account must still be judged against the real (pre-takeover) baseline.
    rows = _established() + [_row(0.2, country="NG", verdict="malicious")]
    snapshot = _snapshot(rows)
    assert snapshot.sender_baseline.status == "established"
    assert "NG" not in snapshot.sender_baseline.countries["originating"]
    assert account_takeover.EXTERNAL_ID in _ids(_eml(reply_to="ap@acme-remit.net", body=PAYMENT_CHANGE), snapshot)
    assert "1 recent message(s) from this address were flagged malicious" in summary_line(
        snapshot.sender_baseline, COUNTRY_NAMES.get
    )


def test_unauthenticated_or_suspicious_history_cannot_whitelist_a_country():
    rows = _established() + [
        _row(3, country="NG", auth=False),
        _row(2, country="NG", verdict="suspicious"),
    ]
    baseline = build_baseline(SENDER, rows)
    assert baseline.status == "established" and "NG" not in baseline.countries["originating"]
    assert account_takeover.EXTERNAL_ID in _ids(_eml(origin_ip=NG, body=PAYMENT_CHANGE), _snapshot(rows))


def test_countries_are_only_compared_within_the_same_ip_source():
    # Baseline knows the client (originating) country; this message only has the provider's
    # server IP (Netherlands). Different source: no comparison, no anomaly, no finding.
    email = _eml(origin_ip=None, spf_ip="40.107.22.91", body=PAYMENT_CHANGE)
    assert extract_signals(email).country_source == "spf_client_ip"
    assert not (_ids(email, _snapshot(_established())) & ATO_IDS)


def test_known_country_after_travel_is_no_longer_new():
    # Two clean, authenticated sightings at least a day apart: the sender really is there.
    rows = _established() + [_row(4, country="GB"), _row(2, country="GB")]
    assert not (_ids(_eml(origin_ip=GB, body=PAYMENT_CHANGE), _snapshot(rows)) & ATO_IDS)


def test_one_harmless_email_from_a_new_country_does_not_whitelist_it():
    # Found in the live run: a hijacked account's usual first move is a harmless message,
    # then the payment request. One sighting (or two in the same burst) must not make the
    # attacker's country "normal".
    for extra in ([_row(0.5, country="NG")], [_row(0.5, country="NG"), _row(0.4, country="NG")]):
        rows = _established() + extra
        assert build_baseline(SENDER, rows).countries["originating"] == {"US": 5}
        assert account_takeover.EXTERNAL_ID in _ids(_eml(origin_ip=NG, body=PAYMENT_CHANGE), _snapshot(rows))


# ---- the non-geographic anomalies (what catches hosted M365/Gmail takeovers) -------------------


def test_new_reply_to_domain_with_payment_change_fires():
    email = _eml(reply_to="accounts@acme-remit.net", body=PAYMENT_CHANGE)
    result = account_takeover.assess(email, _snapshot(_established()))
    assert result is not None and any("New reply-to domain: acme-remit.net" in a for a in result.anomalies)


def test_new_return_path_domain_with_credential_request_fires():
    email = _eml(return_path="bounce@mailer-xyz.top", body="Please verify your password here: https://x.example/login")
    result = account_takeover.assess(email, _snapshot(_established()))
    assert result is not None and "credential" in result.intents


def test_new_sending_provider_with_mfa_request_fires():
    rows = _established(provider="outlook.com")
    email = _eml(body="Can you send me the verification code you just got? I'm locked out.")
    result = account_takeover.assess(email, _snapshot(rows))
    assert result is not None and "mfa" in result.intents
    assert any("New sending provider: acme-supplies.com" in a for a in result.anomalies)


def test_timing_outlier_needs_enough_history_and_a_big_gap():
    rows = [_row(40 - i * 3, hour=13 + (i % 5)) for i in range(10)]  # 13:00-17:00 UTC
    late = _eml(date="Tue, 10 Nov 2026 03:00:00 +0000", body=PAYMENT_CHANGE)
    result = account_takeover.assess(late, _snapshot(rows))
    assert result is not None and any(a.startswith("Timing outlier: 03:00 UTC") for a in result.anomalies)
    assert account_takeover.assess(late, _snapshot(rows[:9])) is None  # too little history
    near = _eml(date="Tue, 10 Nov 2026 19:00:00 +0000", body=PAYMENT_CHANGE)  # 2h from 17:00
    assert account_takeover.assess(near, _snapshot(rows)) is None


def test_urgency_counts_only_when_heavy_and_tied_to_a_link():
    rows = _established()
    pressure = "URGENT: action required immediately, final notice. Review the document now."
    assert account_takeover.assess(_eml(origin_ip=NG, body=pressure), _snapshot(rows)) is None
    with_link = _eml(origin_ip=NG, body=pressure, link="https://docs.acme-share.top/view")
    result = account_takeover.assess(with_link, _snapshot(rows))
    assert result is not None and result.intents == ["urgent_action"]


# ---- signals ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spf,dkim,dmarc,expected",
    [
        ("pass", "pass", "pass", True),
        ("none", "none", "pass", True),
        ("pass", "pass", "none", True),
        ("pass", "none", "none", False),
        ("pass", "pass", "fail", False),
        ("softfail", "pass", "pass", False),
    ],
)
def test_authenticates_as_sender(spf, dkim, dmarc, expected):
    email = _eml()
    email.auth_results = email.auth_results.model_copy(update={"spf": spf, "dkim": dkim, "dmarc": dmarc})
    assert authenticates_as_sender(email) is expected


def test_signals_prefer_the_originating_client_ip():
    s = extract_signals(_eml(origin_ip=NG, reply_to="x@other.net"))
    assert (s.sending_country, s.country_source, s.sending_ip) == ("NG", "originating", NG)
    assert s.from_domain == "acme-supplies.com" and s.reply_to_domain == "other.net"
    assert s.return_path_domain == "acme-supplies.com" and s.message_hour_utc == 15
    assert s.sending_provider == "acme-supplies.com" and s.auth_pass
