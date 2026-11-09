"""Received-chain / X-Originating-IP / SPF client-ip extraction against real-format header
samples (tests/fixtures/received/, modeled on Gmail, Microsoft 365, Postfix+amavis, Exim and
qmail headers, with sender/recipient domains replaced by .example names)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.sender_ip import build_sender_ip_info
from app.channels.message import Channel, Message
from app.parsing.auth_results import extract_spf_client_ip
from app.parsing.eml_parser import parse_eml
from app.parsing.received_chain import (
    MAX_HOPS,
    extract_originating_ip,
    extract_received_spf_client_ip,
    parse_hop,
    parse_received_chain,
    pick_received_sending_hop,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "received"


def _parse(name: str) -> Message:
    return parse_eml((FIXTURES / name).read_bytes())


# ---- parse_eml keeps the whole chain ------------------------------------------------------


def test_parse_eml_keeps_every_received_header_in_order():
    """The `headers` dict collapses repeated headers to one; the chain must not."""
    parsed = _parse("postfix_amavis_no_auth.eml")
    assert len(parsed.received_headers) == 4
    assert parsed.received_headers[0].startswith("from localhost")
    assert "192.168.1.20" in parsed.received_headers[-1]


# ---- per-format hop parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "header, expected_ip, expected_from, expected_by",
    [
        # Gmail / Postfix style: rDNS + bracketed literal
        (
            "from mail.paypa1-secure.example (mail.paypa1-secure.example. [185.220.101.47]) "
            "by mx.google.com with ESMTPS id a1si2345678wrb.112",
            "185.220.101.47", "mail.paypa1-secure.example", "mx.google.com",
        ),
        # Exim: bare literal + helo=
        (
            "from [45.142.120.10] (helo=WIN-8K2J3L4M5N6) by mx1.hosting.example with esmtp (Exim 4.96)",
            "45.142.120.10", None, "mx1.hosting.example",
        ),
        # Exim: literal with source port
        (
            "from host.example ([77.88.55.60]:51234 helo=host.example) by mx.example.net with esmtps",
            "77.88.55.60", "host.example", "mx.example.net",
        ),
        # Microsoft 365: unbracketed IP in parentheses
        (
            "from mail.invoices-portal.example (45.142.120.10) by "
            "DB5PEPF00014B8F.mail.protection.outlook.com (10.167.8.198) with Microsoft SMTP Server",
            "45.142.120.10", "mail.invoices-portal.example", "db5pepf00014b8f.mail.protection.outlook.com",
        ),
        # qmail
        ("from unknown (HELO mailer) (77.88.55.60) by mx.example.net with SMTP", "77.88.55.60", "unknown", "mx.example.net"),
        # IPv6 literal
        (
            "from mail.example.org ([IPv6:2a00:1450:4864:20::536]) by mx.example.net with ESMTPS",
            "2a00:1450:4864:20::536", "mail.example.org", "mx.example.net",
        ),
    ],
)
def test_parse_hop_formats(header, expected_ip, expected_from, expected_by):
    hop = parse_hop(0, header)
    assert hop.ip == expected_ip
    assert hop.from_host == expected_from
    assert hop.by_host == expected_by
    assert hop.is_public is True


def test_bracketed_peer_ip_wins_over_an_ip_looking_helo():
    hop = parse_hop(0, "from [8.8.4.4] (helo=[10.0.0.1]) by mx.example.net with esmtp")
    assert hop.ip == "8.8.4.4"


def test_hop_without_from_clause_has_no_ip():
    hop = parse_hop(0, "by 2002:a05:7300:5e0a:b0:1a2:3b4c:5d6e with SMTP id x10csp1234567dyb;")
    assert hop.ip is None
    assert hop.by_host is None  # an IP literal is not a hostname


def test_private_and_loopback_hops_are_not_public():
    hops = parse_received_chain(
        [
            "from localhost (localhost [127.0.0.1]) by mail.victim.example (Postfix)",
            "from [192.168.1.20] (unknown [192.168.1.20]) by smtp.sender.example (Postfix)",
        ]
    )
    assert [h.is_public for h in hops] == [False, False]
    assert pick_received_sending_hop(hops) is None


def test_garbage_headers_never_raise():
    hops = parse_received_chain(["", "from", "from (((( [not.an.ip] by", "by only"])
    assert all(h.ip is None for h in hops)


def test_chain_is_capped():
    hops = parse_received_chain([f"from h{i}.example ([8.8.8.8]) by mx.example.net" for i in range(100)])
    assert len(hops) == MAX_HOPS


# ---- picking the sending hop --------------------------------------------------------------


def test_topmost_external_hop_wins_over_a_forged_lower_hop():
    """Everything below the receiver's edge is attacker-writable. The forged bottom hop claims
    8.8.8.8; the real connecting IP is the topmost external hop."""
    info = build_sender_ip_info(_parse("forged_bottom_hop.eml"))
    assert info.sending_ip.ip == "77.88.55.60"
    assert info.sending_ip_source == "received_chain"
    assert info.sending_ip_confidence == "lower"


def test_postfix_amavis_skips_loopback_reinjection_hops():
    info = build_sender_ip_info(_parse("postfix_amavis_no_auth.eml"))
    assert info.sending_ip.ip == "91.198.174.192"
    assert info.sending_ip_source == "received_chain"
    assert len(info.hops) == 4


def test_exim_bare_literal():
    info = build_sender_ip_info(_parse("exim_bare_literal.eml"))
    assert info.sending_ip.ip == "45.142.120.10"


def test_m365_internal_relays_are_skipped_in_received_fallback():
    """Strip the SPF stamps so only the chain is available: the three internal
    *.prod.outlook.com / *.outlook.office365.com IPv6 relays must be skipped."""
    parsed = _parse("m365_inbound_internal_hops.eml")
    parsed.received_spf_header = None
    parsed.auth_results.raw_header = None
    info = build_sender_ip_info(parsed)
    assert info.sending_ip.ip == "45.142.120.10"
    assert info.sending_ip_source == "received_chain"


def test_same_provider_only_chain_falls_back_to_topmost_public_hop():
    hops = parse_received_chain(
        ["from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS"]
    )
    assert pick_received_sending_hop(hops).ip == "209.85.220.41"


# ---- SPF client-ip (higher confidence) ----------------------------------------------------


def test_m365_uses_received_spf_client_ip():
    info = build_sender_ip_info(_parse("m365_inbound_internal_hops.eml"))
    assert info.sending_ip.ip == "45.142.120.10"
    assert info.sending_ip_source == "spf_client_ip"
    assert info.sending_ip_confidence == "higher"


def test_gmail_uses_received_spf_and_reports_x_originating_ip_separately():
    info = build_sender_ip_info(_parse("gmail_inbound_softfail.eml"))
    assert info.sending_ip.ip == "185.220.101.47"
    assert info.sending_ip_source == "spf_client_ip"
    assert info.originating_ip.ip == "102.89.33.14"


def test_authentication_results_client_ip_takes_precedence_over_received_chain():
    parsed = Message(
        channel=Channel.EMAIL,
        received_headers=["from relay.example (relay.example [77.88.55.60]) by mx.victim.example"],
    )
    parsed.auth_results.raw_header = "mx.victim.example; spf=pass smtp.mailfrom=a@b.example client-ip=8.8.4.4"
    info = build_sender_ip_info(parsed)
    assert info.sending_ip.ip == "8.8.4.4"
    assert info.sending_ip_source == "spf_client_ip"


def test_extract_spf_client_ip_first_match_semantics_unchanged():
    """Pins the semantics known_bad_sender relied on before extraction: only the first
    client-ip= counts, and an invalid one yields None rather than a later match."""
    assert extract_spf_client_ip("spf=pass client-ip=203.0.113.5") == "203.0.113.5"
    assert extract_spf_client_ip("client-ip=[2001:db8::1]") == "2001:db8::1"
    assert extract_spf_client_ip("client-ip=999.1.1.1 | client-ip=8.8.8.8") is None
    assert extract_spf_client_ip(None) is None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("pass (google.com: ...) client-ip=209.85.220.41;", "209.85.220.41"),
        ("Fail (protection.outlook.com: ...) receiver=protection.outlook.com; client-ip=45.142.120.10; helo=x;", "45.142.120.10"),
        ("pass client-ip=2a00:1450:4864:20::536", "2a00:1450:4864:20::536"),
        ("none (no client ip here)", None),
        ("pass client-ip=not-an-ip;", None),
        (None, None),
    ],
)
def test_extract_received_spf_client_ip(value, expected):
    assert extract_received_spf_client_ip(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [("[102.89.33.14]", "102.89.33.14"), ("102.89.33.14", "102.89.33.14"), ("[garbage]", None), ("", None), (None, None)],
)
def test_extract_originating_ip(value, expected):
    assert extract_originating_ip(value) == expected


# ---- absent / non-email --------------------------------------------------------------------


def test_no_ip_headers_returns_none():
    assert build_sender_ip_info(parse_eml(b"Subject: hi\n\nbody only")) is None


def test_chat_messages_have_no_sender_ip_info():
    assert build_sender_ip_info(Message(channel=Channel.SLACK)) is None
