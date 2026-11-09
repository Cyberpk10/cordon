"""Source IP + country display end to end: email analyze -> persisted Case -> case detail,
incident evidence events, Early-Warning alerts and the activity-log analyzer summary. Also
pins the core contract: header-derived IPs are display-only and never move a score."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.db.models import Case
from app.threat_intel import loader as threat_intel_loader
from app.threat_intel.loader import ThreatIntelSnapshot

RECEIVED_FIXTURES = Path(__file__).parent.parent / "fixtures" / "received"

_BODY_ONLY = (
    b"From: \"PayPal Billing\" <billing@paypa1-secure.example>\n"
    b"To: victim@gmail.com\n"
    b"Subject: Your account has been limited\n"
    b"MIME-Version: 1.0\n"
    b"Content-Type: text/plain; charset=\"utf-8\"\n\n"
    b"Please verify your account within 24 hours: http://paypa1-secure.example/verify\n"
)

_IP_HEADERS = (
    b"Received: from mail.paypa1-secure.example (mail.paypa1-secure.example. [185.220.101.47])\n"
    b"        by mx.google.com with ESMTPS id a1si2345678wrb; Mon, 02 Nov 2026 08:14:03 -0800\n"
    b"Received-SPF: softfail (google.com: ...) client-ip=185.220.101.47;\n"
    b"X-Originating-IP: [102.89.33.14]\n"
)


@pytest.fixture()
def tor_feed_with_header_ips(monkeypatch):
    """Plant both header IPs in the threat-intel snapshot as Tor exits."""
    snap = ThreatIntelSnapshot(
        hostnames={},
        urls={},
        ip_exact={"185.220.101.47": "tor_exit_node", "102.89.33.14": "tor_exit_node", "185.220.101.9": "tor_exit_node"},
        ip_networks=(),
        snapshot_date="2099-01-01",
    )
    monkeypatch.setattr(threat_intel_loader, "load_snapshot", lambda: snap)
    return snap


def _analyze(client, raw: bytes, name: str = "x.eml"):
    resp = client.post("/api/analyze", files={"file": (name, raw, "message/rfc822")})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_analyze_returns_sending_ip_with_country_and_tor_label(authed_client, tor_feed_with_header_ips):
    body = _analyze(authed_client, (RECEIVED_FIXTURES / "gmail_inbound_softfail.eml").read_bytes())
    info = body["sender_ip_info"]
    assert info["sending_ip"]["ip"] == "185.220.101.47"
    assert info["sending_ip_source"] == "spf_client_ip"
    assert info["sending_ip_confidence"] == "higher"
    assert info["sending_ip"]["geo"]["status"] == "resolved"
    assert info["sending_ip"]["geo"]["country_name"]  # real bundled snapshot
    assert info["sending_ip"]["geo"]["source"] == "db-ip"
    assert info["sending_ip"]["threat_intel"]["label"] == "Tor exit node"
    assert info["originating_ip"]["ip"] == "102.89.33.14"
    assert len(info["hops"]) == 3


def test_sender_ip_info_is_persisted_and_returned_on_case_detail(authed_client, db_session):
    body = _analyze(authed_client, (RECEIVED_FIXTURES / "postfix_amavis_no_auth.eml").read_bytes())
    row = db_session.get(Case, __import__("uuid").UUID(body["id"]))
    assert row.sender_ip_info["sending_ip"]["ip"] == "91.198.174.192"

    detail = authed_client.get(f"/api/cases/{body['id']}").json()
    assert detail["sender_ip_info"]["sending_ip"]["ip"] == "91.198.174.192"
    assert detail["sender_ip_info"]["sending_ip_source"] == "received_chain"
    assert detail["sender_ip_info"]["sending_ip_confidence"] == "lower"


def test_header_ips_never_change_the_pipeline_score_even_when_known_bad(tor_feed_with_header_ips):
    """The display-only contract at the pipeline level: identical score/verdict/indicators
    with or without the Received/Received-SPF/X-Originating-IP headers, even with those IPs
    on the Tor feed."""
    from app.analysis.email_pipeline import run_email_pipeline

    without = run_email_pipeline(_BODY_ONLY)
    with_ips = run_email_pipeline(_IP_HEADERS + _BODY_ONLY)
    assert without.sender_ip_info is None
    assert with_ips.sender_ip_info.sending_ip.threat_intel.label == "Tor exit node"
    assert (with_ips.score, with_ips.verdict) == (without.score, without.verdict)
    assert [i.id for i in with_ips.indicators] == [i.id for i in without.indicators]


def test_header_ips_never_change_the_api_score_even_when_known_bad(
    authed_client, other_account_authed_client, tor_feed_with_header_ips
):
    """Same contract through POST /api/analyze. Two separate accounts, because analyzing the
    same sender twice in ONE account legitimately changes sender-history indicators
    (first-contact vs. seen-before), which would confound the comparison."""
    without = _analyze(authed_client, _BODY_ONLY, "a.eml")
    with_ips = _analyze(other_account_authed_client, _IP_HEADERS + _BODY_ONLY, "b.eml")

    assert without["sender_ip_info"] is None
    assert with_ips["sender_ip_info"]["sending_ip"]["threat_intel"]["label"] == "Tor exit node"
    assert with_ips["score"] == without["score"]
    assert with_ips["verdict"] == without["verdict"]
    assert sorted(i["id"] for i in with_ips["indicators"]) == sorted(i["id"] for i in without["indicators"])


def test_email_without_ip_headers_has_null_sender_ip_info(authed_client):
    body = authed_client.post("/api/analyze/text", json={"raw_text": "Subject: hi\n\nplain text only"}).json()
    assert body["sender_ip_info"] is None


def test_incident_evidence_events_carry_ip_country_and_threat_intel(
    authed_client, load_events_fixture, tor_feed_with_header_ips
):
    events = load_events_fixture("brute_force_attack.json")
    for e in events:
        e["source_ip"] = "185.220.101.9"
    events[0]["geo"] = {"country": "NL"}  # log-supplied on one event

    created = authed_client.post("/api/events", json={"events": events}).json()["incidents_created"][0]
    detail = authed_client.get(f"/api/incidents/{created['id']}").json()

    contexts = [e["source_ip_context"] for e in detail["evidence_events"]]
    assert all(c["ip"] == "185.220.101.9" for c in contexts)
    assert all(c["threat_intel"]["label"] == "Tor exit node" for c in contexts)
    sources = {c["geo"]["source"] for c in contexts}
    assert sources == {"log", "db-ip"}  # log geo shown as log; others resolved from the IP
    log_ctx = next(c for c in contexts if c["geo"]["source"] == "log")
    assert log_ctx["geo"]["country_name"] == "Netherlands"


def test_incident_with_documentation_range_ip_is_non_public(authed_client, load_events_fixture):
    events = load_events_fixture("brute_force_attack.json")  # 203.0.113.10 (TEST-NET-3)
    created = authed_client.post("/api/events", json={"events": events}).json()["incidents_created"][0]
    detail = authed_client.get(f"/api/incidents/{created['id']}").json()
    assert detail["evidence_events"][0]["source_ip_context"]["geo"]["status"] == "non_public"


def test_early_warning_alert_lists_actor_source_ips(authed_client):
    """Same verified forming-chain replay as test_early_warning_endpoint, with source IPs."""
    actor = "chain-ip-actor@corp.com"
    t0 = datetime.now(timezone.utc) - timedelta(days=8)
    day0 = [
        {"timestamp": t0.isoformat(), "actor": actor, "action": "auth_fail", "outcome": "failure",
         "source_ip": "102.89.33.14"}
        for _ in range(2)
    ]
    day5 = [{
        "timestamp": (t0 + timedelta(days=5)).isoformat(), "actor": actor, "action": "file_access",
        "target": "finance/report.xlsx", "outcome": "success", "source_ip": "102.89.33.14",
    }]
    day8 = [{
        "timestamp": (t0 + timedelta(days=8)).isoformat(), "actor": actor, "action": "data_transfer",
        "target": "unfamiliar-host.example.net", "bytes": 10_000_000, "outcome": "success",
        "source_ip": "8.8.8.8",
    }]
    for batch in (day0, day5, day8):
        assert authed_client.post("/api/events", json={"events": batch}).status_code == 200

    alerts = authed_client.get("/api/early-warnings").json()["alerts"]
    assert len(alerts) == 1
    ips = alerts[0]["source_ips"]
    assert [s["ip"] for s in ips] == ["102.89.33.14", "8.8.8.8"]  # busiest first
    assert ips[0]["event_count"] == 3
    assert ips[1]["geo"]["country_code"] == "US"


def test_activity_log_summary_has_source_ip_details(authed_client):
    csv = "timestamp,account,source_ip,geo,result\n" + "\n".join(
        f"2026-01-06T10:0{i}:00Z,alice@corp.com,8.8.8.8,US,FAILURE" for i in range(6)
    )
    body = authed_client.post("/api/activity-log/analyze", json={"raw_text": csv}).json()
    details = body["summary"]["source_ip_details"]
    assert details[0]["ip"] == "8.8.8.8"
    assert details[0]["geo"]["source"] == "log"
    assert details[0]["geo"]["country_name"] == "United States"
    assert body["summary"]["source_ips"] == ["8.8.8.8"]  # unchanged legacy field
