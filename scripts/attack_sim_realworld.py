#!/usr/bin/env python3
"""REAL-WORLD red-team suite — the commodity/criminal attacks that actually breach small
businesses, churches, and schools, as opposed to phase 3/4's elite-tier/nation-state tradecraft
(those remain useful ceiling tests, just not what shows up in a typical SMB breach report).
Authorized, dev-only, synthetic data. Defensive testing of our own local instance only.

Covers: credential phishing (lookalike domain), BEC/invoice-and-wire fraud (spoofed-sender and
compromised-vendor variants), account takeover from stolen credentials (new-geo login,
impossible travel, first sensitive-file access), password spray (single-IP and
subnet-rotating/proxy-pool variants), a ransomware precursor chain (phish -> access -> mass
file enumeration -> exfiltration), a malicious-attachment/commodity-malware lure (link +
attachment + a real threat-intel-feed hit), and a second compromised-vendor variant (a calm,
no-urgency credential-harvest lure). Ends with a benign-heavy control scenario — the hard bar
for this suite is ZERO false positives, not just a detection rate.

This script REFUSES TO RUN unless --base-url resolves to localhost/127.0.0.1/::1 or a host
explicitly listed in ALLOWED_HOSTS below — enforced at startup (enforce_target_allowlist()).
It never sends real email and never performs any real network attack; every "attacker" action
is a synthetic API call. NEVER add a production host to ALLOWED_HOSTS.

RUN ISOLATION (baked in from the start, not bolted on): every run creates and uses its OWN
brand-new account (an auto-generated, randomly-salted email under @cordon.local) — never logs
into an existing one, and never reuses a previous run's account. This is a structural fix for
the cross-run false-positive class documented in logs/redteam-daily.log (2026-09-27/09-30):
that bug required an OLD run's Incident to be deleted (cleanup_sim.py) so its still-undeleted
Events (append-only; see app/api/routes/events.py) could later be "rediscovered" by an
unrelated request's account-wide re-scan. An account this script never revisits, and never
calls cleanup_sim.py against, can never hit that path — there is no delete-then-rediscover
cycle to trigger it. Every synthetic identifier (actor email) AND every synthetic source IP is
additionally salted per run_id (see _run_salt_octet) as defense in depth, matching the fix
already applied to attack_sim.py/attack_sim_phase2.py/phase3/phase4/phase5.

Trade-off accepted deliberately: this means every run leaves behind one throwaway Account/User
row that nothing ever deletes (no account-deletion endpoint exists, and the Events table is
intentionally append-only — see cleanup_sim.py's own docstring). For a local dev SQLite
instance running this once a day, that's a few hundred harmless rows a year, not a problem;
it is NOT something to "fix" by reusing accounts, which is exactly the bug class this script
exists to avoid reintroducing.

Usage:
    python3 scripts/attack_sim_realworld.py
    python3 scripts/attack_sim_realworld.py --base-url http://localhost:8000 --pace 0 --no-prompt

Stdlib only. Ends by printing a SCORECARD in the same format phase 3 established (so
scripts/daily_redteam.sh's existing log-line parsing keeps working unchanged): per-scenario
CAUGHT/MISSED, an overall "Detection rate: X/Y" line, and a "False positives: N" line. Unlike
phase 3 (where most misses are the EXPECTED, correct outcome of elite evasion), every attack
scenario here is expected to be CAUGHT — these are not sophisticated techniques, they're what
actually breaches under-resourced organizations. A miss here is a real gap, not a badge of
honor for the attacker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

DEFAULT_BASE_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:5173"

# Hard allowlist enforced by enforce_target_allowlist() below — identical convention to every
# other script in this directory. Add a hostname here only when you deliberately mean to point
# this script at it — never add a production host.
ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "cordon-staging-backend.onrender.com",
}


def enforce_target_allowlist(base_url: str) -> None:
    host = urllib.parse.urlsplit(base_url).hostname
    if host is None or host.lower() not in ALLOWED_HOSTS:
        print(_c(_RED, f"\n[REFUSED] --base-url host {host!r} is not localhost and is not"), file=sys.stderr)
        print(_c(_RED, "in ALLOWED_HOSTS (this file). This script writes real, persisted"), file=sys.stderr)
        print(_c(_RED, "case/incident/account data on whatever it talks to — refusing to run"), file=sys.stderr)
        print(_c(_RED, "against an unrecognized host."), file=sys.stderr)
        print(_c(_RED, "If this is a legitimate staging target, add its hostname to"), file=sys.stderr)
        print(_c(_RED, "ALLOWED_HOSTS explicitly. NEVER add a production host."), file=sys.stderr)
        sys.exit(1)


_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_MAGENTA = "\033[35m"


def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def banner(title: str) -> None:
    print()
    print(_c(_BOLD + _CYAN, "=" * 78))
    print(_c(_BOLD + _CYAN, f" {title}"))
    print(_c(_BOLD + _CYAN, "=" * 78))


def scenario(number: int, title: str) -> None:
    print()
    print(_c(_BOLD + _MAGENTA, f"--- SCENARIO {number}: {title} " + "-" * max(0, 50 - len(title))))


def attacker(msg: str) -> None:
    print(_c(_RED, "[ATTACKER] ") + msg)


def cordon(msg: str) -> None:
    print(_c(_GREEN, "[CORDON]   ") + msg)


def setup(msg: str) -> None:
    print(_c(_YELLOW, "[SETUP]    ") + msg)


def dim(msg: str) -> None:
    print(_c(_DIM, "           " + msg))


class HTTPStatusError(RuntimeError):
    def __init__(self, status: int, body: str, path: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"{status} on {path}: {body}")


class AegisClient:
    """Thin stdlib HTTP wrapper — self-contained, matching this repo's existing convention
    that each script under scripts/ duplicates it rather than sharing a module."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token: str | None = None

    def _request(self, method: str, path: str, *, json_body: dict | None = None,
                 params: dict | None = None, auth: bool = True) -> dict:
        url = self.base_url + path
        if params:
            query = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in params.items() if v is not None)
            if query:
                url = f"{url}?{query}"

        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        headers = {"Content-Type": "application/json"}
        if auth:
            if not self.token:
                raise RuntimeError("AegisClient.token is not set — call create_isolated_account() first.")
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise HTTPStatusError(exc.code, body, path) from None
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Could not reach Cordon at {self.base_url} ({exc.reason}). "
                f"Is the backend running? Start it with:\n"
                f"  cd backend && source .venv/bin/activate && uvicorn app.main:app --reload"
            ) from None

    def post(self, path: str, json_body: dict | None = None, *, auth: bool = True) -> dict:
        return self._request("POST", path, json_body=json_body, auth=auth)

    def get(self, path: str, params: dict | None = None, *, auth: bool = True) -> dict:
        return self._request("GET", path, params=params, auth=auth)


def create_isolated_account(client: AegisClient, run_id: str) -> str:
    """Always SIGNS UP a brand-new account — never logs into an existing one. This is the
    run-isolation mechanism (see module docstring): an account this script never reuses and
    never revisits can never accumulate the cross-run leftover evidence that caused the
    2026-09-27/09-30 false-positive regressions. Returns the account email (for display only
    — nothing else in this script needs to log into it again)."""
    email = f"redteam-realworld-{run_id}@cordon.local"
    password = secrets.token_urlsafe(24)
    setup(f"Creating a fresh, isolated account for this run: {_c(_BOLD, email)}...")
    resp = client.post(
        "/api/auth/signup",
        {"account_name": f"Red Team Real-World Sim {run_id}", "email": email, "password": password},
        auth=False,
    )
    client.token = resp["access_token"]
    cordon(f"account created. account_id={resp['user']['account_id']} (never reused, never logged into again)")
    return email


# --------------------------------------------------------------------------------------------
# Scorecard — identical shape/output format to attack_sim_phase3.py's, so
# scripts/daily_redteam.sh's existing `parse_rate`/`parse_fp` grep patterns keep working.
# --------------------------------------------------------------------------------------------


@dataclass
class ScorecardEntry:
    number: int
    name: str
    mechanism: str
    caught: bool
    detail: str
    expected_to_evade: bool = False  # every scenario here SHOULD be caught; True would mean "a miss is expected"


@dataclass
class Scorecard:
    entries: list[ScorecardEntry] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    def record(self, number: int, name: str, mechanism: str, caught: bool, detail: str,
               expected_to_evade: bool = False) -> None:
        self.entries.append(ScorecardEntry(number, name, mechanism, caught, detail, expected_to_evade))

    def record_false_positive(self, description: str) -> None:
        self.false_positives.append(description)

    def print_report(self) -> None:
        banner("SCORECARD — real-world commodity/criminal attacks")

        caught_count = sum(1 for e in self.entries if e.caught)
        total = len(self.entries)
        rate_color = _GREEN if caught_count == total else _YELLOW if caught_count >= total * 0.75 else _RED

        print()
        for e in self.entries:
            tag = _c(_BOLD + _GREEN, "CAUGHT") if e.caught else _c(_BOLD + _RED, "MISSED")
            print(f"  {e.number}. {e.name:<46} {tag}")
            print(_c(_DIM, f"     targets: {e.mechanism}"))
            print(_c(_DIM, f"     result:  {e.detail}"))

        print()
        print(
            f"Detection rate: "
            + _c(_BOLD + rate_color, f"{caught_count}/{total}")
            + f" scenarios raised a non-safe verdict or incident."
        )

        print()
        if self.false_positives:
            print(_c(_BOLD + _RED, f"False positives: {len(self.false_positives)}"))
            for fp in self.false_positives:
                dim(f"- {fp}")
        else:
            print(_c(_BOLD + _GREEN, "False positives: 0") + " — every benign actor stayed safe.")

        misses = [e for e in self.entries if not e.caught]
        print()
        if misses:
            print(_c(_BOLD + _RED, "Gaps (real-world attacks that got through — investigate):"))
            for e in misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        else:
            print(_c(_BOLD + _GREEN, "No misses this run — every commodity/criminal scenario was caught."))

        print()
        hard_bar_ok = not self.false_positives
        if hard_bar_ok and not misses:
            print(_c(_BOLD + _GREEN, "DAILY GREEN: zero false positives, zero misses."))
        elif hard_bar_ok:
            print(_c(_BOLD + _YELLOW, "Zero false positives (hard bar met), but gaps remain above."))
        else:
            print(_c(_BOLD + _RED, "HARD BAR FAILED: false positives are never acceptable for this suite."))


# --------------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------------

_NY_GEO = {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060}
_LAGOS_GEO = {"country": "NG", "region": "Lagos", "lat": 6.5244, "lon": 3.3792}
_HOME_IP_BASE = "198.51.100"


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _business_days(start: datetime, count: int) -> list[datetime]:
    """`count` consecutive weekdays starting at-or-after `start` — avoids off_hours_access's
    unconditional weekend check deciding a scenario's outcome by which day it happens to run."""
    days: list[datetime] = []
    current = start
    while len(days) < count:
        if current.weekday() < 5:
            days.append(current)
        current += timedelta(days=1)
    return days


def _snap_to_weekday(dt: datetime) -> datetime:
    return _business_days(dt, 1)[0]


def _run_salt_octet(seed: str) -> int:
    """A stable per-run byte (0-255) derived from a run-unique seed. Salts an otherwise-fixed
    IP octet per run — defense in depth on top of this script's real isolation mechanism (a
    brand-new account every run, see create_isolated_account's docstring). Identical to the
    helper already used in attack_sim.py/phase2/3/4/5."""
    return int(hashlib.sha256(seed.encode()).hexdigest()[:2], 16)


def post_events_and_check(client: AegisClient, events: list[dict]) -> tuple[bool, list[dict]]:
    """Returns (any_incident_created, incidents_created).

    Deliberately the SIMPLE form here (no run-id-actor-scoping filter like phase 3/4/5 need) —
    this script never calls cleanup_sim.py and never reuses its account, so the specific bug
    those filters guard against (an incident gets deleted, its evidence Events' incident_id is
    FK-SET-NULLed, and a later unrelated request's account-wide re-scan "rediscovers" that
    stale evidence as a brand-new incident) cannot happen here: there is no delete step, ever,
    against this account. See the module docstring for the full isolation rationale.
    """
    resp = client.post("/api/events", {"events": events})
    incidents = resp.get("incidents_created") or []
    return bool(incidents), incidents


def _describe_incidents(incidents: list[dict]) -> str:
    if not incidents:
        return "no incident raised — verdict stayed safe"
    parts = []
    for inc in incidents:
        who = inc.get("related_actors") or [inc["actor"]]
        parts.append(
            f"{inc['verdict'].upper()} risk={inc['score']}/100 "
            f"[{', '.join(inc['detection_types'])}] (actor(s)={', '.join(who)})"
        )
    return "; ".join(parts)


def build_email(
    *,
    from_display: str,
    from_addr: str,
    to_addr: str = "ap-team@ourcompany.example",
    subject: str,
    date: datetime,
    body_text: str,
    body_html: str | None = None,
    reply_to: str | None = None,
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
    auth_domain: str | None = None,
    attachment: tuple[str, str] | None = None,  # (filename, content_type)
) -> str:
    """Builds a raw .eml-shaped MIME message via the stdlib email package (rather than
    hand-written MIME boundaries) — correctness by construction for the varied combinations
    of reply-to/attachment/html this suite needs across 9 scenarios."""
    if body_html is not None:
        content: MIMEMultipart | MIMEText = MIMEMultipart("alternative")
        content.attach(MIMEText(body_text, "plain"))
        content.attach(MIMEText(body_html, "html"))
    else:
        content = MIMEText(body_text, "plain")

    if attachment is not None:
        msg = MIMEMultipart("mixed")
        msg.attach(content)
        filename, content_type = attachment
        maintype, _, subtype = content_type.partition("/")
        part = MIMEBase(maintype, subtype or "octet-stream")
        part.set_payload(b"synthetic-redteam-test-payload-not-real-malware")
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment", filename=filename)
        msg.attach(part)
    else:
        msg = content

    domain = auth_domain or from_addr.rsplit("@", 1)[-1]
    msg["From"] = f'"{from_display}" <{from_addr}>'
    msg["To"] = to_addr
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["Authentication-Results"] = (
        f"mx.ourcompany.example; spf={spf} smtp.mailfrom={domain}; "
        f"dkim={dkim} header.d={domain}; dmarc={dmarc} header.from={domain}"
    )
    return msg.as_string()


def analyze_email(client: AegisClient, raw_text: str) -> dict:
    return client.post("/api/analyze/text", {"raw_text": raw_text})


def _indicator_ids(resp: dict) -> list[str]:
    return [i["id"] for i in resp.get("indicators", [])]


# --------------------------------------------------------------------------------------------
# Scenario 1 — Credential phishing (lookalike domain + credential harvest)
# --------------------------------------------------------------------------------------------
#
# The single most common way a small org actually gets breached: a fake Microsoft 365 /
# Google Workspace "verify your account" email. Targets app.indicators.lookalike_domain
# (typosquat of a curated brand domain, edit distance 1) + credential_payment.py's
# CREDENTIAL_REQUEST phrase bank + urgency_language.py + auth_failures.py (SPF/DKIM/DMARC all
# fail, since the attacker doesn't control microsoft.com's real infrastructure) + a
# display-vs-href link mismatch.

_PHISHING_EMAIL_HTML = """<html><body>
<p><b>Unusual sign-in activity detected.</b></p>
<p>We detected an unusual sign-in attempt on your Microsoft 365 account. You must
<b>verify your account within 24 hours</b> or your account will be suspended.</p>
<p><a href="https://micros0ft.com/verify-account">https://login.microsoftonline.com/verify</a></p>
<p>Failure to comply will result in permanent account closure.</p>
<p>- Microsoft 365 Security Team</p>
</body></html>
"""


def run_scenario_1_credential_phishing(client: AegisClient, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(1, "CREDENTIAL PHISHING (LOOKALIKE DOMAIN)")
    attacker("a fake 'Microsoft 365 Security' notice goes out from micros0ft.com (a one-")
    attacker("character typosquat of microsoft.com) — the single most common way a small")
    attacker("org/church/school actually gets breached...")
    time.sleep(min(pace, 2))

    raw = build_email(
        from_display="Microsoft 365 Security",
        from_addr="account-security@micros0ft.com",
        subject="Urgent: Unusual sign-in activity — verify your account within 24 hours",
        date=now,
        body_text=(
            "Unusual sign-in activity detected. We detected an unusual sign-in attempt on "
            "your Microsoft 365 account. You must verify your account within 24 hours or "
            "your account will be suspended. Failure to comply will result in permanent "
            "account closure."
        ),
        body_html=_PHISHING_EMAIL_HTML,
        spf="fail", dkim="fail", dmarc="fail",
    )
    resp = analyze_email(client, raw)
    verdict = resp["verdict"].upper()
    score = resp["score"]
    caught = verdict != "SAFE"
    ids = _indicator_ids(resp)

    color = _GREEN if caught else _RED
    cordon(f"case {resp['id']} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    for title in (i["title"] for i in resp["indicators"]):
        dim(f"- {title}")

    sc.record(
        1, "Credential phishing (lookalike domain)",
        "typosquat of a curated brand domain + credential-harvest language + failed SPF/DKIM/DMARC + link mismatch",
        caught, f"verdict={verdict} score={score}/100, indicators={', '.join(ids)}",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 2 — BEC / invoice-and-wire fraud: spoofed-sender variant
# --------------------------------------------------------------------------------------------
#
# Classic "CEO/pastor fraud": a display name impersonating a real, trusted staff member
# (here, a church pastor — same mechanic works for "the school principal" or "the owner"),
# sent from a first-contact external domain, asking for an urgent wire transfer. Deliberately
# text-only (no link, no attachment) — real BEC usually is, since adding either just gives
# the target more to double-check. Targets credential_payment.py's PAYMENT_REQUEST,
# urgency_language.py, sender_mismatch.py's DISPLAY_NAME_EMAIL_MISMATCH/
# SENDER_REPLYTO_MISMATCH, and sender_history.py's FIRST_CONTACT_SENDER.


def run_scenario_2_bec_spoofed_sender(client: AegisClient, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(2, "BEC / WIRE FRAUD — SPOOFED SENDER")
    attacker("'Pastor James Whitfield' appears to email the finance volunteer asking for an")
    attacker("urgent wire transfer — display name impersonates a real, trusted staff member,")
    attacker("but the actual From address and Reply-To are both attacker-controlled...")
    time.sleep(min(pace, 2))

    raw = build_email(
        from_display="Pastor James Whitfield (pastor.james@gracechapel.example)",
        from_addr="j.whitfield@fastmail-executive.com",
        reply_to="pastorjwhitfield@protonmail.com",
        to_addr="finance-volunteer@ourcompany.example",
        subject="Quick favor — need this handled today",
        date=now,
        body_text=(
            "I need you to process an urgent wire transfer today before our vendor deadline. "
            "This is time-sensitive and I need it handled as soon as possible — please keep "
            "this confidential until I'm back in the office. I'll send the account details "
            "once you confirm you can process it today."
        ),
    )
    resp = analyze_email(client, raw)
    verdict = resp["verdict"].upper()
    score = resp["score"]
    caught = verdict != "SAFE"
    ids = _indicator_ids(resp)

    color = _GREEN if caught else _RED
    cordon(f"case {resp['id']} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    for title in (i["title"] for i in resp["indicators"]):
        dim(f"- {title}")

    sc.record(
        2, "BEC/wire fraud — spoofed sender",
        "display-name impersonation of a trusted staff member + Reply-To mismatch + first-contact domain + urgent payment request, no link/attachment",
        caught, f"verdict={verdict} score={score}/100, indicators={', '.join(ids)}",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 3 — BEC / invoice-and-wire fraud: compromised-vendor variant
# --------------------------------------------------------------------------------------------
#
# A real vendor's mailbox gets taken over and used to request a bank-detail change —
# indistinguishable from a legitimate vendor at the domain/SPF/DKIM/DMARC level (the attacker
# controls the real mailbox). Targets app.indicators.trusted_sender_anomaly
# (TRUSTED_SENDER_ANOMALY, M8 detection max-out Stage A) specifically: a payment-change ask
# from a sender this account has prior contact with, corroborated by urgency. First seeds a
# SEEN_BEFORE classification for the vendor domain with two calm, routine prior emails (real
# per-account sender history — app.sender_history — built from this account's own past Case
# rows, never backdated).

_VENDOR_DOMAIN = "summitofficesupply.example"
_VENDOR_FROM = f"billing@{_VENDOR_DOMAIN}"


def _seed_vendor_history(client: AegisClient, now: datetime, pace: float) -> None:
    setup(f"Seeding real per-account sender history for {_VENDOR_DOMAIN} (2 routine prior emails)...")
    for i, note in enumerate([
        "Attached is this month's statement for your records — nothing due at this time.",
        "Thanks for your continued business. Here's our updated product catalog for Q4.",
    ]):
        raw = build_email(
            from_display="Summit Office Supply — Billing",
            from_addr=_VENDOR_FROM,
            subject=f"Monthly statement #{i + 1}",
            date=now - timedelta(minutes=5 - i),
            body_text=note,
        )
        resp = analyze_email(client, raw)
        dim(f"prior email {i + 1}/2: verdict={resp['verdict'].upper()} score={resp['score']}/100 (routine, expected safe)")
    time.sleep(min(pace, 1))


def run_scenario_3_bec_compromised_vendor(client: AegisClient, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(3, "BEC / WIRE FRAUD — COMPROMISED VENDOR (PAYMENT-CHANGE ASK)")
    _seed_vendor_history(client, now, pace)

    attacker(f"{_VENDOR_DOMAIN}'s real mailbox gets taken over — the follow-up email reads as a")
    attacker("routine billing update from a sender this account has corresponded with before,")
    attacker("and still passes SPF/DKIM/DMARC cleanly since it's really their infrastructure...")
    time.sleep(min(pace, 2))

    raw = build_email(
        from_display="Summit Office Supply — Billing",
        from_addr=_VENDOR_FROM,
        subject="Re: Monthly statement — updated remittance details",
        date=now,
        body_text=(
            "This is to notify you of a change of bank details for our account effective "
            "immediately. Please update your records before your next payment run — this is "
            "time-sensitive, we'd like it reflected as soon as possible so there's no delay "
            "to next month's order."
        ),
        spf="pass", dkim="pass", dmarc="pass",
    )
    resp = analyze_email(client, raw)
    verdict = resp["verdict"].upper()
    score = resp["score"]
    caught = verdict != "SAFE"
    ids = _indicator_ids(resp)

    color = _GREEN if caught else _RED
    cordon(f"case {resp['id']} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    for title in (i["title"] for i in resp["indicators"]):
        dim(f"- {title}")

    sc.record(
        3, "BEC/wire fraud — compromised vendor (payment-change)",
        "payment/bank-detail-change request from a sender with real prior history, corroborated by urgency (app.indicators.trusted_sender_anomaly)",
        caught, f"verdict={verdict} score={score}/100, indicators={', '.join(ids)}",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 4 — Account takeover from stolen credentials
# --------------------------------------------------------------------------------------------
#
# Builds a real 5-day behavioral baseline for an ordinary employee (home-country logins,
# ordinary shared-doc access) — enough history to clear every cold-start gate
# (baseline_min_events_for_location/resource_class = 5) — then simulates stolen credentials
# used from a new country, landing within the impossible-travel window of the legitimate
# login, immediately followed by first-ever access to a finance file. Targets
# app.detections.impossible_travel + anomalous_location + sensitive_resource_access together
# — the realistic shape of "someone's password got phished and the attacker logged straight
# in," not a brute-force guess.


def run_scenario_4_account_takeover(client: AegisClient, run_id: str, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(4, "ACCOUNT TAKEOVER FROM STOLEN CREDENTIALS")
    actor = f"maria.gonzalez.{run_id}@victimcorp.example"
    home_ip = f"{_HOME_IP_BASE}.{_run_salt_octet(actor)}"
    attacker(f"{_c(_BOLD, actor)}'s password was phished last week. First, 5 ordinary business")
    attacker("days of real baseline activity (home logins, normal shared-doc access)...")
    time.sleep(min(pace, 2))

    days = _business_days(now - timedelta(days=9), 5)
    for day in days:
        events = [
            {
                "timestamp": _iso(day.replace(hour=9, minute=0)),
                "actor": actor, "action": "login", "source_ip": home_ip,
                "outcome": "success", "geo": _NY_GEO,
            },
            {
                "timestamp": _iso(day.replace(hour=9, minute=10)),
                "actor": actor, "action": "file_access", "source_ip": home_ip,
                "target": "shared/volunteer-schedule.xlsx", "outcome": "success",
            },
            {
                "timestamp": _iso(day.replace(hour=9, minute=20)),
                "actor": actor, "action": "file_access", "source_ip": home_ip,
                "target": "shared/newsletter-draft.docx", "outcome": "success",
            },
        ]
        fired, _ = post_events_and_check(client, events)
        if fired:
            cordon(_c(_BOLD + _RED, f"unexpected incident during baseline-building on {day.date()}!"))
        dim(f"{day.date()}: ordinary home-IP login + 2 normal file accesses -> baseline growing")

    attacker("...then the stolen credentials get used from Lagos, Nigeria, 45 minutes after")
    attacker(f"{_c(_BOLD, actor)}'s real morning login — followed immediately by the account's")
    attacker("very first-ever access to a finance file.")
    time.sleep(min(pace, 2))

    takeover_day = _business_days(days[-1] + timedelta(days=1), 1)[0]
    legit_login_at = takeover_day.replace(hour=9, minute=0)
    takeover_at = legit_login_at + timedelta(minutes=45)
    events = [
        {
            "timestamp": _iso(legit_login_at),
            "actor": actor, "action": "login", "source_ip": home_ip,
            "outcome": "success", "geo": _NY_GEO,
        },
        {
            "timestamp": _iso(takeover_at),
            "actor": actor, "action": "login",
            "source_ip": f"41.203.{_run_salt_octet(actor + '-takeover')}.17",
            "outcome": "success", "geo": _LAGOS_GEO,
        },
        {
            "timestamp": _iso(takeover_at + timedelta(minutes=2)),
            "actor": actor, "action": "file_access",
            "source_ip": f"41.203.{_run_salt_octet(actor + '-takeover')}.17",
            "target": "finance/q4-budget-and-reserves.xlsx", "outcome": "success",
        },
    ]
    fired, incidents = post_events_and_check(client, events)
    caught = fired
    color = _GREEN if caught else _RED
    cordon(f"takeover batch -> {_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    if caught:
        dim(_describe_incidents(incidents))

    sc.record(
        4, "Account takeover from stolen credentials",
        "impossible travel + login from a never-seen country + first-ever finance-file access, all against a real established baseline",
        caught,
        _describe_incidents(incidents) if caught else "no incident raised despite impossible travel, new-country login, and first sensitive access",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 5 — Password spray: single IP
# --------------------------------------------------------------------------------------------
#
# The most basic, highest-volume real-world credential attack: one IP (a single compromised
# host, or a cheap VPS) sprays a handful of failed logins across many accounts, staying under
# any one account's own brute-force floor. Targets app.detections.cross_actor.
# detect_password_spray's exact-IP grouping.

_SPRAY_ACCOUNT_COUNT = 10


def run_scenario_5_password_spray_single_ip(client: AegisClient, run_id: str, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(5, "PASSWORD SPRAY — SINGLE IP")
    spray_ip = f"203.0.113.{_run_salt_octet(run_id + '-spray-single')}"
    attacker(f"spraying {_SPRAY_ACCOUNT_COUNT} staff accounts from one IP ({spray_ip}), 2-3 failed")
    attacker("logins each — commodity credential-stuffing, not evasive, just high-volume...")
    time.sleep(min(pace, 2))

    events = []
    for i in range(_SPRAY_ACCOUNT_COUNT):
        actor = f"staff-{i:02d}.{run_id}@victimcorp.example"
        attempts = 2 if i % 2 else 3
        for j in range(attempts):
            events.append({
                "timestamp": _iso(now + timedelta(minutes=i * 0.5, seconds=j * 20)),
                "actor": actor, "action": "auth_fail", "source_ip": spray_ip, "outcome": "failure",
            })

    fired, incidents = post_events_and_check(client, events)
    caught = fired
    color = _GREEN if caught else _RED
    cordon(f"{len(events)} failed logins across {_SPRAY_ACCOUNT_COUNT} accounts, one IP -> "
           f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    if caught:
        dim(_describe_incidents(incidents))

    sc.record(
        5, "Password spray — single IP",
        "cross-actor correlation by exact source IP, 10 actors well above the 8-distinct-actor floor",
        caught, _describe_incidents(incidents) if caught else f"0 of {_SPRAY_ACCOUNT_COUNT} accounts ever triggered an incident",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 6 — Password spray: subnet-rotating proxy pool
# --------------------------------------------------------------------------------------------
#
# A step up from scenario 5 but still commodity-grade: a cheap residential-proxy pool rotates
# through a handful of addresses in the SAME /24 (unlike phase 3 scenario 1's elite one-fresh-
# subnet-per-victim technique, which really does evade this). Targets the same detector's
# /24-subnet grouping, proving basic proxy rotation within one block doesn't help the attacker.

_ROTATE_ACCOUNT_COUNT = 10


def run_scenario_6_password_spray_subnet_rotating(client: AegisClient, run_id: str, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(6, "PASSWORD SPRAY — SUBNET-ROTATING PROXY POOL")
    base_octet = _run_salt_octet(run_id + "-spray-rotating") % 240
    attacker(f"spraying {_ROTATE_ACCOUNT_COUNT} staff accounts through a cheap residential-proxy pool —")
    attacker(f"a different exact IP per attempt, but all within one 198.51.100.{base_octet}-ish /24...")
    time.sleep(min(pace, 2))

    events = []
    for i in range(_ROTATE_ACCOUNT_COUNT):
        actor = f"employee-{i:02d}.{run_id}@victimcorp.example"
        ip = f"198.51.100.{base_octet + i}"
        attempts = 2 if i % 2 else 3
        for j in range(attempts):
            events.append({
                "timestamp": _iso(now + timedelta(minutes=i * 0.5, seconds=j * 20)),
                "actor": actor, "action": "auth_fail", "source_ip": ip, "outcome": "failure",
            })

    fired, incidents = post_events_and_check(client, events)
    caught = fired
    color = _GREEN if caught else _RED
    cordon(f"{len(events)} failed logins across {_ROTATE_ACCOUNT_COUNT} accounts, "
           f"{_ROTATE_ACCOUNT_COUNT} IPs in one /24 -> {_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    if caught:
        dim(_describe_incidents(incidents))

    sc.record(
        6, "Password spray — subnet-rotating proxy pool",
        "cross-actor correlation groups by /24 subnet, not exact IP — a cheap same-block proxy pool doesn't evade it (only a fresh /24 per victim would, see phase 3 scenario 1)",
        caught, _describe_incidents(incidents) if caught else f"0 of {_ROTATE_ACCOUNT_COUNT} accounts ever triggered an incident",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 7 — Ransomware precursor chain
# --------------------------------------------------------------------------------------------
#
# The standard pre-encryption chain behind most real ransomware breaches: a phishing email
# gets a foothold, stolen credentials get used, the attacker enumerates as many files as they
# can reach, then stages a bulk exfiltration (double-extortion) before ever touching an
# encryptor. Reports each stage separately — "caught" for this scenario means EVERY stage
# independently alerted, i.e. defense-in-depth actually worked, not just the last one.

_RANSOMWARE_PHISH_HTML = """<html><body>
<p>Please review the attached invoice and confirm receipt at your earliest convenience.</p>
<p><a href="http://invoice-review-portal.top/view">View invoice</a></p>
</body></html>
"""


def run_scenario_7_ransomware_precursor_chain(client: AegisClient, run_id: str, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(7, "RANSOMWARE PRECURSOR CHAIN")
    actor = f"office-admin.{run_id}@victimcorp.example"
    attacker("stage 1/4: a phishing email delivers the initial lure...")
    time.sleep(min(pace, 2))

    phish_raw = build_email(
        from_display="Accounts Payable",
        from_addr="invoices@billing-review-portal.top",
        subject="Invoice attached — please confirm receipt",
        date=now,
        body_text="Please review the attached invoice and confirm receipt at your earliest convenience.",
        body_html=_RANSOMWARE_PHISH_HTML,
        spf="fail", dkim="fail", dmarc="fail",
    )
    phish_resp = analyze_email(client, phish_raw)
    phish_caught = phish_resp["verdict"].upper() != "SAFE"
    dim(f"phishing lure: verdict={phish_resp['verdict'].upper()} score={phish_resp['score']}/100 -> "
        f"{'CAUGHT' if phish_caught else 'MISSED'}")

    attacker(f"stage 2/4: stolen credentials get brute-forced into {_c(_BOLD, actor)}'s account...")
    time.sleep(min(pace, 2))
    brute_ip = f"203.0.113.{_run_salt_octet(actor + '-brute')}"
    t0 = now + timedelta(minutes=5)
    brute_events = [
        {
            "timestamp": _iso(t0 + timedelta(minutes=i)),
            "actor": actor, "action": "auth_fail", "source_ip": brute_ip, "outcome": "failure",
        }
        for i in range(6)
    ]
    success_at = t0 + timedelta(minutes=6)
    brute_events.append({
        "timestamp": _iso(success_at), "actor": actor, "action": "login",
        "source_ip": brute_ip, "outcome": "success", "geo": _NY_GEO,
    })
    brute_events.append({
        "timestamp": _iso(success_at + timedelta(minutes=1)), "actor": actor,
        "action": "privilege_change", "target": f"{actor} -> admin", "outcome": "success",
    })
    access_fired, access_incidents = post_events_and_check(client, brute_events)
    dim(f"credential access + privilege escalation -> {'CAUGHT' if access_fired else 'MISSED'}")

    attacker("stage 3/4: mass file enumeration across every share the account can reach...")
    time.sleep(min(pace, 2))
    enum_start = success_at + timedelta(minutes=2)
    enum_events = [
        {
            "timestamp": _iso(enum_start + timedelta(seconds=i * 10)),
            "actor": actor, "action": "file_access", "source_ip": brute_ip,
            "target": f"shared/dept-{i % 5}/file-{i}.docx", "outcome": "success",
        }
        for i in range(25)
    ]
    enum_fired, enum_incidents = post_events_and_check(client, enum_events)
    dim(f"25 files across 5 shares enumerated -> {'CAUGHT' if enum_fired else 'MISSED'}")

    attacker("stage 4/4: bulk exfiltration before any encryptor would even run (double-extortion staging)...")
    time.sleep(min(pace, 2))
    exfil_events = [{
        "timestamp": _iso(enum_start + timedelta(minutes=10)),
        "actor": actor, "action": "data_transfer", "source_ip": brute_ip,
        "target": "ransomware-staging-relay.example.net", "bytes": 650_000_000, "outcome": "success",
    }]
    exfil_fired, exfil_incidents = post_events_and_check(client, exfil_events)
    dim(f"650MB transfer to an unfamiliar host -> {'CAUGHT' if exfil_fired else 'MISSED'}")

    all_incidents = access_incidents + enum_incidents + exfil_incidents
    stages = {
        "phishing lure": phish_caught,
        "credential access/privilege escalation": access_fired,
        "mass file enumeration": enum_fired,
        "bulk exfiltration": exfil_fired,
    }
    caught = all(stages.values())
    color = _GREEN if caught else _RED
    cordon(f"chain complete -> {_c(_BOLD + color, 'ALL 4 STAGES CAUGHT' if caught else 'AT LEAST ONE STAGE MISSED')}")

    detail = "; ".join(f"{name}={'caught' if ok else 'MISSED'}" for name, ok in stages.items())
    sc.record(
        7, "Ransomware precursor chain",
        "phish -> stolen-credential access -> mass file enumeration -> bulk exfiltration; every stage should independently alert (defense in depth)",
        caught, detail + ("; " + _describe_incidents(all_incidents) if all_incidents else ""),
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 8 — Malicious attachment / commodity malware lure
# --------------------------------------------------------------------------------------------
#
# A generic, mass-blasted commodity-malware email: urgency, a double-extension executable
# disguised as a PDF invoice, AND a link to a host that is a real, literal match in the
# bundled threat-intel snapshot (app/threat_intel/data/hostnames.txt) — not a synthetic
# look-alike, an exact feed hit. Targets attachment_risk.py (ATTACHMENT_DOUBLE_EXTENSION +
# ATTACHMENT_RISKY_EXTENSION) and known_bad_urls.py (LINK_KNOWN_MALICIOUS).

_MALWARE_LURE_HTML = """<html><body>
<p>URGENT: Your invoice payment is past due. Review the attached document immediately to
avoid service interruption.</p>
<p><a href="http://001dda.top/invoice-portal">Click here to review</a></p>
</body></html>
"""


def run_scenario_8_malicious_attachment(client: AegisClient, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(8, "MALICIOUS ATTACHMENT / COMMODITY MALWARE LURE")
    attacker("a mass-blasted 'overdue invoice' email carries a PDF-disguised .exe attachment")
    attacker("and a link to a host that's a literal, exact hit in our own threat-intel feed...")
    time.sleep(min(pace, 2))

    raw = build_email(
        from_display="Billing Department",
        from_addr="noreply@invoice-notify-service.click",
        subject="URGENT: Invoice payment past due — action required immediately",
        date=now,
        body_text=(
            "URGENT: Your invoice payment is past due. Review the attached document "
            "immediately to avoid service interruption."
        ),
        body_html=_MALWARE_LURE_HTML,
        spf="fail", dkim="fail", dmarc="softfail",
        attachment=("Invoice_89213.pdf.exe", "application/octet-stream"),
    )
    resp = analyze_email(client, raw)
    verdict = resp["verdict"].upper()
    score = resp["score"]
    caught = verdict != "SAFE"
    ids = _indicator_ids(resp)

    color = _GREEN if caught else _RED
    cordon(f"case {resp['id']} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    for title in (i["title"] for i in resp["indicators"]):
        dim(f"- {title}")

    sc.record(
        8, "Malicious attachment / commodity malware lure",
        "double-extension executable disguised as a PDF + urgency + a link matching a real threat-intel feed hostname",
        caught, f"verdict={verdict} score={score}/100, indicators={', '.join(ids)}",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 9 — Compromised legitimate vendor: calm lure (second BEC/vendor variant)
# --------------------------------------------------------------------------------------------
#
# Distinct mechanism from scenario 3: no urgency language at all, and no payment/wire ask —
# just a calm credential-harvest request from a sender with real prior contact (e.g. a small
# org's outsourced IT/MSP provider, a very common real SMB breach vector), corroborated by a
# link to a domain that doesn't match the vendor's own or any trusted-vendor allowlist entry.
# Targets trusted_sender_anomaly.py's off-pattern-link corroboration path specifically (the
# ONE path that doesn't need urgency to fire).

_MSP_DOMAIN = "brightpath-itservices.example"
_MSP_FROM = f"support@{_MSP_DOMAIN}"


def run_scenario_9_compromised_vendor_calm_lure(client: AegisClient, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(9, "COMPROMISED VENDOR — CALM, NO-URGENCY LURE")
    setup(f"Seeding real per-account sender history for {_MSP_DOMAIN} (our outsourced IT provider)...")
    for i, note in enumerate([
        "Your scheduled maintenance window completed successfully, no action needed.",
        "This month's support summary is attached — 2 tickets resolved, no open issues.",
    ]):
        raw = build_email(
            from_display="BrightPath IT Services",
            from_addr=_MSP_FROM,
            subject=f"IT support update #{i + 1}",
            date=now - timedelta(minutes=5 - i),
            body_text=note,
        )
        resp = analyze_email(client, raw)
        dim(f"prior email {i + 1}/2: verdict={resp['verdict'].upper()} score={resp['score']}/100 (routine, expected safe)")
    time.sleep(min(pace, 1))

    attacker(f"{_MSP_DOMAIN}'s mailbox gets compromised — the follow-up is calm, no urgency at")
    attacker("all, just a routine-sounding ask to re-confirm portal access via an unfamiliar link...")
    time.sleep(min(pace, 2))

    html = (
        '<html><body><p>As part of our regular security maintenance, please confirm your '
        "login credentials remain active by signing back into the support portal.</p>"
        '<p><a href="https://brightpath-portal-secure.example/login">Portal login</a></p>'
        "</body></html>"
    )
    raw = build_email(
        from_display="BrightPath IT Services",
        from_addr=_MSP_FROM,
        subject="Routine portal access confirmation",
        date=now,
        body_text=(
            "As part of our regular security maintenance, please confirm your login "
            "credentials remain active by signing back into the support portal."
        ),
        body_html=html,
        spf="pass", dkim="pass", dmarc="pass",
    )
    resp = analyze_email(client, raw)
    verdict = resp["verdict"].upper()
    score = resp["score"]
    caught = verdict != "SAFE"
    ids = _indicator_ids(resp)

    color = _GREEN if caught else _RED
    cordon(f"case {resp['id']} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    for title in (i["title"] for i in resp["indicators"]):
        dim(f"- {title}")

    sc.record(
        9, "Compromised vendor — calm, no-urgency lure",
        "credential request from a sender with real prior history, no urgency at all — corroborated only by a link to an unfamiliar domain (app.indicators.trusted_sender_anomaly)",
        caught, f"verdict={verdict} score={score}/100, indicators={', '.join(ids)}",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 10 — Benign-heavy control (the hard bar: zero false positives)
# --------------------------------------------------------------------------------------------
#
# Deliberately pressure-tests the exact margins the scenarios above sit next to: varied normal
# employee activity, a real (SEEN_BEFORE) vendor's routine correspondence with no risky ask, a
# one-off legitimate first-time finance-file access (scored but should stay under SAFE_MAX on
# its own), and a handful of employees mistyping a password from a shared office IP — one
# below the cross-actor spray floor. Deliberately does NOT include a "legitimate business
# travel" case: a first trip to a brand-new country is, today, indistinguishable from
# new-geo account takeover to anomalous_location.py — an accepted, documented product
# trade-off (same spirit as every other known gap this repo tracks), not something to paper
# over by excluding it from scenario 4 or by quietly declaring it "not a false positive."

_CONTROL_BENIGN_TARGETS = [
    "shared/onboarding/welcome-guide.pdf",
    "shared/newsletter-draft.docx",
    "shared/volunteer-schedule.xlsx",
]
_CONTROL_SHARED_IP_GROUP_SIZE = 6  # 2 below cross_actor_spray_min_actors (8)


def run_scenario_10_benign_control(client: AegisClient, run_id: str, now: datetime, pace: float, sc: Scorecard) -> None:
    scenario(10, "BENIGN-HEAVY CONTROL (HARD BAR: ZERO FALSE POSITIVES)")
    attacker("(no attacker this round — ordinary staff activity, a real vendor's routine")
    attacker("correspondence, a one-off legitimate finance lookup, and a few employees who")
    attacker("mistyped their password from the shared office Wi-Fi)")
    time.sleep(0.5)

    for index in range(4):
        day = _snap_to_weekday(now + timedelta(days=index))
        actor = f"control-{index}.{run_id}@victimcorp.example"
        home_ip = f"{_HOME_IP_BASE}.{_run_salt_octet(actor + '-control')}"
        events = [{
            "timestamp": _iso(day.replace(hour=10, minute=0)),
            "actor": actor, "action": "login", "source_ip": home_ip,
            "outcome": "success", "geo": _NY_GEO,
        }]
        for i in range(4 + index):
            events.append({
                "timestamp": _iso(day.replace(hour=10, minute=5 + i * 5)),
                "actor": actor, "action": "file_access", "source_ip": home_ip,
                "target": _CONTROL_BENIGN_TARGETS[i % len(_CONTROL_BENIGN_TARGETS)], "outcome": "success",
            })
        fired, incidents = post_events_and_check(client, events)
        if fired:
            cordon(_c(_BOLD + _RED, f"FALSE POSITIVE: {actor} (normal activity) raised an incident!"))
            dim(_describe_incidents(incidents))
            sc.record_false_positive(f"{actor}: {_describe_incidents(incidents)}")
        else:
            cordon(f"{actor}: varied normal day, correctly stayed safe.")

    treasurer = f"treasurer.{run_id}@victimcorp.example"
    treasurer_ip = f"{_HOME_IP_BASE}.{_run_salt_octet(treasurer + '-control')}"
    setup(f"Building a short baseline for {treasurer} (treasurer), then one legitimate first-time finance lookup...")
    baseline_day = _snap_to_weekday(now - timedelta(days=5))
    baseline_events = [{
        "timestamp": _iso(baseline_day.replace(hour=11, minute=0)),
        "actor": treasurer, "action": "login", "source_ip": treasurer_ip,
        "outcome": "success", "geo": _NY_GEO,
    }]
    for i in range(5):
        baseline_events.append({
            "timestamp": _iso(baseline_day.replace(hour=11, minute=5 + i * 5)),
            "actor": treasurer, "action": "file_access", "source_ip": treasurer_ip,
            "target": _CONTROL_BENIGN_TARGETS[i % len(_CONTROL_BENIGN_TARGETS)], "outcome": "success",
        })
    fired, _ = post_events_and_check(client, baseline_events)
    if fired:
        cordon(_c(_BOLD + _RED, "unexpected incident during treasurer baseline-building!"))

    lookup_day = _snap_to_weekday(now + timedelta(days=1))
    lookup_events = [{
        "timestamp": _iso(lookup_day.replace(hour=11, minute=0)),
        "actor": treasurer, "action": "login", "source_ip": treasurer_ip,
        "outcome": "success", "geo": _NY_GEO,
    }, {
        "timestamp": _iso(lookup_day.replace(hour=11, minute=5)),
        "actor": treasurer, "action": "file_access", "source_ip": treasurer_ip,
        "target": "finance/this-quarter-giving-summary.xlsx", "outcome": "success",
    }]
    fired, incidents = post_events_and_check(client, lookup_events)
    if fired:
        cordon(_c(_BOLD + _RED, "FALSE POSITIVE: treasurer's first legitimate finance lookup raised an incident!"))
        dim(_describe_incidents(incidents))
        sc.record_false_positive(f"{treasurer}: {_describe_incidents(incidents)}")
    else:
        cordon(f"{treasurer}: first-ever (legitimate) finance-file access -> correctly stayed safe.")

    setup(f"Seeding real sender history for {_VENDOR_DOMAIN}, then one more routine, risk-free email...")
    raw = build_email(
        from_display="Summit Office Supply — Billing",
        from_addr=_VENDOR_FROM,
        subject="Thank you for your order",
        date=now,
        body_text="Thank you for your recent order — it has shipped and should arrive within 3-5 business days.",
    )
    resp = analyze_email(client, raw)
    if resp["verdict"].upper() != "SAFE":
        cordon(_c(_BOLD + _RED, f"FALSE POSITIVE: routine vendor shipping email scored {resp['verdict'].upper()}!"))
        sc.record_false_positive(f"routine vendor email: verdict={resp['verdict'].upper()} score={resp['score']}/100")
    else:
        cordon(f"routine vendor shipping email: verdict=SAFE score={resp['score']}/100 -> correctly stayed safe.")

    shared_ip_day = _snap_to_weekday(now + timedelta(days=2))
    control_shared_ip = f"198.51.{_run_salt_octet(run_id + '-control-shared')}.50"
    events = [{
        "timestamp": _iso(shared_ip_day.replace(hour=9, minute=i)),
        "actor": f"wifi-user-{i}.{run_id}@victimcorp.example",
        "action": "auth_fail", "source_ip": control_shared_ip, "outcome": "failure",
    } for i in range(_CONTROL_SHARED_IP_GROUP_SIZE)]
    fired, incidents = post_events_and_check(client, events)
    if fired:
        cordon(_c(_BOLD + _RED,
                  f"FALSE POSITIVE: {_CONTROL_SHARED_IP_GROUP_SIZE} employees mistyping a password "
                  f"from shared Wi-Fi raised an incident!"))
        dim(_describe_incidents(incidents))
        sc.record_false_positive(f"{_CONTROL_SHARED_IP_GROUP_SIZE} employees, shared IP: {_describe_incidents(incidents)}")
    else:
        cordon(f"{_CONTROL_SHARED_IP_GROUP_SIZE} employees mistyping a password from shared Wi-Fi "
               "(below the spray floor) -> correctly stayed safe.")


# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Cordon backend URL (default: %(default)s)")
    parser.add_argument("--pace", type=float, default=2.0, help="Seconds between scenarios (default: %(default)s)")
    parser.add_argument("--no-prompt", action="store_true", help="Skip the 'press Enter to start' gate")
    args = parser.parse_args()

    enforce_target_allowlist(args.base_url)

    banner("CORDON REAL-WORLD RED-TEAM SUITE — commodity/criminal attacks (authorized, synthetic data)")
    print(_c(_DIM, f"Target backend : {args.base_url}"))
    print(_c(_DIM, f"Frontend       : {FRONTEND_URL}"))
    print()
    print("Every scenario here is a REAL technique that breaches under-resourced orgs —")
    print("a miss is a genuine gap, not expected evasion. Zero false positives is the hard bar.")
    print("This run creates and uses its OWN brand-new, isolated account (never reused).")
    print("This script refuses to run against any host that isn't localhost or explicitly")
    print("listed in ALLOWED_HOSTS (enforced above, before any network call was made).")

    if not args.no_prompt:
        try:
            input(_c(_BOLD, "\nPress Enter to launch the campaign..."))
        except EOFError:
            pass

    client = AegisClient(args.base_url)
    sc = Scorecard()

    try:
        run_id = os.urandom(4).hex()
        create_isolated_account(client, run_id)

        now = datetime.now(timezone.utc)

        run_scenario_1_credential_phishing(client, now, args.pace, sc)
        run_scenario_2_bec_spoofed_sender(client, now, args.pace, sc)
        run_scenario_3_bec_compromised_vendor(client, now, args.pace, sc)
        run_scenario_4_account_takeover(client, run_id, now, args.pace, sc)
        run_scenario_5_password_spray_single_ip(client, run_id, now - timedelta(hours=2), args.pace, sc)
        run_scenario_6_password_spray_subnet_rotating(client, run_id, now - timedelta(hours=1), args.pace, sc)
        run_scenario_7_ransomware_precursor_chain(client, run_id, now - timedelta(hours=4), args.pace, sc)
        run_scenario_8_malicious_attachment(client, now, args.pace, sc)
        run_scenario_9_compromised_vendor_calm_lure(client, now, args.pace, sc)
        run_scenario_10_benign_control(client, run_id, now - timedelta(days=7), args.pace, sc)

        sc.print_report()

        banner("CAMPAIGN COMPLETE")
        print(f"Run id (actor suffix) : {run_id}")
        print("Check the Cases and Detections tabs in the frontend —")
        print(f"{FRONTEND_URL}")
        print()
        print(_c(_DIM, "This run's account is never reused — re-run any time for a fully fresh, isolated run."))
        return 1 if sc.false_positives else 0
    except HTTPStatusError as exc:
        print(_c(_RED, f"\n[ERROR] {exc}"), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(_c(_RED, f"\n[ERROR] {exc}"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
