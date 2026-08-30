#!/usr/bin/env python3
"""PHASE 2 — brutal red-team stress test against a LOCAL Cordon instance. Authorized, dev-only,
synthetic data. Unlike scripts/attack_sim.py (phase 1, one obvious attack chain), every scenario
here is deliberately built against a specific, confirmed edge of Cordon's current detection
rules — the point is to find what Cordon MISSES, not to demo what it catches. Each scenario's
docstring below cites the exact backend module/threshold it targets; nothing here is guessed.

This script only ever talks to --base-url (default http://localhost:8000) — check that value
before running it. It never sends real email and never performs any real network attack; every
"attacker" action is a synthetic API call, exactly like phase 1. Pointing --base-url at a real
deployment means the case/incident data this creates is real, persisted data there — see
scripts/cleanup_sim.py to delete it afterward (unchanged — it already wipes every case/incident
for whichever account you log into, regardless of which script created them).

Usage:
    python3 scripts/attack_sim_phase2.py
    python3 scripts/attack_sim_phase2.py --base-url http://localhost:8000 --pace 0 --no-prompt

Account resolution is identical to phase 1 (same env vars, same flags, same signup-or-login
logic) — run this against the same account as phase 1 if you like; cleanup_sim.py wipes both.

Stdlib only. Ends by printing a SCORECARD: for each of the 7 scenarios, whether Cordon raised a
non-safe verdict/incident, plus an overall detection rate, any false positives from the benign
activity mixed in throughout, and a "weakest spots" list naming the specific mechanism behind
each miss.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_ACCOUNT_NAME = "Aegis Demo Account"
EMAIL_ENV_VAR = "AEGIS_EMAIL"
PASSWORD_ENV_VAR = "AEGIS_PASSWORD"
FRONTEND_URL = "http://localhost:5173"

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
    print(_c(_BOLD + _CYAN, "=" * 76))
    print(_c(_BOLD + _CYAN, f" {title}"))
    print(_c(_BOLD + _CYAN, "=" * 76))


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
    """Thin stdlib HTTP wrapper — same shape as phase 1's, duplicated rather than imported
    (matches this repo's existing convention: each script under scripts/ is self-contained)."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token: str | None = None

    def _request(self, method: str, path: str, *, json_body: dict | None = None,
                 auth: bool = True) -> dict:
        url = self.base_url + path
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        headers = {"Content-Type": "application/json"}
        if auth:
            if not self.token:
                raise RuntimeError("AegisClient.token is not set — call login()/signup() first.")
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

    def get(self, path: str, *, auth: bool = True) -> dict:
        return self._request("GET", path, auth=auth)


def ensure_account(client: AegisClient, *, email: str, password: str, account_name: str) -> None:
    """Identical logic to phase 1's — logs in if the account exists, signs up if not, never
    prints the password."""
    setup(f"Logging into {_c(_BOLD, email)} on this local Cordon instance...")
    try:
        resp = client.post("/api/auth/login", {"email": email, "password": password}, auth=False)
        client.token = resp["access_token"]
        cordon(f"logged in. account_id={resp['user']['account_id']}")
        return
    except HTTPStatusError as exc:
        if exc.status != 401:
            raise

    setup(f"No matching login — creating the account {_c(_BOLD, email)}...")
    try:
        resp = client.post(
            "/api/auth/signup",
            {"account_name": account_name, "email": email, "password": password},
            auth=False,
        )
    except HTTPStatusError as exc:
        if exc.status == 409:
            raise RuntimeError(
                f"An account for {email} already exists on this instance, but the password "
                f"you provided doesn't match it. Re-check AEGIS_PASSWORD / --password (or the "
                f"password you typed at the prompt) and try again."
            ) from None
        raise
    client.token = resp["access_token"]
    cordon(f"account created. account_id={resp['user']['account_id']}")


# --------------------------------------------------------------------------------------------
# Scorecard
# --------------------------------------------------------------------------------------------


@dataclass
class ScorecardEntry:
    number: int
    name: str
    mechanism: str
    caught: bool  # True = Cordon raised a non-safe verdict/incident for this scenario
    detail: str


@dataclass
class Scorecard:
    entries: list[ScorecardEntry] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)  # benign actors that got flagged

    def record(self, number: int, name: str, mechanism: str, caught: bool, detail: str) -> None:
        self.entries.append(ScorecardEntry(number, name, mechanism, caught, detail))

    def record_false_positive(self, description: str) -> None:
        self.false_positives.append(description)

    def print_report(self) -> None:
        banner("SCORECARD — honest results, not a demo")

        caught_count = sum(1 for e in self.entries if e.caught)
        total = len(self.entries)
        rate_color = _GREEN if caught_count >= total * 0.7 else _YELLOW if caught_count >= total * 0.4 else _RED

        print()
        for e in self.entries:
            tag = _c(_BOLD + _GREEN, "CAUGHT") if e.caught else _c(_BOLD + _RED, "MISSED")
            print(f"  {e.number}. {e.name:<32} {tag}")
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
            print(_c(_BOLD + _YELLOW, "Weakest spots (fix these first):"))
            for e in misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        else:
            print(_c(_BOLD + _GREEN, "No misses this run — every scenario was caught."))


# --------------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------------

_NY_GEO = {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060}
_MOSCOW_GEO = {"country": "RU", "region": "Moscow", "lat": 55.7558, "lon": 37.6173}
_HOME_IP = "198.51.100.20"


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _business_days(start: datetime, count: int) -> list[datetime]:
    """`count` consecutive weekdays starting at-or-after `start` — used everywhere a scenario
    needs to avoid off_hours_access's unconditional weekend check (app/detections/
    off_hours_access.py: `ts.weekday() >= 5` always counts as off-hours, baseline or not) so a
    scenario's outcome is never accidentally decided by which day of the week it happened to
    run on."""
    days: list[datetime] = []
    current = start
    while len(days) < count:
        if current.weekday() < 5:
            days.append(current)
        current += timedelta(days=1)
    return days


def post_events_and_check(client: AegisClient, events: list[dict]) -> tuple[bool, list[dict]]:
    """Returns (any_incident_created, incidents_created)."""
    resp = client.post("/api/events", {"events": events})
    incidents = resp.get("incidents_created") or []
    return bool(incidents), incidents


def _describe_incidents(incidents: list[dict]) -> str:
    if not incidents:
        return "no incident raised — verdict stayed safe"
    parts = []
    for inc in incidents:
        parts.append(
            f"{inc['verdict'].upper()} risk={inc['score']}/100 "
            f"[{', '.join(inc['detection_types'])}] (actor={inc['actor']})"
        )
    return "; ".join(parts)


# --------------------------------------------------------------------------------------------
# Scenario 1 — Evasive phishing
# --------------------------------------------------------------------------------------------
#
# Targets: app/indicators/urgency_language.py + credential_payment.py (fixed regex phrase
# banks — zero score if the text just doesn't use those exact phrases) and
# app/indicators/lookalike_domain.py (only checks the 16 brands curated in
# app/indicators/data/brands.yaml — impersonating anything else is invisible to it). Also
# avoids app/indicators/ai_authored.py's stylometric-regularity signals on purpose (a
# TOO-polished lure trips that instead) via natural sentence variation and a contraction.
# Authentication-Results is set to full pass, representing an attacker who controls their own
# domain's DNS (a bought/aged domain) rather than someone else's.

_EVASIVE_PHISH_EMAIL = """From: "Okta" <no-reply@oktaverify-notifications.com>
To: target-employee@ourcompany.example
Subject: Weekly sign-in approvals summary
Date: Mon, 24 Aug 2026 10:05:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom=oktaverify-notifications.com; dkim=pass header.d=oktaverify-notifications.com; dmarc=pass header.from=oktaverify-notifications.com
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi there,

A few new sign-in approvals showed up on your account this week, most from your
usual laptop but one from a device we haven't seen before. We've started sending
this summary to a few teams as part of a broader review of device trust across
the company.

Take a look when you get a chance: https://oktaverify-notifications.com/approvals/review

No action is needed if everything looks familiar to you. If something doesn't
look right, forwarding this to IT is the easiest way to flag it.

- IT Operations
"""


def run_scenario_1_evasive_phishing(client: AegisClient, pace: float, sc: Scorecard) -> None:
    scenario(1, "EVASIVE PHISHING")
    attacker("crafting a calm, professionally-written lure impersonating 'Okta' (not one of")
    attacker("the 16 curated brands) with no urgency language and a domain that owns its own")
    attacker("DNS (SPF/DKIM/DMARC all pass)...")
    time.sleep(min(pace, 2))

    resp = client.post("/api/analyze/text", {"raw_text": _EVASIVE_PHISH_EMAIL})
    verdict = resp["verdict"].upper()
    score = resp["score"]
    indicator_titles = [i["title"] for i in resp["indicators"]]
    caught = verdict != "SAFE"

    color = _GREEN if caught else _RED
    cordon(f"case {resp['id']} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    if indicator_titles:
        for title in indicator_titles:
            dim(f"- {title}")
    else:
        dim("(zero indicators fired)")

    sc.record(
        1, "Evasive phishing", "urgency/credential phrase banks + curated-brand-only lookalike check",
        caught, f"verdict={verdict} score={score}/100, {len(indicator_titles)} indicator(s) fired",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 5 — Supply-chain phishing
# --------------------------------------------------------------------------------------------
#
# Same underlying technique as scenario 1 (uncurated brand, no phrase-bank matches) but a
# distinct vendor/partner narrative and domain, so it's its own finding rather than a repeat.

_SUPPLY_CHAIN_EMAIL = """From: "Meridian Compliance Partners" <notifications@meridian-compliance-portal.com>
To: target-employee@ourcompany.example
Subject: Your Q3 vendor access review is ready
Date: Wed, 26 Aug 2026 09:40:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom=meridian-compliance-portal.com; dkim=pass header.d=meridian-compliance-portal.com; dmarc=pass header.from=meridian-compliance-portal.com
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi,

Meridian handles the quarterly vendor access reviews for a few of our partner
organizations, and yours is part of this cycle. It's a short form, mostly
checking which systems you still need access to.

You can find it here: https://meridian-compliance-portal.com/reviews/q3-2026

It usually takes most people about five minutes. Let me know if you run into
any trouble opening it.

Dana Reyes
Meridian Compliance Partners
"""


def run_scenario_5_supply_chain(client: AegisClient, pace: float, sc: Scorecard) -> None:
    scenario(5, "SUPPLY-CHAIN PHISHING")
    attacker("impersonating a fictional compliance/vendor-management partner ('Meridian') —")
    attacker("a trusted-looking B2B relationship, not an obvious consumer-brand lookalike...")
    time.sleep(min(pace, 2))

    resp = client.post("/api/analyze/text", {"raw_text": _SUPPLY_CHAIN_EMAIL})
    verdict = resp["verdict"].upper()
    score = resp["score"]
    indicator_titles = [i["title"] for i in resp["indicators"]]
    caught = verdict != "SAFE"

    color = _GREEN if caught else _RED
    cordon(f"case {resp['id']} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    if indicator_titles:
        for title in indicator_titles:
            dim(f"- {title}")
    else:
        dim("(zero indicators fired)")

    sc.record(
        5, "Supply-chain phishing", "curated-brand-only lookalike check has no notion of B2B vendor trust",
        caught, f"verdict={verdict} score={score}/100, {len(indicator_titles)} indicator(s) fired",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 2 — Low-and-slow exfiltration
# --------------------------------------------------------------------------------------------
#
# Targets: app/detections/data_exfiltration.py fires per-EVENT only, when a single
# data_transfer/file_download's bytes exceeds settings.exfil_large_transfer_bytes (500MB
# default). There is no cumulative/rolling-volume check for bytes anywhere in the codebase —
# app/baselines only tracks event COUNT for file_access/file_download, never data_transfer
# bytes. Each daily batch is also its own detection window (app/api/routes/events.py anchors
# the 24h lookback to the batch's own max timestamp), so spreading transfers across many days
# means no single evaluation ever sees more than ~24h of them regardless.

_EXFIL_HOST = "unfamiliar-storage-relay.example.net"


def run_scenario_2_low_and_slow_exfiltration(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(2, "LOW-AND-SLOW EXFILTRATION")
    actor = f"lowslow.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)} moves data out in small pieces across 9 business days —")
    attacker(f"20-80MB at a time to {_EXFIL_HOST}, never once near the 500MB single-event")
    attacker("threshold, ~1.4GB total by the end...")
    time.sleep(min(pace, 2))

    days = _business_days(t0, 9)
    any_incident = False
    incidents_seen: list[dict] = []
    total_bytes = 0

    for day_index, day in enumerate(days):
        chunk_sizes = [30_000_000 + (day_index * 4_000_000), 55_000_000 - (day_index * 1_000_000)]
        events = []
        for i, size in enumerate(chunk_sizes):
            ts = day.replace(hour=15, minute=i * 10)
            events.append(
                {
                    "timestamp": _iso(ts),
                    "actor": actor,
                    "action": "data_transfer",
                    "source_ip": _HOME_IP,
                    "target": _EXFIL_HOST,
                    "bytes": size,
                    "outcome": "success",
                }
            )
            total_bytes += size
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
        dim(f"day {day_index + 1}/9 ({day.date()}): {len(events)} transfer(s), "
            f"{sum(c for c in chunk_sizes):,} bytes -> {'incident raised' if fired else 'no incident'}")

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(
        f"after 9 days and {total_bytes:,} total bytes moved -> "
        f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}"
    )
    sc.record(
        2, "Low-and-slow exfiltration", "per-event byte threshold, no cumulative-volume check for data_transfer",
        caught, _describe_incidents(incidents_seen) if caught else f"no incident across any of 9 daily batches ({total_bytes:,} bytes total)",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 3 — Password spray at scale
# --------------------------------------------------------------------------------------------
#
# Targets: app/detections/brute_force.py fires at >=5 auth_fail events for ONE actor within a
# 15-minute window. There is no same-source-IP-across-many-actors detector anywhere in
# app/detections/ — confirmed by reading every module in that directory. 15 accounts x 2-3
# failed attempts each (well under the per-actor floor) is stealthier in real life and
# invisible to this rule set by construction.

_SPRAY_IP = "198.51.100.77"
_SPRAY_ACCOUNT_COUNT = 15


def run_scenario_3_password_spray(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(3, "PASSWORD SPRAY AT SCALE")
    attacker(f"spraying {_SPRAY_ACCOUNT_COUNT} different accounts from {_SPRAY_IP}, only 2-3")
    attacker("failed attempts per account — never enough for any single account to look like")
    attacker("brute-forcing...")
    time.sleep(min(pace, 2))

    events = []
    for i in range(_SPRAY_ACCOUNT_COUNT):
        actor = f"spray-{i:02d}.{run_id}@victimcorp.example"
        attempts = 2 if i % 3 else 3
        for j in range(attempts):
            events.append(
                {
                    "timestamp": _iso(t0 + timedelta(minutes=i, seconds=j * 20)),
                    "actor": actor,
                    "action": "auth_fail",
                    "source_ip": _SPRAY_IP,
                    "outcome": "failure",
                }
            )

    fired, incidents = post_events_and_check(client, events)
    caught = fired
    color = _GREEN if caught else _RED
    cordon(
        f"{len(events)} failed logins across {_SPRAY_ACCOUNT_COUNT} accounts, same source IP -> "
        f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}"
    )
    sc.record(
        3, "Password spray at scale", "brute-force detector is scoped per-actor only, no cross-actor/same-IP correlation",
        caught, _describe_incidents(incidents) if caught else f"0 of {_SPRAY_ACCOUNT_COUNT} accounts individually crossed the 5-failure floor",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 4 — Insider threat
# --------------------------------------------------------------------------------------------
#
# Targets: app/detections/mass_file_access.py's baseline-volume-anomaly path (fires only if a
# day's count exceeds mean + 3*stddev of the actor's own history, app/core/config.py's
# baseline_volume_stddev_multiplier=3.0 — a wide bar) and the complete absence of any
# per-resource/target-sensitivity baseline anywhere in app/baselines/aggregation.py: the
# system can represent "more files than this actor's history," never "files this actor has
# never touched" or "files far outside this actor's normal scope." Baseline is built honestly
# via the real ingestion path (6 business days of mundane activity) before the "attack" day,
# which stays at the SAME volume as a normal day (~5 files, matching their own established
# range) but touches finance/HR/legal targets they've never touched before — a real insider
# escalation that never trips off_hours/anomalous_location (same hours/location throughout)
# and, by construction, shouldn't trip the volume baseline either, since the count itself
# isn't actually elevated.

_NORMAL_TARGETS = [
    "shared/team-project/roadmap.docx",
    "shared/team-project/notes.docx",
    "shared/team-project/status-update.pptx",
    "shared/team-project/budget-draft.xlsx",
    "shared/team-project/meeting-minutes.docx",
]
_SENSITIVE_TARGETS = [
    "finance/q3-budget-actuals.xlsx",
    "finance/payroll-adjustments.xlsx",
    "hr/comp-review-2026.xlsx",
    "hr/pending-terminations.docx",
    "legal/pending-litigation-notes.docx",
]
_BASELINE_DAILY_COUNTS = [4, 4, 3, 4, 5, 4]


def run_scenario_4_insider_threat(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(4, "INSIDER THREAT")
    actor = f"insider.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)} has valid credentials and never leaves their usual hours or")
    attacker("location — over 6 days we first establish their real baseline (~4 files/day,")
    attacker("routine team documents), then have them touch finance/HR/legal files they've")
    attacker("never accessed before, at a totally normal DAILY VOLUME for them...")
    time.sleep(min(pace, 2))

    baseline_days = _business_days(t0, len(_BASELINE_DAILY_COUNTS))
    for day_index, (day, count) in enumerate(zip(baseline_days, _BASELINE_DAILY_COUNTS)):
        events = [
            {
                "timestamp": _iso(day.replace(hour=15, minute=0)),
                "actor": actor,
                "action": "login",
                "source_ip": _HOME_IP,
                "outcome": "success",
                "geo": _NY_GEO,
            }
        ]
        for i in range(count):
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=15, minute=5 + i * 3)),
                    "actor": actor,
                    "action": "file_access",
                    "source_ip": _HOME_IP,
                    "target": _NORMAL_TARGETS[i % len(_NORMAL_TARGETS)],
                    "outcome": "success",
                }
            )
        fired, _ = post_events_and_check(client, events)
        dim(f"baseline day {day_index + 1}/{len(_BASELINE_DAILY_COUNTS)} ({day.date()}): "
            f"{count} routine file accesses -> {'incident raised (unexpected!)' if fired else 'safe, as expected'}")

    attack_day = _business_days(baseline_days[-1] + timedelta(days=1), 1)[0]
    attack_count = 5  # matches the top of their established normal range on purpose
    events = [
        {
            "timestamp": _iso(attack_day.replace(hour=15, minute=0)),
            "actor": actor,
            "action": "login",
            "source_ip": _HOME_IP,
            "outcome": "success",
            "geo": _NY_GEO,
        }
    ]
    for i in range(attack_count):
        events.append(
            {
                "timestamp": _iso(attack_day.replace(hour=15, minute=5 + i * 3)),
                "actor": actor,
                "action": "file_access",
                "source_ip": _HOME_IP,
                "target": _SENSITIVE_TARGETS[i % len(_SENSITIVE_TARGETS)],
                "outcome": "success",
            }
        )
    fired, incidents = post_events_and_check(client, events)

    caught = fired
    color = _GREEN if caught else _RED
    cordon(
        f"attack day ({attack_day.date()}): {attack_count} finance/HR/legal file accesses, "
        f"same hours/location as always -> {_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}"
    )
    sc.record(
        4, "Insider threat", "no per-resource/target-sensitivity baseline exists; volume-only anomaly needs a real spike, not just unfamiliar targets",
        caught, _describe_incidents(incidents) if caught else "same hours/location/volume as their own established baseline — nothing fired",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 6 — Concurrent compromised accounts
# --------------------------------------------------------------------------------------------
#
# Originally targeted app/db/models.py's Incident being scoped to exactly one
# (account_id, actor) with no multi-actor "campaign"/correlation concept anywhere in the
# schema — closed by Stage 1 detection hardening (app.detections.cross_actor,
# Incident.related_actors): correlated actors sharing a source-IP subnet now merge into
# ONE linked incident. This scenario is deliberately LOUD per-actor (unlike scenario 2/3)
# since the point isn't evasion, it's checking whether 3 simultaneous compromises are each
# still caught correctly under load, and confirming (not assuming) whether anything links
# them together.

_CONCURRENT_ACTOR_COUNT = 3


def run_scenario_6_concurrent_compromise(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(6, "CONCURRENT COMPROMISED ACCOUNTS")
    attacker(f"{_CONCURRENT_ACTOR_COUNT} accounts compromised in the same window — each gets its")
    attacker("own brute-force -> impossible-travel -> large-exfiltration chain, submitted together...")
    time.sleep(min(pace, 2))

    actors = [f"concurrent-{i + 1}.{run_id}@victimcorp.example" for i in range(_CONCURRENT_ACTOR_COUNT)]
    events = []
    for idx, actor in enumerate(actors):
        actor_t0 = t0 + timedelta(minutes=idx * 2)
        for i in range(6):
            events.append(
                {
                    "timestamp": _iso(actor_t0 + timedelta(minutes=i)),
                    "actor": actor,
                    "action": "auth_fail",
                    "source_ip": f"203.0.113.{10 + idx}",
                    "outcome": "failure",
                }
            )
        success_at = actor_t0 + timedelta(minutes=6)
        events.append(
            {
                "timestamp": _iso(success_at),
                "actor": actor,
                "action": "login",
                "source_ip": f"203.0.113.{10 + idx}",
                "outcome": "success",
                "geo": _NY_GEO,
            }
        )
        takeover_at = success_at + timedelta(minutes=30)
        events.append(
            {
                "timestamp": _iso(takeover_at),
                "actor": actor,
                "action": "login",
                "source_ip": f"91.198.174.{10 + idx}",
                "outcome": "success",
                "geo": _MOSCOW_GEO,
            }
        )
        events.append(
            {
                "timestamp": _iso(takeover_at + timedelta(minutes=5)),
                "actor": actor,
                "action": "data_transfer",
                "target": "unknown-host.example.net",
                "bytes": 700_000_000,
                "outcome": "success",
            }
        )

    fired, incidents = post_events_and_check(client, events)
    by_actor = {inc["actor"]: inc for inc in incidents}

    # A Stage 1 coordinated-attack merge gives all 3 actors ONE incident whose `actor`
    # field is a synthetic multi-account label (not any real actor's own name) — so the
    # real per-actor identities only ever show up in `related_actors`, never as a key in
    # by_actor. Check for that merge explicitly rather than assuming the old
    # one-incident-per-actor shape.
    merged = next(
        (inc for inc in incidents if set(actors).issubset(set(inc.get("related_actors") or []))),
        None,
    )

    if merged:
        cordon(
            f"ONE linked incident covers all {len(actors)} accounts: {merged['id']} -> "
            f"{_c(_BOLD + _GREEN, merged['verdict'].upper())} risk={merged['score']}/100"
        )
        dim("detections: " + ", ".join(merged["detection_types"]))
        dim("related_actors: " + ", ".join(merged["related_actors"]))
        caught = True
        evidence = (
            f"ONE linked incident ({merged['verdict'].upper()} risk={merged['score']}/100, "
            f"{', '.join(merged['detection_types'])}) covers all {len(actors)} accounts via "
            f"related_actors"
        )
    else:
        for actor in actors:
            inc = by_actor.get(actor)
            if inc:
                cordon(f"{actor}: incident {inc['id']} -> {inc['verdict'].upper()} risk={inc['score']}/100")
                dim("detections: " + ", ".join(inc["detection_types"]))
            else:
                cordon(_c(_BOLD + _RED, f"{actor}: NO INCIDENT RAISED"))
        caught = False
        evidence = (
            f"{len(by_actor)}/{len(actors)} actors individually caught; "
            f"no unified multi-actor incident was raised"
        )

    sc.record(
        6, "Concurrent compromised accounts",
        "closed by Stage 1 detection hardening: correlated actors sharing a source-IP subnet now merge into one linked incident (app.detections.cross_actor, Incident.related_actors)",
        caught, evidence,
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 7 — Benign-under-load (false-positive check)
# --------------------------------------------------------------------------------------------
#
# Mundane, single-location, business-hours activity for 3 "normal employee" actors, run
# interleaved with the attack scenarios above (not batched at the end) so it's a genuine
# concurrency/false-positive check, not an afterthought.

_BENIGN_TARGETS = [
    "shared/onboarding/welcome-guide.pdf",
    "shared/team-project/status-update.pptx",
    "shared/handbook/pto-policy.pdf",
]


def run_benign_activity(client: AegisClient, run_id: str, index: int, t0: datetime, sc: Scorecard) -> None:
    # Snapped to a guaranteed weekday (see _business_days) — off_hours_access unconditionally
    # flags weekends regardless of hour, and this is meant to be a clean false-positive
    # control, not accidentally-real off-hours activity depending on which day this script
    # happens to be run.
    t0 = _business_days(t0, 1)[0]
    actor = f"benign-{index}.{run_id}@victimcorp.example"
    events = [
        {
            "timestamp": _iso(t0.replace(hour=10, minute=0)),
            "actor": actor,
            "action": "login",
            "source_ip": _HOME_IP,
            "outcome": "success",
            "geo": _NY_GEO,
        }
    ]
    for i in range(3):
        events.append(
            {
                "timestamp": _iso(t0.replace(hour=10, minute=5 + i * 5)),
                "actor": actor,
                "action": "file_access",
                "source_ip": _HOME_IP,
                "target": _BENIGN_TARGETS[i % len(_BENIGN_TARGETS)],
                "outcome": "success",
            }
        )
    fired, incidents = post_events_and_check(client, events)
    if fired:
        cordon(_c(_BOLD + _RED, f"FALSE POSITIVE: {actor} (normal activity) raised an incident!"))
        dim(_describe_incidents(incidents))
        sc.record_false_positive(f"{actor}: {_describe_incidents(incidents)}")
    else:
        cordon(f"{actor}: normal day, correctly stayed safe.")


# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------


def resolve_credentials(args: argparse.Namespace) -> tuple[str, str]:
    email = args.email or os.environ.get(EMAIL_ENV_VAR)
    if not email:
        email = input("Cordon account email: ").strip()

    password = args.password or os.environ.get(PASSWORD_ENV_VAR)
    if not password:
        password = getpass.getpass("Cordon account password (hidden): ")

    if not email or not password:
        raise RuntimeError("An email and password are required (flags, env vars, or the prompt).")
    return email, password


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Cordon backend URL (default: %(default)s)")
    parser.add_argument("--email", default=None, help=f"Account email. Falls back to ${EMAIL_ENV_VAR}, then a prompt.")
    parser.add_argument("--password", default=None, help=f"Account password. Falls back to ${PASSWORD_ENV_VAR}, then a hidden prompt.")
    parser.add_argument("--account-name", default=DEFAULT_ACCOUNT_NAME, help="Only used if the account doesn't exist yet.")
    parser.add_argument("--pace", type=float, default=3.0, help="Seconds between scenarios (default: %(default)s)")
    parser.add_argument("--no-prompt", action="store_true", help="Skip the 'press Enter to start' gate")
    args = parser.parse_args()

    banner("CORDON PHASE 2 — BRUTAL RED-TEAM STRESS TEST (authorized, synthetic data)")
    print(_c(_DIM, f"Target backend : {args.base_url}"))
    print(_c(_DIM, f"Frontend       : {FRONTEND_URL}  (log in with the same account to watch)"))
    print()
    print("This is an adversarial test of Cordon's own detection engine, not a demo — several")
    print("scenarios are EXPECTED to slip through. That's the point: find the gaps, harden them.")
    print("This script only ever talks to the URL above — double-check it before continuing.")

    email, password = resolve_credentials(args)
    print(_c(_DIM, f"\nRunning as     : {email}"))

    if not args.no_prompt:
        try:
            input(_c(_BOLD, "\nOpen the frontend and log in now, then press Enter to launch the campaign..."))
        except EOFError:
            pass

    client = AegisClient(args.base_url)
    sc = Scorecard()

    try:
        ensure_account(client, email=email, password=password, account_name=args.account_name)

        run_id = os.urandom(4).hex()
        now = datetime.now(timezone.utc)

        run_scenario_1_evasive_phishing(client, args.pace, sc)

        run_benign_activity(client, run_id, 1, now - timedelta(days=20), sc)

        run_scenario_2_low_and_slow_exfiltration(client, run_id, now - timedelta(days=14), args.pace, sc)

        run_scenario_3_password_spray(client, run_id, now - timedelta(hours=6), args.pace, sc)

        run_benign_activity(client, run_id, 2, now - timedelta(days=3), sc)

        run_scenario_4_insider_threat(client, run_id, now - timedelta(days=10), args.pace, sc)

        run_scenario_5_supply_chain(client, args.pace, sc)

        run_benign_activity(client, run_id, 3, now - timedelta(days=1), sc)

        run_scenario_6_concurrent_compromise(client, run_id, now - timedelta(hours=2), args.pace, sc)

        sc.print_report()

        banner("CAMPAIGN COMPLETE")
        print(f"Run id (actor suffix) : {run_id}")
        print("Check the Cases and Detections tabs in the frontend —")
        print(f"{FRONTEND_URL}")
        print()
        print(_c(_DIM, "Re-run any time — every actor identity is freshened per run."))
        print(_c(_DIM, "scripts/cleanup_sim.py wipes everything this (and phase 1) created."))
        return 0
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
