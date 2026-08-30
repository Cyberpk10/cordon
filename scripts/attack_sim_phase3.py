#!/usr/bin/env python3
"""PHASE 3 — ADAPTIVE, elite-tier red-team stress test against a LOCAL Cordon instance.
Authorized, dev-only, synthetic data. Where phase 2 found gaps that Stage 1 detection
hardening then closed (cross-actor /24 correlation, coordinated-campaign merge, 7-day
cumulative-volume exfiltration — see commit 4e34d8e), phase 3 assumes the attacker already
KNOWS Stage 1 exists and engineers tradecraft specifically to slip underneath its exact
thresholds, plus the M5 Stage 2 UEBA baselines. Each scenario's docstring cites the exact
backend module/threshold it targets and how the code actually behaves — including one place
(scenario 2) where the obvious framing ("split across destinations") doesn't match how the
code works (cumulative_exfiltration.py sums per-ACTOR, not per-destination) and the real
evasion mechanic is spelled out instead.

This script only ever talks to --base-url (default http://localhost:8000) — check that value
before running it. It never sends real email and never performs any real network attack; every
"attacker" action is a synthetic API call, exactly like phases 1/2. Pointing --base-url at a
real deployment means the case/incident data this creates is real, persisted data there — see
scripts/cleanup_sim.py to delete it afterward (unchanged — it already wipes every case/incident
for whichever account you log into, regardless of which script created them).

Usage:
    python3 scripts/attack_sim_phase3.py
    python3 scripts/attack_sim_phase3.py --base-url http://localhost:8000 --pace 0 --no-prompt

Account resolution is identical to phases 1/2 (same env vars, same flags, same signup-or-login
logic) — run this against the same account if you like; cleanup_sim.py wipes all three.

Stdlib only. Ends by printing a SCORECARD: for each of the 7 scenarios, whether Cordon raised a
non-safe verdict/incident, plus an overall detection rate, any false positives from the benign
activity mixed in throughout, and a "weakest spots" list naming the specific mechanism behind
each miss. Scenarios 1-5 being MISSED here is the EXPECTED, correct outcome of elite-tier
adaptive tradecraft beating today's defenses, not a regression — 6 and 7 staying clean is the
real pass/fail bar for this round.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import statistics
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
    """Thin stdlib HTTP wrapper — duplicated from phases 1/2 rather than imported (matches
    this repo's existing convention: each script under scripts/ is self-contained)."""

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
    """Identical logic to phases 1/2's — logs in if the account exists, signs up if not, never
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
    expected_to_evade: bool = True  # False for scenarios where CAUGHT is the desired outcome


@dataclass
class Scorecard:
    entries: list[ScorecardEntry] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    def record(self, number: int, name: str, mechanism: str, caught: bool, detail: str,
               expected_to_evade: bool = True) -> None:
        self.entries.append(ScorecardEntry(number, name, mechanism, caught, detail, expected_to_evade))

    def record_false_positive(self, description: str) -> None:
        self.false_positives.append(description)

    def print_report(self) -> None:
        banner("SCORECARD — honest results, not a demo")

        caught_count = sum(1 for e in self.entries if e.caught)
        total = len(self.entries)
        rate_color = _GREEN if caught_count >= total * 0.5 else _YELLOW if caught_count >= total * 0.25 else _RED

        print()
        for e in self.entries:
            tag = _c(_BOLD + _GREEN, "CAUGHT") if e.caught else _c(_BOLD + _RED, "MISSED")
            note = "" if (e.caught == (not e.expected_to_evade)) else _c(_DIM, "  (unexpected)")
            print(f"  {e.number}. {e.name:<38} {tag}{note}")
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

        misses = [e for e in self.entries if not e.caught and e.expected_to_evade]
        unexpected_misses = [e for e in self.entries if not e.caught and not e.expected_to_evade]
        print()
        if misses:
            print(_c(_BOLD + _YELLOW, "Weakest spots (elite-tier tradecraft that still gets through):"))
            for e in misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        if unexpected_misses:
            print(_c(_BOLD + _RED, "Unexpected misses (should have been caught — investigate):"))
            for e in unexpected_misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        if not misses and not unexpected_misses:
            print(_c(_BOLD + _GREEN, "No misses this run — every scenario was caught."))


# --------------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------------

_NY_GEO = {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060}
_HOME_IP = "198.51.100.20"


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _business_days(start: datetime, count: int) -> list[datetime]:
    """`count` consecutive weekdays starting at-or-after `start` — used everywhere a scenario
    needs to avoid off_hours_access's unconditional weekend check (app/detections/
    off_hours_access.py: weekends always count as off-hours, baseline or not) so a scenario's
    outcome is never accidentally decided by which day of the week it happened to run on."""
    days: list[datetime] = []
    current = start
    while len(days) < count:
        if current.weekday() < 5:
            days.append(current)
        current += timedelta(days=1)
    return days


def _snap_to_weekday(dt: datetime) -> datetime:
    return _business_days(dt, 1)[0]


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
        who = inc.get("related_actors") or [inc["actor"]]
        parts.append(
            f"{inc['verdict'].upper()} risk={inc['score']}/100 "
            f"[{', '.join(inc['detection_types'])}] (actor(s)={', '.join(who)})"
        )
    return "; ".join(parts)


# --------------------------------------------------------------------------------------------
# Scenario 1 — Subnet-rotating password spray
# --------------------------------------------------------------------------------------------
#
# Targets: app/detections/cross_actor.py::detect_password_spray groups auth_fail events by
# /24 SUBNET (first three octets), firing only when one subnet's 15-minute sliding window
# sees >= settings.cross_actor_spray_min_actors (8) distinct actors. An attacker who already
# knows this rotates through a DIFFERENT /24 per actor instead of reusing one IP — every
# subnet's count caps at 1, structurally below the floor regardless of how many accounts or
# how tight the timing is.

_SUBNET_ROTATE_ACCOUNT_COUNT = 20


def run_scenario_1_subnet_rotating_spray(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(1, "SUBNET-ROTATING PASSWORD SPRAY")
    attacker(f"spraying {_SUBNET_ROTATE_ACCOUNT_COUNT} accounts, 2-3 failed attempts each — but this")
    attacker("time every account gets its OWN /24 subnet (a botnet/proxy pool, not one IP),")
    attacker("specifically to slip past Stage 1's subnet-grouping correlation...")
    time.sleep(min(pace, 2))

    events = []
    for i in range(_SUBNET_ROTATE_ACCOUNT_COUNT):
        actor = f"rotate-{i:02d}.{run_id}@victimcorp.example"
        ip = f"10.{i}.5.5"  # a distinct /24 ("10.{i}.5") per actor
        attempts = 2 if i % 3 else 3
        for j in range(attempts):
            events.append(
                {
                    "timestamp": _iso(t0 + timedelta(minutes=i * 0.5, seconds=j * 20)),
                    "actor": actor,
                    "action": "auth_fail",
                    "source_ip": ip,
                    "outcome": "failure",
                }
            )

    fired, incidents = post_events_and_check(client, events)
    caught = fired
    color = _GREEN if caught else _RED
    cordon(
        f"{len(events)} failed logins across {_SUBNET_ROTATE_ACCOUNT_COUNT} accounts, "
        f"{_SUBNET_ROTATE_ACCOUNT_COUNT} distinct /24 subnets -> "
        f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}"
    )
    sc.record(
        1, "Subnet-rotating password spray",
        "cross-actor correlation groups by /24 subnet — rotating one IP per actor caps every subnet's count at 1",
        caught,
        _describe_incidents(incidents) if caught else
        f"0 of {_SUBNET_ROTATE_ACCOUNT_COUNT} subnets ever reached the 8-distinct-actor floor",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 2 — Sub-threshold / window-spread exfiltration
# --------------------------------------------------------------------------------------------
#
# Targets: app/detections/cumulative_exfiltration.py sums bytes across EVERY non-allowlisted
# transfer for an actor within a rolling settings.exfil_cumulative_window_days (7) window,
# regardless of which destination each one went to — so splitting across multiple
# destinations does NOT evade it (it's an actor-total, not a per-destination total; a naive
# "spread across destinations" attacker would still get caught). It also requires >= 2
# qualifying transfers before it even looks at the total (settings.exfil_cumulative_min_
# transfers). An attacker who paces transfers MORE than 7 days apart ensures no rolling
# window ever contains more than ONE transfer — the count-of-2 floor is never reached,
# regardless of how large each individual transfer is (as long as it also stays under
# app/detections/data_exfiltration.py's single-event 500MB threshold).

_EXFIL_HOST_A = "unfamiliar-storage-relay.example.net"
_EXFIL_HOST_B = "unfamiliar-backup-node.example.net"
_WINDOW_SPREAD_CYCLES = 7
_WINDOW_SPREAD_GAP_DAYS = 12  # safely > exfil_cumulative_window_days (7) even after weekday snapping
_WINDOW_SPREAD_BYTES = 280_000_000  # < exfil_large_transfer_bytes (500MB)


def run_scenario_2_window_spread_exfiltration(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(2, "SUB-THRESHOLD / WINDOW-SPREAD EXFILTRATION")
    actor = f"windowspread.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)} learned the cumulative check has a 7-day rolling window and")
    attacker("a 2-transfer floor — so instead of splitting across destinations (which wouldn't")
    attacker(f"help, it's an account-total either way), they pace ONE ~280MB transfer every "
             f"{_WINDOW_SPREAD_GAP_DAYS} days...")
    time.sleep(min(pace, 2))

    any_incident = False
    incidents_seen: list[dict] = []
    total_bytes = 0
    hosts = [_EXFIL_HOST_A, _EXFIL_HOST_B]

    for cycle in range(_WINDOW_SPREAD_CYCLES):
        day = _snap_to_weekday(t0 + timedelta(days=_WINDOW_SPREAD_GAP_DAYS * cycle))
        events = [
            {
                "timestamp": _iso(day.replace(hour=15, minute=0)),
                "actor": actor,
                "action": "data_transfer",
                "source_ip": _HOME_IP,
                "target": hosts[cycle % len(hosts)],
                "bytes": _WINDOW_SPREAD_BYTES,
                "outcome": "success",
            }
        ]
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
        total_bytes += _WINDOW_SPREAD_BYTES
        dim(f"cycle {cycle + 1}/{_WINDOW_SPREAD_CYCLES} ({day.date()}): 1 transfer, "
            f"{_WINDOW_SPREAD_BYTES:,} bytes -> {'incident raised' if fired else 'no incident'}")

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(
        f"after {_WINDOW_SPREAD_CYCLES} cycles and {total_bytes:,} total bytes moved -> "
        f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}"
    )
    sc.record(
        2, "Sub-threshold / window-spread exfiltration",
        "cumulative check is an actor-total (destination-splitting doesn't help) but needs >=2 transfers within its 7-day rolling window — spacing transfers 9+ days apart means no window ever sees more than 1",
        caught,
        _describe_incidents(incidents_seen) if caught else
        f"no incident across any of {_WINDOW_SPREAD_CYCLES} cycles ({total_bytes:,} bytes total, never >1 transfer per 7-day window)",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 3 — Baseline-poisoning insider
# --------------------------------------------------------------------------------------------
#
# Targets: app/baselines/aggregation.py's daily_volume is a ROLLING
# settings.baseline_daily_volume_window_days (30) window, explicitly designed (per the
# module's own comment) "so the baseline can adapt if an actor's normal workload genuinely
# changes." app/detections/mass_file_access.py's volume-anomaly gate only fires past
# mean + 3*stddev of that rolling history once settings.baseline_min_days_for_volume (5)
# days exist — an attacker who ramps their daily count up GRADUALLY shifts the mean/stddev
# to match. The one thing that can't be poisoned away is MASS_FILE_ACCESS's distinct-target
# static backstop (>= 10 distinct targets/day, always applies regardless of baseline) — so
# the ramp keeps every day's distinct target pool at 5, cycling through repeats to reach the
# day's count. The exact ramp below was verified numerically (not eyeballed) against
# app.baselines.aggregation.is_volume_anomalous's real formula before writing this script —
# no day, including the final theft day, ever crosses mean + 3*stddev of its own prior
# rolling history.

_POISON_NORMAL_TARGETS = [
    "shared/team-project/roadmap.docx",
    "shared/team-project/notes.docx",
    "shared/team-project/status-update.pptx",
    "shared/team-project/budget-draft.xlsx",
    "shared/team-project/meeting-minutes.docx",
]
_POISON_SENSITIVE_TARGETS = [
    "finance/q3-budget-actuals.xlsx",
    "finance/payroll-adjustments.xlsx",
    "hr/comp-review-2026.xlsx",
    "hr/pending-terminations.docx",
    "legal/pending-litigation-notes.docx",
]
# Verified via scripts (see plan notes): no day's count ever exceeds mean + 3*stddev of the
# rolling history that precedes it, including the theft day below.
_POISON_RAMP = [4, 4, 5, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 12, 13, 14]
_POISON_THEFT_COUNT = 15


def _poison_pool(day_index: int) -> list[str]:
    sensitive_in_pool = min(len(_POISON_SENSITIVE_TARGETS), day_index // 4)
    normal_in_pool = len(_POISON_NORMAL_TARGETS) - sensitive_in_pool
    return _POISON_NORMAL_TARGETS[:normal_in_pool] + _POISON_SENSITIVE_TARGETS[:sensitive_in_pool]


def run_scenario_3_baseline_poisoning_insider(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(3, "BASELINE-POISONING INSIDER")
    actor = f"poison.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)} spends {len(_POISON_RAMP)} business days gradually raising their")
    attacker("own daily file-access count (4 -> 14/day) while quietly mixing in more and more")
    attacker("finance/HR/legal files each week — poisoning the 30-day rolling baseline itself,")
    attacker("never once exceeding 5 distinct targets/day...")
    time.sleep(min(pace, 2))

    days = _business_days(t0, len(_POISON_RAMP))
    any_incident_during_ramp = False
    for day_index, (day, count) in enumerate(zip(days, _POISON_RAMP)):
        pool = _poison_pool(day_index)
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
                    "timestamp": _iso(day.replace(hour=15, minute=5 + i * 2)),
                    "actor": actor,
                    "action": "file_access",
                    "source_ip": _HOME_IP,
                    "target": pool[i % len(pool)],
                    "outcome": "success",
                }
            )
        fired, _ = post_events_and_check(client, events)
        any_incident_during_ramp = any_incident_during_ramp or fired
        sensitive_share = sum(1 for t in pool if t in _POISON_SENSITIVE_TARGETS)
        dim(f"ramp day {day_index + 1}/{len(_POISON_RAMP)} ({day.date()}): {count} file accesses, "
            f"{sensitive_share}/{len(pool)} of today's pool is sensitive -> "
            f"{'incident raised (unexpected!)' if fired else 'safe, as expected'}")

    theft_day = _business_days(days[-1] + timedelta(days=1), 1)[0]
    events = [
        {
            "timestamp": _iso(theft_day.replace(hour=15, minute=0)),
            "actor": actor,
            "action": "login",
            "source_ip": _HOME_IP,
            "outcome": "success",
            "geo": _NY_GEO,
        }
    ]
    for i in range(_POISON_THEFT_COUNT):
        events.append(
            {
                "timestamp": _iso(theft_day.replace(hour=15, minute=5 + i * 2)),
                "actor": actor,
                "action": "file_access",
                "source_ip": _HOME_IP,
                "target": _POISON_SENSITIVE_TARGETS[i % len(_POISON_SENSITIVE_TARGETS)],
                "outcome": "success",
            }
        )
    fired, incidents = post_events_and_check(client, events)

    caught = fired or any_incident_during_ramp
    color = _GREEN if caught else _RED
    cordon(
        f"theft day ({theft_day.date()}): {_POISON_THEFT_COUNT} entirely-sensitive file accesses, "
        f"volume matching their now-poisoned baseline -> "
        f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}"
    )
    sc.record(
        3, "Baseline-poisoning insider",
        "30-day rolling volume baseline is designed to adapt; a gradual ramp (always <10 distinct targets/day) shifts mean+3*stddev to match, so the real theft never looks anomalous",
        caught,
        _describe_incidents(incidents) if caught else
        "theft-day volume and distinct-target count both stayed inside the actor's own (poisoned) rolling baseline — nothing fired",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 4 — Compromised legitimate vendor
# --------------------------------------------------------------------------------------------
#
# Targets: app/indicators/ as a whole has no sender-history/reputation/trust-store module —
# confirmed by reading every file in that package. The analyzer is single-shot per email;
# there is no mechanism, and never has been, for "this sender has emailed us safely before"
# to matter. This scenario's actual defeat mechanism is IDENTICAL to phase 2's scenarios 1
# and 5 (no phrase-bank matches, no curated-brand impersonation, natural stylometry to dodge
# AI_AUTHORED_SUSPECTED, SPF/DKIM/DMARC pass) — framed as a believable "compromised vendor
# with prior history" attack to make the same known, still-open gap concrete, not because
# anything new was found.

_COMPROMISED_VENDOR_EMAIL = """From: "Alex Chen - Northbridge Logistics" <alex.chen@northbridge-logistics-partners.com>
To: ap-team@ourcompany.example
Subject: Re: Q3 invoice batch — updated remittance details
Date: Fri, 28 Aug 2026 11:20:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom=northbridge-logistics-partners.com; dkim=pass header.d=northbridge-logistics-partners.com; dmarc=pass header.from=northbridge-logistics-partners.com
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi team,

Following up on the invoice batch from earlier this month — our finance team
switched banks partway through the quarter, so a few of the remittance details
on file are now out of date. I've attached the updated ones for the two
invoices still open.

Details and the updated form are here: https://northbridge-logistics-partners.com/ap/remit-update

Let me know if anything doesn't line up on your end and I'll double check with
our billing lead before the next cycle closes.

Thanks,
Alex Chen
Northbridge Logistics Partners
"""


def run_scenario_4_compromised_vendor(client: AegisClient, pace: float, sc: Scorecard) -> None:
    scenario(4, "COMPROMISED LEGITIMATE VENDOR")
    attacker("a real, previously-benign vendor relationship ('Northbridge Logistics') gets")
    attacker("their own account taken over — the lure reads as a routine follow-up to an")
    attacker("existing thread, not a first-contact phish, and the domain still passes SPF/")
    attacker("DKIM/DMARC cleanly since the attacker controls the real infrastructure now...")
    time.sleep(min(pace, 2))

    resp = client.post("/api/analyze/text", {"raw_text": _COMPROMISED_VENDOR_EMAIL})
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
        4, "Compromised legitimate vendor",
        "no sender-history/reputation mechanism exists anywhere in the analyzer — same structural gap as phase 2's evasive/supply-chain phishing, now framed as an account takeover",
        caught, f"verdict={verdict} score={score}/100, {len(indicator_titles)} indicator(s) fired",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 5 — Low-and-slow multi-week kill chain
# --------------------------------------------------------------------------------------------
#
# Composes two already-confirmed evasion primitives across ~7 weeks so no single 24h
# detection window or 7-day cumulative window ever sees more than one quiet step: sparse
# recon (well under every static/volume threshold, spread a week apart) followed by exfil
# paced with scenario 2's window-spread mechanic. Login pattern is held deliberately
# constant (same hour/location throughout) rather than attempting a second, separate
# statistical drift model — the point of this scenario is the temporal spread itself, not
# stacking a third distinct mechanism on top.

_KILL_CHAIN_RECON_TARGETS = [
    "shared/company-directory/org-chart.pdf",
    "shared/it-wiki/vpn-setup-guide.pdf",
]


def run_scenario_5_low_and_slow_kill_chain(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(5, "LOW-AND-SLOW MULTI-WEEK KILL CHAIN")
    actor = f"killchain.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)} spreads a full recon -> access -> exfil chain across ~7 weeks —")
    attacker("a couple of quiet lookups a week, then two large transfers paced far enough")
    attacker("apart (12+ days) that no rolling window ever sees more than one at once...")
    time.sleep(min(pace, 2))

    any_incident = False
    incidents_seen: list[dict] = []

    for week in range(4):
        day = _snap_to_weekday(t0 + timedelta(weeks=week))
        events = [
            {
                "timestamp": _iso(day.replace(hour=15, minute=0)),
                "actor": actor,
                "action": "login",
                "source_ip": _HOME_IP,
                "outcome": "success",
                "geo": _NY_GEO,
            },
            {
                "timestamp": _iso(day.replace(hour=15, minute=10)),
                "actor": actor,
                "action": "file_access",
                "source_ip": _HOME_IP,
                "target": _KILL_CHAIN_RECON_TARGETS[week % len(_KILL_CHAIN_RECON_TARGETS)],
                "outcome": "success",
            },
        ]
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
        dim(f"week {week + 1}/4 (recon, {day.date()}): 1 quiet lookup -> "
            f"{'incident raised' if fired else 'no incident'}")

    # Two exfil transfers, 12+ days apart (not a literal "week 5/week 6" — a plain 7-day
    # gap sits exactly on the cumulative check's rolling-window boundary, which the
    # inclusive >=/<= comparison in app.api.routes.events would still catch; scenario 2's
    # own gap needed the same fix after a live run surfaced it).
    exfil_days = [_snap_to_weekday(t0 + timedelta(weeks=4)), None]
    exfil_days[1] = _snap_to_weekday(exfil_days[0] + timedelta(days=_WINDOW_SPREAD_GAP_DAYS))
    for stage, day in enumerate(exfil_days):
        events = [
            {
                "timestamp": _iso(day.replace(hour=15, minute=0)),
                "actor": actor,
                "action": "data_transfer",
                "source_ip": _HOME_IP,
                "target": _EXFIL_HOST_A,
                "bytes": _WINDOW_SPREAD_BYTES,
                "outcome": "success",
            }
        ]
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
        dim(f"exfil stage {stage + 1}/2 ({day.date()}): 1 transfer, {_WINDOW_SPREAD_BYTES:,} bytes -> "
            f"{'incident raised' if fired else 'no incident'}")

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(f"~7-week chain complete -> {_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    sc.record(
        5, "Low-and-slow multi-week kill chain",
        "composes window-spread exfiltration with sparse, low-volume recon spread across weeks — no single detection window ever sees more than one quiet step",
        caught,
        _describe_incidents(incidents_seen) if caught else
        "recon and exfil both individually stayed under every static and rolling threshold across the whole chain",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 6 — Noise-blended attack
# --------------------------------------------------------------------------------------------
#
# Targets a hypothesis, not a known gap: does burying a real spray under heavy unrelated
# benign traffic, split across several batches, dilute or delay detection? Detections are
# strictly actor-scoped or explicitly evidence-gated cross-actor (app.detections.cross_actor.
# detect_coordinated_campaign only ever considers already-non-safe actors; detect_password_
# spray only ever looks at auth_fail events, never file_access/login noise), so this is
# expected to still get CAUGHT — a clean pass here is a genuine, informative "noise-blending
# doesn't help attackers" result, not a forced miss.

_NOISE_SPRAY_IP = "203.0.113.200"
_NOISE_SPRAY_ACCOUNT_COUNT = 10
_NOISE_BENIGN_TARGETS = [
    "shared/onboarding/welcome-guide.pdf",
    "shared/team-project/status-update.pptx",
    "shared/handbook/pto-policy.pdf",
]


def run_scenario_6_noise_blended_attack(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(6, "NOISE-BLENDED ATTACK")
    attacker(f"a real {_NOISE_SPRAY_ACCOUNT_COUNT}-account spray from one IP, but split across 3")
    attacker("batches and buried under heavy unrelated benign file-access noise in each one —")
    attacker("testing whether volume alone can hide it...")
    time.sleep(min(pace, 2))

    # Snapped to a real business day/hour — the "noise" actors are meant to be genuinely
    # benign and must never accidentally trip off_hours_access or mass_file_access
    # themselves (a first run of this scenario did exactly that, unsnapped and too heavy,
    # and the resulting non-safe noise actors then correctly but confusingly got merged by
    # COORDINATED_ATTACK_CORRELATION since they all shared one IP — a bug in this test's
    # data, not the backend). Each noise actor also gets its own IP now, belt-and-suspenders
    # against that specific false-merge risk.
    day = _snap_to_weekday(t0)
    spray_actors = [f"noisy-{i:02d}.{run_id}@victimcorp.example" for i in range(_NOISE_SPRAY_ACCOUNT_COUNT)]
    noise_actors = [f"noise-cover-{i}.{run_id}@victimcorp.example" for i in range(4)]

    any_incident = False
    incidents_seen: list[dict] = []
    batches = [spray_actors[0:3], spray_actors[3:7], spray_actors[7:10]]
    for batch_index, batch_actors in enumerate(batches):
        events = []
        for actor in batch_actors:
            i = spray_actors.index(actor)
            attempts = 2 if i % 3 else 3
            for j in range(attempts):
                events.append(
                    {
                        "timestamp": _iso(day.replace(hour=10, minute=0) + timedelta(minutes=i, seconds=j * 20)),
                        "actor": actor,
                        "action": "auth_fail",
                        "source_ip": _NOISE_SPRAY_IP,
                        "outcome": "failure",
                    }
                )
        for n, noise_actor in enumerate(noise_actors):
            for k in range(3):
                events.append(
                    {
                        "timestamp": _iso(day.replace(hour=14, minute=0) + timedelta(minutes=batch_index * 10 + k * 3)),
                        "actor": noise_actor,
                        "action": "file_access",
                        "source_ip": f"198.51.100.{60 + n}",
                        "target": _NOISE_BENIGN_TARGETS[k % len(_NOISE_BENIGN_TARGETS)],
                        "outcome": "success",
                    }
                )
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
        dim(f"batch {batch_index + 1}/3: {len(batch_actors)} spray actor(s) + "
            f"{len(noise_actors) * 3} noise events -> "
            f"{'incident raised' if fired else 'no incident yet'}")

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(f"{_NOISE_SPRAY_ACCOUNT_COUNT} accounts sprayed under heavy noise -> "
           f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    sc.record(
        6, "Noise-blended attack",
        "cross-actor detection only ever looks at auth_fail evidence, never unrelated noise — expected to remain robust",
        caught,
        _describe_incidents(incidents_seen) if caught else
        f"0 of {_NOISE_SPRAY_ACCOUNT_COUNT} spray accounts ever triggered an incident despite heavy noise",
        expected_to_evade=False,
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 7 — Benign-heavy control (false-positive check under adversarial-looking load)
# --------------------------------------------------------------------------------------------
#
# Heavier and more targeted than phase 2's benign check: several ordinary employees with
# varied legitimate activity, PLUS one group of 7 legitimate employees each with a single
# mistyped-password auth_fail from a shared office/VPN egress IP — deliberately placed one
# below settings.cross_actor_spray_min_actors (8) to pressure-test the exact Stage 1 margin,
# not just confirm generic normal activity stays quiet.

_CONTROL_BENIGN_TARGETS = [
    "shared/onboarding/welcome-guide.pdf",
    "shared/team-project/status-update.pptx",
    "shared/handbook/pto-policy.pdf",
]
_CONTROL_SHARED_IP_GROUP_SIZE = 7  # one below cross_actor_spray_min_actors (8)
_CONTROL_SHARED_IP = "198.51.100.50"


def run_scenario_7_benign_heavy_control(client: AegisClient, run_id: str, t0: datetime, sc: Scorecard) -> None:
    scenario(7, "BENIGN-HEAVY CONTROL")
    attacker("(no attacker this round — just heavy, varied legitimate activity, plus 7 real")
    attacker("employees who each mistyped their password once from the same office IP)")
    time.sleep(0.5)

    for index in range(4):
        day = _snap_to_weekday(t0 + timedelta(days=index))
        actor = f"control-{index}.{run_id}@victimcorp.example"
        events = [
            {
                "timestamp": _iso(day.replace(hour=10, minute=0)),
                "actor": actor,
                "action": "login",
                "source_ip": _HOME_IP,
                "outcome": "success",
                "geo": _NY_GEO,
            }
        ]
        for i in range(4 + index):  # varied, legitimate volumes
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=10, minute=5 + i * 5)),
                    "actor": actor,
                    "action": "file_access",
                    "source_ip": _HOME_IP,
                    "target": _CONTROL_BENIGN_TARGETS[i % len(_CONTROL_BENIGN_TARGETS)],
                    "outcome": "success",
                }
            )
        fired, incidents = post_events_and_check(client, events)
        if fired:
            cordon(_c(_BOLD + _RED, f"FALSE POSITIVE: {actor} (normal activity) raised an incident!"))
            dim(_describe_incidents(incidents))
            sc.record_false_positive(f"{actor}: {_describe_incidents(incidents)}")
        else:
            cordon(f"{actor}: varied normal day, correctly stayed safe.")

    shared_ip_day = _snap_to_weekday(t0 + timedelta(days=5))
    events = []
    for i in range(_CONTROL_SHARED_IP_GROUP_SIZE):
        events.append(
            {
                "timestamp": _iso(shared_ip_day.replace(hour=9, minute=i)),
                "actor": f"employee-{i}.{run_id}@victimcorp.example",
                "action": "auth_fail",
                "source_ip": _CONTROL_SHARED_IP,
                "outcome": "failure",
            }
        )
    fired, incidents = post_events_and_check(client, events)
    if fired:
        cordon(_c(_BOLD + _RED,
                  f"FALSE POSITIVE: {_CONTROL_SHARED_IP_GROUP_SIZE} employees mistyping a password "
                  f"from a shared IP raised an incident!"))
        dim(_describe_incidents(incidents))
        sc.record_false_positive(
            f"{_CONTROL_SHARED_IP_GROUP_SIZE} employees, shared IP: {_describe_incidents(incidents)}"
        )
    else:
        cordon(f"{_CONTROL_SHARED_IP_GROUP_SIZE} employees mistyping a password from a shared IP "
               f"(1 below the spray floor) -> correctly stayed safe.")


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

    banner("CORDON PHASE 3 — ADAPTIVE, ELITE-TIER RED-TEAM STRESS TEST (authorized, synthetic data)")
    print(_c(_DIM, f"Target backend : {args.base_url}"))
    print(_c(_DIM, f"Frontend       : {FRONTEND_URL}  (log in with the same account to watch)"))
    print()
    print("These attackers already know Stage 1 detection hardening exists and engineer")
    print("tradecraft specifically to slip underneath its exact thresholds. Scenarios 1-5")
    print("MISSING is the expected, correct result of elite-tier evasion — 6 and 7 staying")
    print("clean is the real bar this round.")
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

        run_scenario_1_subnet_rotating_spray(client, run_id, now - timedelta(hours=6), args.pace, sc)

        run_scenario_2_window_spread_exfiltration(client, run_id, now - timedelta(days=63), args.pace, sc)

        run_scenario_3_baseline_poisoning_insider(client, run_id, now - timedelta(days=32), args.pace, sc)

        run_scenario_4_compromised_vendor(client, args.pace, sc)

        run_scenario_5_low_and_slow_kill_chain(client, run_id, now - timedelta(weeks=6), args.pace, sc)

        run_scenario_6_noise_blended_attack(client, run_id, now - timedelta(hours=2), args.pace, sc)

        run_scenario_7_benign_heavy_control(client, run_id, now - timedelta(days=7), sc)

        sc.print_report()

        banner("CAMPAIGN COMPLETE")
        print(f"Run id (actor suffix) : {run_id}")
        print("Check the Cases and Detections tabs in the frontend —")
        print(f"{FRONTEND_URL}")
        print()
        print(_c(_DIM, "Re-run any time — every actor identity is freshened per run."))
        print(_c(_DIM, "scripts/cleanup_sim.py wipes everything phases 1-3 created."))
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
