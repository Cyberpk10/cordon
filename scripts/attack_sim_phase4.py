#!/usr/bin/env python3
"""PHASE 4 — NATION-STATE / APT-GRADE red-team stress test against a LOCAL Cordon instance.
Authorized, dev-only, synthetic data. This is the final and hardest round: a patient,
well-resourced adversary who already knows every defense Cordon has today (Stage 1 cross-actor
correlation + cumulative exfiltration, Stage 3a sender-history intelligence) and designs
tradecraft to look like nothing at all — not "under a threshold" but statistically
indistinguishable from legitimate activity. MOST SCENARIOS HERE ARE EXPECTED TO SUCCEED. That
is deliberate and the scorecard says so plainly — pretending a nation-state actor can't beat
today's purely statistical/threshold-based detection would be dishonest.

Two mechanisms below were verified with a real run of the indicator engine while writing this
script, not assumed:
  - A "silent" first-contact email (no claimed relationship, no urgency/credential language)
    scores FIRST_CONTACT_SENDER alone (8 points) — nowhere near SAFE_MAX (24).
  - Sender-history's FIRST_CONTACT_SENDER/UNKNOWN_VENDOR_CLAIM checks are gated on
    classification == FIRST_CONTACT specifically (app/sender_history/aggregation.py) — ANY
    prior contact at all (even a single innocuous email seconds earlier, "SEEN_BEFORE", not
    the fuller "regular correspondent" ESTABLISHED bar) already suppresses both checks. This
    is a sharper, more damning finding than "you need real established trust": a single prior
    email is enough for a subsequently-compromised mailbox to go completely unflagged.

This script only ever talks to --base-url (default http://localhost:8000) — check that value
before running it. It never sends real email and never performs any real network attack; every
"attacker" action is a synthetic API call, exactly like phases 1-3. Pointing --base-url at a
real deployment means the case/incident data this creates is real, persisted data there — see
scripts/cleanup_sim.py to delete it afterward.

Usage:
    python3 scripts/attack_sim_phase4.py
    python3 scripts/attack_sim_phase4.py --base-url http://localhost:8000 --pace 0 --no-prompt

Account resolution is identical to phases 1-3. Stdlib only. Ends with a SCORECARD: per-scenario
caught/missed (labeled against what's actually expected — most scenarios here are supposed to
be missed), overall detection rate, false positives from the benign control, and a candid
"what an APT gets past us, and why" section.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
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
    """Thin stdlib HTTP wrapper — duplicated from phases 1-3 rather than imported (matches
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
    """Identical logic to phases 1-3's — logs in if the account exists, signs up if not,
    never prints the password."""
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
            print(f"  {e.number}. {e.name:<40} {tag}{note}")
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
            print(_c(_BOLD + _YELLOW, "Weakest spots (nation-state-grade tradecraft that gets through):"))
            for e in misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        if unexpected_misses:
            print(_c(_BOLD + _RED, "Unexpected misses (should have been caught — investigate):"))
            for e in unexpected_misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        if not misses and not unexpected_misses:
            print(_c(_BOLD + _GREEN, "No misses this run — every scenario was caught."))

        print()
        print(_c(_BOLD + _YELLOW, "What an APT gets past us, and why:"))
        for line in _APT_HONEST_ASSESSMENT:
            print(f"  - {line}")


_APT_HONEST_ASSESSMENT = [
    "Every current detector is either a static threshold or relative to an actor's own "
    "history — there is no content-based, resource-sensitivity, or intent-based signal "
    "anywhere in the codebase. Activity that matches an established pattern is invisible by "
    "construction, not by evasion (scenario 2).",
    "Cross-actor correlation (Stage 1) only ever looks at actors who are ALREADY individually "
    "non-safe. A campaign where every account stays under its own per-actor thresholds never "
    "produces a candidate to correlate in the first place (scenario 6) — the correlation is "
    "sound, but it has nothing to work with.",
    "Cumulative-exfiltration and baseline-volume checks are windowed (7 and 30 days "
    "respectively). Any adversary willing to operate slower than the window — which a patient, "
    "well-resourced actor by definition is — moves unlimited volume with zero incidents "
    "(scenarios 1, 4, 5).",
    "Stage 3a's sender-history checks are gated on true first contact. A single prior "
    "innocuous email — not sustained trust, just one message — permanently suppresses "
    "FIRST_CONTACT_SENDER and UNKNOWN_VENDOR_CLAIM for that domain. A compromised mailbox "
    "that has ever legitimately emailed this account once is now a blind spot for content "
    "the sender-history layer can't see through (scenario 3).",
    "None of this is a bug to patch — it's the honest ceiling of purely statistical, "
    "threshold/baseline-based detection. Closing these requires fundamentally different "
    "signal: content/intent classification, resource-sensitivity-aware DLP, and genuine "
    "cross-session behavioral modeling beyond volume and location.",
]


# --------------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------------

_NY_GEO = {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060}
_HOME_IP = "198.51.100.20"


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _business_days(start: datetime, count: int) -> list[datetime]:
    """`count` consecutive weekdays starting at-or-after `start` — off_hours_access flags
    weekends unconditionally regardless of hour, so every scenario below anchors to a
    guaranteed weekday rather than depending on which day this script happens to run."""
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


# app.indicators.domain_age_heuristic.DOMAIN_LOOKS_RANDOMLY_GENERATED fires on a domain
# label with high character-entropy AND a digit/letter mix (>=8 chars). Every phishing/vendor
# domain below is built from readable dictionary words, joined by hyphens, with NO digits —
# that alone makes the digit/letter-mix condition permanently false, so these domains can
# never self-trigger the heuristic regardless of length or entropy. (An earlier version of
# this script embedded raw run_id hex directly in domain names — e.g.
# "resource-notes-42d614.example" — which does have a digit/letter mix and DID self-trigger
# the heuristic; this was a harness bug, not a finding about the engine, caught by inspecting
# exactly which indicator fired during a live verification run.)
_SLUG_WORDS_A = [
    "cedar", "harbor", "summit", "brightpath", "fernwood", "aldergate",
    "brookline", "westfield", "clearwater", "hillcrest", "silverpine", "oakridge",
]
_SLUG_WORDS_B = [
    "notes", "logistics", "partners", "compliance", "services", "solutions",
    "consulting", "analytics", "ventures", "systems", "worldwide", "group",
]


def _readable_domain(run_id: str, salt: str) -> str:
    """A distinct, letter-only, readable-looking domain per (run_id, salt) pair — varies
    across runs (so a re-run never accidentally inherits a prior run's sender-history state
    for the same domain, which would silently change what these scenarios are actually
    demonstrating) without ever embedding digits."""
    digest = hashlib.sha256(f"{run_id}:{salt}".encode()).digest()
    h = int.from_bytes(digest, "big")
    word_a = _SLUG_WORDS_A[h % len(_SLUG_WORDS_A)]
    word_b = _SLUG_WORDS_B[(h // len(_SLUG_WORDS_A)) % len(_SLUG_WORDS_B)]
    return f"{word_a}-{word_b}.example"


def _run_salt_octet(run_id: str) -> int:
    """A stable per-run byte (0-255) derived from run_id. Used to vary an otherwise-fixed IP
    octet across runs so cross-actor grouping detectors — which correlate by shared /24
    subnet or exact IP over a real lookback window that spans the WHOLE account, not just the
    current batch — never accidentally combine a previous run's leftover events with the
    current run's just because both runs used the same literal IP."""
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:2], 16)


# Reused verbatim from phase 3's numerically-verified window-spread exfiltration mechanic:
# pacing transfers more than exfil_cumulative_window_days (7) apart, even after weekday
# snapping, means no rolling window ever sees more than one qualifying transfer — the
# cumulative check's 2-transfer floor is never reached regardless of total volume or duration.
_WINDOW_SPREAD_GAP_DAYS = 12


# --------------------------------------------------------------------------------------------
# Scenario 1 — Long-dwell multi-stage campaign
# --------------------------------------------------------------------------------------------
#
# Targets the composition of every windowed check at once: initial access via a silent
# first-contact email (no claimed relationship -> only FIRST_CONTACT_SENDER, 8 points, verified
# against the real engine), then persistence/lateral-movement at low, steady volume, then data
# staging that never crosses MASS_FILE_ACCESS's static (20/10-distinct) or baseline
# (mean+3*stddev) gates, then exfiltration paced beyond the 7-day cumulative window — spread
# across ~4-5 months so no 24h detection window, 7-day cumulative window, or 30-day baseline
# window ever sees more than one quiet stage at a time.

_STAGING_TARGETS = [
    "shared/roadmap/notes.docx",
    "shared/roadmap/status.pptx",
    "finance/vendor-list.xlsx",
    "hr/org-chart.pdf",
    "legal/contracts-index.docx",
]


def run_scenario_1_long_dwell_campaign(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(1, "LONG-DWELL MULTI-STAGE CAMPAIGN")
    actor = f"longdwell.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)}: silent spear-phish -> quiet persistence -> data staging ->")
    attacker("paced exfiltration, spread across ~4-5 months so no window ever sees more than")
    attacker("one quiet stage at a time...")
    time.sleep(min(pace, 2))

    any_incident = False
    incidents_seen: list[dict] = []

    # Stage A — initial access: silent first-contact email, no claimed relationship.
    phish_domain = _readable_domain(run_id, "scenario1-phish")
    raw_email = f"""From: "Dana Whitfield" <dana.whitfield@{phish_domain}>
To: target-employee@ourcompany.example
Subject: A resource you might find useful
Date: Mon, 24 Aug 2026 10:05:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom={phish_domain}; dkim=pass header.d={phish_domain}; dmarc=pass header.from={phish_domain}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi,

I came across some research that seemed relevant to what your team's been
working on lately, so I figured I'd pass it along in case it's useful.

Here's the write-up: https://{phish_domain}/notes/industry-trends-2026

No need to reply either way.

Dana
"""
    resp = client.post("/api/analyze/text", {"raw_text": raw_email})
    email_caught = resp["verdict"] != "safe"
    dim(f"stage A (initial access, silent first-contact email): verdict={resp['verdict']} "
        f"score={resp['score']}/100")

    # Stage B — persistence/lateral movement: 4 weeks, 2 quiet visits/week, steady volume.
    for week in range(4):
        for visit in range(2):
            day = _snap_to_weekday(t0 + timedelta(weeks=week, days=visit * 2))
            events = [
                {
                    "timestamp": _iso(day.replace(hour=14, minute=0)),
                    "actor": actor, "action": "login", "source_ip": _HOME_IP,
                    "outcome": "success", "geo": _NY_GEO,
                },
                {
                    "timestamp": _iso(day.replace(hour=14, minute=10)),
                    "actor": actor, "action": "file_access", "source_ip": _HOME_IP,
                    "target": _STAGING_TARGETS[0], "outcome": "success",
                },
            ]
            fired, incidents = post_events_and_check(client, events)
            any_incident = any_incident or fired
            incidents_seen.extend(incidents)
    dim("stage B (persistence, 4 weeks, 2 quiet visits/week): "
        f"{'incident raised' if any_incident else 'no incident'}")

    # Stage C — data staging: 8 weekly visits, 1-2 files each, progressively more sensitive.
    for week in range(8):
        day = _snap_to_weekday(t0 + timedelta(weeks=4 + week))
        count = 1 if week < 4 else 2
        events = [
            {
                "timestamp": _iso(day.replace(hour=14, minute=0)),
                "actor": actor, "action": "login", "source_ip": _HOME_IP,
                "outcome": "success", "geo": _NY_GEO,
            }
        ]
        for i in range(count):
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=14, minute=10 + i * 5)),
                    "actor": actor, "action": "file_access", "source_ip": _HOME_IP,
                    "target": _STAGING_TARGETS[(week + i) % len(_STAGING_TARGETS)],
                    "outcome": "success",
                }
            )
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
    dim("stage C (data staging, 8 weekly visits, 1-2 files each): "
        f"{'incident raised' if any_incident else 'no incident'}")

    # Stage D — exfiltration: 6 cycles, paced 12+ days apart, well under both the single-event
    # and cumulative-window thresholds.
    for cycle in range(6):
        day = _snap_to_weekday(t0 + timedelta(weeks=12, days=_WINDOW_SPREAD_GAP_DAYS * cycle))
        events = [
            {
                "timestamp": _iso(day.replace(hour=14, minute=0)),
                "actor": actor, "action": "data_transfer", "source_ip": _HOME_IP,
                "target": "unfamiliar-storage-relay.example.net", "bytes": 280_000_000,
                "outcome": "success",
            }
        ]
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
    dim("stage D (exfiltration, 6 cycles, 12+ days apart): "
        f"{'incident raised' if any_incident else 'no incident'}")

    caught = email_caught or any_incident
    color = _GREEN if caught else _RED
    cordon(f"~4-5 month campaign complete -> {_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    sc.record(
        1, "Long-dwell multi-stage campaign",
        "every stage individually stays under a windowed/static threshold; spread across months means no 24h/7-day/30-day window ever sees more than one quiet stage",
        caught,
        (f"initial-access email: verdict={resp['verdict']}; " + _describe_incidents(incidents_seen))
        if (email_caught or any_incident) else
        "initial-access email stayed safe (score 8/100) and all 4 activity stages across ~5 months raised nothing",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 2 — Living off the land
# --------------------------------------------------------------------------------------------
#
# Targets the structural fact that every detector is a threshold or a baseline comparison —
# activity that matches an account's own established pattern cannot cross either, by
# construction. This isn't evasion, it's the honest ceiling of purely statistical detection.

def run_scenario_2_living_off_the_land(client: AegisClient, run_id: str, t0: datetime, sc: Scorecard) -> None:
    scenario(2, "LIVING OFF THE LAND")
    actor = f"lotl.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)}: a compromised account that never deviates from its own")
    attacker("established hours, location, or volume — just keeps doing what it always does...")
    time.sleep(0.5)

    any_incident = False
    incidents_seen: list[dict] = []
    days = _business_days(t0, 45)

    for day_index, day in enumerate(days):
        events = [
            {
                "timestamp": _iso(day.replace(hour=11, minute=0)),
                "actor": actor, "action": "login", "source_ip": _HOME_IP,
                "outcome": "success", "geo": _NY_GEO,
            }
        ]
        for i in range(4):
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=11, minute=5 + i * 5)),
                    "actor": actor, "action": "file_access", "source_ip": _HOME_IP,
                    "target": _STAGING_TARGETS[i % len(_STAGING_TARGETS)], "outcome": "success",
                }
            )
        if day_index >= 15 and day_index % 10 == 0:
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=11, minute=30)),
                    "actor": actor, "action": "data_transfer", "source_ip": _HOME_IP,
                    "target": f"partner-sync-{day_index}.example.net", "bytes": 60_000_000,
                    "outcome": "success",
                }
            )
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(f"45 business days of unchanged, established-pattern activity -> "
           f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    sc.record(
        2, "Living off the land",
        "every detector is a static threshold or a baseline comparison — activity matching an established pattern has nothing to cross, structurally, not by evasion",
        caught,
        _describe_incidents(incidents_seen) if caught else
        "45 business days at unchanged hours/location/volume raised nothing — there is no content or resource-sensitivity signal to detect against",
    )


# --------------------------------------------------------------------------------------------
# Scenario 3 — Targeted spear-phish from a compromised, previously-contacted sender
# --------------------------------------------------------------------------------------------
#
# Targets Stage 3a's own trust model at its sharpest point: FIRST_CONTACT_SENDER and
# UNKNOWN_VENDOR_CLAIM are gated on classification == FIRST_CONTACT specifically
# (app/sender_history/aggregation.py). A SINGLE prior innocuous email — not the fuller
# "regular correspondent" ESTABLISHED bar (>=3 occurrences spanning >=1 day), just one prior
# contact ever — already reclassifies the domain as SEEN_BEFORE and permanently suppresses
# both checks. Verified against the real engine while writing this script: one prior email,
# seconds earlier, was enough. A mailbox this account has ever legitimately heard from once is
# a blind spot the moment it's compromised.

def run_scenario_3_targeted_compromised_vendor(client: AegisClient, run_id: str, pace: float, sc: Scorecard) -> None:
    scenario(3, "TARGETED SPEAR-PHISH FROM A COMPROMISED SENDER")
    domain = _readable_domain(run_id, "scenario3-vendor")
    attacker(f"a genuinely benign mailbox at {_c(_BOLD, domain)} sends one innocuous email,")
    attacker("then gets compromised — the follow-up lure is personalized, references real")
    attacker("internal context, and claims nothing suspicious...")
    time.sleep(min(pace, 2))

    prior_email = f"""From: "Alex Chen" <alex.chen@{domain}>
To: sarah.kim@ourcompany.example
Subject: Question about scheduling
Date: Tue, 25 Aug 2026 14:00:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Sarah, would sometime next week work for a quick call? Happy to work
around your schedule.

Alex
"""
    prior_resp = client.post("/api/analyze/text", {"raw_text": prior_email})
    dim(f"prior contact (innocuous): verdict={prior_resp['verdict']} score={prior_resp['score']}/100")

    lure = f"""From: "Alex Chen" <alex.chen@{domain}>
To: sarah.kim@ourcompany.example
Subject: Notes from the Tuesday sync
Date: Wed, 26 Aug 2026 09:40:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Sarah,

Good talking through the Q4 rollout plan earlier. I pulled together the
shipment schedule we mentioned - take a look when you get a chance:

https://{domain}/schedules/q4-rollout

Let me know if the dates on your end still line up.

Alex
"""
    lure_resp = client.post("/api/analyze/text", {"raw_text": lure})
    verdict = lure_resp["verdict"]
    score = lure_resp["score"]
    indicator_titles = [i["title"] for i in lure_resp["indicators"]]
    caught = verdict != "safe"

    color = _GREEN if caught else _RED
    cordon(f"personalized follow-up lure -> verdict={_c(_BOLD + color, verdict.upper())} score={score}/100")
    if indicator_titles:
        for title in indicator_titles:
            dim(f"- {title}")
    else:
        dim("(zero indicators fired — one prior contact was enough to suppress FIRST_CONTACT_SENDER/UNKNOWN_VENDOR_CLAIM)")

    sc.record(
        3, "Targeted spear-phish from a compromised sender",
        "FIRST_CONTACT_SENDER/UNKNOWN_VENDOR_CLAIM are gated on true first contact — a single prior innocuous email permanently suppresses both, no sustained trust required",
        caught, f"verdict={verdict} score={score}/100, {len(indicator_titles)} indicator(s) fired",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 4 — Distributed low-volume exfiltration
# --------------------------------------------------------------------------------------------
#
# Same window-spread mechanic as scenario 1's stage D and phase 3 scenario 2, extended: more
# destinations (cosmetic — cumulative_exfiltration.py sums per-ACTOR across every destination,
# so destination variety doesn't matter mechanically, same correction phase 3 made), smaller
# per-transfer size, longer total duration — the point is underlining that patience alone,
# not cleverness about destinations, is what defeats this check.

_EXFIL_HOSTS = [
    "unfamiliar-cdn-node.example.net",
    "partner-backup-relay.example.net",
    "unfamiliar-storage-relay.example.net",
    "edge-cache-mirror.example.net",
]


def run_scenario_4_distributed_low_volume_exfil(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(4, "DISTRIBUTED LOW-VOLUME EXFILTRATION")
    actor = f"distributed.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)}: small transfers to {len(_EXFIL_HOSTS)} different unfamiliar")
    attacker("destinations, paced 12+ days apart, over 15+ weeks — destination variety doesn't")
    attacker("matter here, the check sums per-actor regardless; only the pacing does...")
    time.sleep(min(pace, 2))

    any_incident = False
    incidents_seen: list[dict] = []
    total_bytes = 0
    cycles = 9

    for cycle in range(cycles):
        day = _snap_to_weekday(t0 + timedelta(days=_WINDOW_SPREAD_GAP_DAYS * cycle))
        size = 150_000_000
        events = [
            {
                "timestamp": _iso(day.replace(hour=15, minute=0)),
                "actor": actor, "action": "data_transfer", "source_ip": _HOME_IP,
                "target": _EXFIL_HOSTS[cycle % len(_EXFIL_HOSTS)], "bytes": size,
                "outcome": "success",
            }
        ]
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)
        total_bytes += size
        dim(f"cycle {cycle + 1}/{cycles} ({day.date()}): 1 transfer to {_EXFIL_HOSTS[cycle % len(_EXFIL_HOSTS)]}, "
            f"{size:,} bytes -> {'incident raised' if fired else 'no incident'}")

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(f"after {cycles} cycles and {total_bytes:,} total bytes across "
           f"{len(_EXFIL_HOSTS)} destinations -> {_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    sc.record(
        4, "Distributed low-volume exfiltration",
        "cumulative check is an actor-total regardless of destination count; pacing beyond the 7-day window at any volume/duration evades it",
        caught,
        _describe_incidents(incidents_seen) if caught else
        f"no incident across any of {cycles} cycles ({total_bytes:,} bytes total across {len(_EXFIL_HOSTS)} destinations)",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 5 — Insider with tradecraft
# --------------------------------------------------------------------------------------------
#
# Reuses phase 3's exact, numerically-verified baseline-poisoning ramp (no day's count ever
# exceeds mean + 3*stddev of its own prior rolling history — verified against
# app.baselines.aggregation.is_volume_anomalous's real formula, not eyeballed), then continues
# at the poisoned steady-state for 10 more days instead of one theft day, to underline that the
# exfiltration is ongoing and indistinguishable from the actor's own (poisoned) norm, not a
# single event.

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
_POISON_RAMP = [4, 4, 5, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 12, 13, 14]
_POISON_STEADY_STATE_COUNT = 15
_POISON_STEADY_STATE_DAYS = 10


def _poison_pool(day_index: int) -> list[str]:
    sensitive_in_pool = min(len(_POISON_SENSITIVE_TARGETS), day_index // 4)
    normal_in_pool = len(_POISON_NORMAL_TARGETS) - sensitive_in_pool
    return _POISON_NORMAL_TARGETS[:normal_in_pool] + _POISON_SENSITIVE_TARGETS[:sensitive_in_pool]


def run_scenario_5_insider_with_tradecraft(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(5, "INSIDER WITH TRADECRAFT")
    actor = f"tradecraft.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)}: {len(_POISON_RAMP)} days gradually raising their own daily")
    attacker("file-access volume while mixing in more sensitive files each week, poisoning the")
    attacker(f"30-day rolling baseline — then {_POISON_STEADY_STATE_DAYS} MORE days of sustained")
    attacker("access at that now-normal rate, never a single spike...")
    time.sleep(min(pace, 2))

    days = _business_days(t0, len(_POISON_RAMP) + _POISON_STEADY_STATE_DAYS)
    any_incident = False

    for day_index, day in enumerate(days[: len(_POISON_RAMP)]):
        count = _POISON_RAMP[day_index]
        pool = _poison_pool(day_index)
        events = [
            {
                "timestamp": _iso(day.replace(hour=15, minute=0)),
                "actor": actor, "action": "login", "source_ip": _HOME_IP,
                "outcome": "success", "geo": _NY_GEO,
            }
        ]
        for i in range(count):
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=15, minute=5 + i * 2)),
                    "actor": actor, "action": "file_access", "source_ip": _HOME_IP,
                    "target": pool[i % len(pool)], "outcome": "success",
                }
            )
        fired, _ = post_events_and_check(client, events)
        any_incident = any_incident or fired
    dim(f"poisoning ramp ({len(_POISON_RAMP)} days, 4->14/day): "
        f"{'incident raised (unexpected!)' if any_incident else 'safe throughout, as expected'}")

    for day in days[len(_POISON_RAMP):]:
        events = [
            {
                "timestamp": _iso(day.replace(hour=15, minute=0)),
                "actor": actor, "action": "login", "source_ip": _HOME_IP,
                "outcome": "success", "geo": _NY_GEO,
            }
        ]
        for i in range(_POISON_STEADY_STATE_COUNT):
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=15, minute=5 + i * 2)),
                    "actor": actor, "action": "file_access", "source_ip": _HOME_IP,
                    "target": _POISON_SENSITIVE_TARGETS[i % len(_POISON_SENSITIVE_TARGETS)],
                    "outcome": "success",
                }
            )
        fired, _ = post_events_and_check(client, events)
        any_incident = any_incident or fired

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(f"{_POISON_STEADY_STATE_DAYS} days of sustained access at the poisoned steady-state "
           f"({_POISON_STEADY_STATE_COUNT}/day, entirely sensitive) -> "
           f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    sc.record(
        5, "Insider with tradecraft",
        "30-day rolling volume baseline is designed to adapt; sustained access at the now-poisoned rate is indistinguishable from the actor's own norm",
        caught,
        "an incident fired during the run" if caught else
        f"{len(_POISON_RAMP)}-day ramp plus {_POISON_STEADY_STATE_DAYS} days of sustained all-sensitive access, all inside the actor's own (poisoned) baseline — nothing fired",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 6 — Coordinated multi-vector across unrelated infrastructure
# --------------------------------------------------------------------------------------------
#
# Targets both cross-actor mechanisms at once: detect_coordinated_campaign only ever considers
# actors that are ALREADY individually non-safe (app/detections/cross_actor.py); detect_
# password_spray only groups by shared /24 subnet. A campaign where every account's own
# activity stays under its own per-actor thresholds AND every account uses a wholly unrelated
# subnet defeats both simultaneously — there is no correlation input to correlate.

_VECTOR_ACTOR_COUNT = 5


def run_scenario_6_coordinated_multi_vector(client: AegisClient, run_id: str, t0: datetime, pace: float, sc: Scorecard) -> None:
    scenario(6, "COORDINATED MULTI-VECTOR ACROSS UNRELATED INFRASTRUCTURE")
    attacker(f"{_VECTOR_ACTOR_COUNT} accounts, each on its own unrelated /24 subnet, each doing")
    attacker("its own small piece of the campaign — a few failed logins, one ordinary login,")
    attacker("one modest transfer — every account individually sub-threshold, submitted")
    attacker("together as one coordinated operation...")
    time.sleep(min(pace, 2))

    actors = [f"vector-{i}.{run_id}@victimcorp.example" for i in range(_VECTOR_ACTOR_COUNT)]
    run_salt = _run_salt_octet(run_id)
    events = []
    for idx, actor in enumerate(actors):
        # Third octet varies by run (run_salt) so a re-run's subnet keys never collide with
        # a prior run's leftover auth_fail events on the same literal subnet — the
        # cross-actor spray/coordinated-campaign checks correlate over the account's whole
        # lookback window, not just this batch, so a fixed IP would risk quietly
        # accumulating actors across separate script runs.
        subnet_ip = f"172.{16 + idx}.{run_salt}.5"
        actor_t0 = t0 + timedelta(minutes=idx * 3)
        for i in range(3):  # under the per-actor brute-force floor (5)
            events.append(
                {
                    "timestamp": _iso(actor_t0 + timedelta(minutes=i)),
                    "actor": actor, "action": "auth_fail", "source_ip": subnet_ip,
                    "outcome": "failure",
                }
            )
        events.append(
            {
                "timestamp": _iso(actor_t0 + timedelta(minutes=3)),
                "actor": actor, "action": "login", "source_ip": subnet_ip,
                "outcome": "success", "geo": _NY_GEO,
            }
        )
        events.append(
            {
                "timestamp": _iso(actor_t0 + timedelta(minutes=8)),
                "actor": actor, "action": "data_transfer", "source_ip": subnet_ip,
                "target": "unfamiliar-storage-relay.example.net", "bytes": 180_000_000,
                "outcome": "success",
            }
        )

    fired, incidents = post_events_and_check(client, events)
    caught = fired
    color = _GREEN if caught else _RED
    cordon(f"{_VECTOR_ACTOR_COUNT}-account coordinated campaign, each on its own subnet, "
           f"each individually sub-threshold -> "
           f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")
    sc.record(
        6, "Coordinated multi-vector across unrelated infrastructure",
        "cross-actor correlation only ever considers already-non-safe actors — if every account stays individually sub-threshold, there's no candidate to correlate, regardless of how coordinated the underlying campaign is",
        caught,
        _describe_incidents(incidents) if caught else
        f"0 of {_VECTOR_ACTOR_COUNT} accounts individually crossed any per-actor threshold, so the coordinated-campaign correlation never saw a candidate",
    )
    time.sleep(pace)


# --------------------------------------------------------------------------------------------
# Scenario 7 — Benign-heavy control (the must-pass scenario)
# --------------------------------------------------------------------------------------------
#
# The real bar this round: heavy, varied, realistic legitimate activity — including genuinely
# recurring vendor correspondence using natural business language (renewals, reviews,
# invoices) from senders that are no longer first-contact — must never produce an incident or
# a non-safe email verdict. Any hit here is a genuine false positive, not a finding.

_CONTROL_BENIGN_TARGETS = [
    "shared/onboarding/welcome-guide.pdf",
    "shared/team-project/status-update.pptx",
    "shared/handbook/pto-policy.pdf",
]
_CONTROL_ACTOR_COUNT = 5
_CONTROL_SHARED_IP_GROUP_SIZE = 7  # one below cross_actor_spray_min_actors (8)


def run_scenario_7_benign_heavy_control(client: AegisClient, run_id: str, t0: datetime, sc: Scorecard) -> None:
    scenario(7, "BENIGN-HEAVY CONTROL")
    attacker("(no attacker this round — heavy realistic legitimate activity, including real")
    attacker("recurring vendor correspondence, held to the zero-false-positive bar)")
    time.sleep(0.5)

    any_false_positive = False

    for index in range(_CONTROL_ACTOR_COUNT):
        day = _snap_to_weekday(t0 + timedelta(days=index))
        actor = f"control-{index}.{run_id}@victimcorp.example"
        events = [
            {
                "timestamp": _iso(day.replace(hour=10, minute=0)),
                "actor": actor, "action": "login", "source_ip": _HOME_IP,
                "outcome": "success", "geo": _NY_GEO,
            }
        ]
        for i in range(4 + index):
            events.append(
                {
                    "timestamp": _iso(day.replace(hour=10, minute=5 + i * 5)),
                    "actor": actor, "action": "file_access", "source_ip": _HOME_IP,
                    "target": _CONTROL_BENIGN_TARGETS[i % len(_CONTROL_BENIGN_TARGETS)],
                    "outcome": "success",
                }
            )
        fired, incidents = post_events_and_check(client, events)
        if fired:
            any_false_positive = True
            cordon(_c(_BOLD + _RED, f"FALSE POSITIVE: {actor} (normal activity) raised an incident!"))
            dim(_describe_incidents(incidents))
            sc.record_false_positive(f"{actor}: {_describe_incidents(incidents)}")
        else:
            cordon(f"{actor}: varied normal day, correctly stayed safe.")

    for v in range(3):
        domain = _readable_domain(run_id, f"scenario7-vendor-{v}")
        prior = f"""From: "Vendor Contact" <hello@{domain}>
To: ap-team@ourcompany.example
Subject: Quick question
Date: Mon, 24 Aug 2026 09:00:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi, just confirming the best contact for billing questions going forward. Thanks!
"""
        prior_resp = client.post("/api/analyze/text", {"raw_text": prior})
        followup = f"""From: "Vendor Contact" <hello@{domain}>
To: ap-team@ourcompany.example
Subject: Your subscription renewal
Date: Wed, 26 Aug 2026 09:00:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi, just a heads up that your subscription renewal is coming up next month.
No action needed unless you'd like to make changes to your plan.
"""
        followup_resp = client.post("/api/analyze/text", {"raw_text": followup})
        if followup_resp["verdict"] != "safe":
            any_false_positive = True
            cordon(_c(_BOLD + _RED, f"FALSE POSITIVE: recurring vendor {domain} flagged as {followup_resp['verdict']}!"))
            sc.record_false_positive(f"{domain}: verdict={followup_resp['verdict']} score={followup_resp['score']}")
        else:
            cordon(f"recurring vendor {domain}: ordinary renewal language, correctly stayed safe "
                   f"(prior contact suppressed the check).")

    # Third octet varies by run (same rationale as scenario 6) — a fixed shared IP reused
    # across script runs would risk a rerun's 7 employees combining with a prior run's
    # leftover 7 on the exact same IP, crossing the 8-actor spray floor as a pure artifact
    # of re-running the harness rather than any real coordinated pattern.
    control_shared_ip = f"198.51.{_run_salt_octet(run_id)}.50"
    shared_ip_day = _snap_to_weekday(t0 + timedelta(days=7))
    events = []
    for i in range(_CONTROL_SHARED_IP_GROUP_SIZE):
        events.append(
            {
                "timestamp": _iso(shared_ip_day.replace(hour=9, minute=i)),
                "actor": f"employee-{i}.{run_id}@victimcorp.example",
                "action": "auth_fail", "source_ip": control_shared_ip, "outcome": "failure",
            }
        )
    fired, incidents = post_events_and_check(client, events)
    if fired:
        any_false_positive = True
        cordon(_c(_BOLD + _RED,
                  f"FALSE POSITIVE: {_CONTROL_SHARED_IP_GROUP_SIZE} employees mistyping a password "
                  f"from a shared IP raised an incident!"))
        sc.record_false_positive(
            f"{_CONTROL_SHARED_IP_GROUP_SIZE} employees, shared IP: {_describe_incidents(incidents)}"
        )
    else:
        cordon(f"{_CONTROL_SHARED_IP_GROUP_SIZE} employees mistyping a password from a shared IP "
               f"(1 below the spray floor) -> correctly stayed safe.")

    if not any_false_positive:
        dim("Zero false positives across all benign-heavy control activity.")


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

    banner("CORDON PHASE 4 — NATION-STATE / APT-GRADE RED-TEAM STRESS TEST (authorized, synthetic data)")
    print(_c(_DIM, f"Target backend : {args.base_url}"))
    print(_c(_DIM, f"Frontend       : {FRONTEND_URL}  (log in with the same account to watch)"))
    print()
    print("This is the final and hardest round. These adversaries are patient, well-resourced,")
    print("and already know every detection Cordon has. MOST SCENARIOS ARE EXPECTED TO SUCCEED —")
    print("that's the honest ceiling of today's statistical/threshold-based detection, not a bug.")
    print("Scenario 7 (zero false positives under load) is the real must-pass bar.")
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

        run_scenario_1_long_dwell_campaign(client, run_id, now - timedelta(days=150), args.pace, sc)

        run_scenario_2_living_off_the_land(client, run_id, now - timedelta(days=90), sc)

        run_scenario_3_targeted_compromised_vendor(client, run_id, args.pace, sc)

        run_scenario_4_distributed_low_volume_exfil(client, run_id, now - timedelta(days=110), args.pace, sc)

        run_scenario_5_insider_with_tradecraft(client, run_id, now - timedelta(days=45), args.pace, sc)

        run_scenario_6_coordinated_multi_vector(client, run_id, now - timedelta(hours=2), args.pace, sc)

        run_scenario_7_benign_heavy_control(client, run_id, now - timedelta(days=14), sc)

        sc.print_report()

        banner("CAMPAIGN COMPLETE")
        print(f"Run id (actor suffix) : {run_id}")
        print("Check the Cases and Detections tabs in the frontend —")
        print(f"{FRONTEND_URL}")
        print()
        print(_c(_DIM, "Re-run any time — every actor identity is freshened per run."))
        print(_c(_DIM, "scripts/cleanup_sim.py wipes everything phases 1-4 created."))
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
