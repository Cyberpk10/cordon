#!/usr/bin/env python3
"""PHASE 5 — stress-tests the two newest Cordon capabilities added after the last Phase 4
run: threat-intelligence enrichment (app/threat_intel/) and the early-warning sensor
(app/threat_level/ + app/early_warning/). Authorized, dev-only, synthetic data — same
pattern as phases 1-4: every "attacker" action is a synthetic API call, nothing here sends
real email or performs any real network attack.

Two mechanisms verified against the real engine before writing these scenarios, not assumed:
  - LINK_KNOWN_MALICIOUS matches a link's host against the bundled threat-intel snapshot
    (backend/app/threat_intel/data/hostnames.txt) and scores 60 (HIGH) ALONE — comfortably
    past SUSPICIOUS_MAX (54) into MALICIOUS on its own. Scenario 1 reads a real, currently-
    bundled hostname straight out of that file at runtime rather than hardcoding one.
  - The early-warning sensor's kill-chain corroboration (app.threat_level.aggregation.
    compute_band) is chain-POSITION-based, not time-based: simulated against the real
    half-life (14d)/chain-multiplier (1.8x)/elevated-floor (25)/min-corroborating-stages (2)
    formulas, a delivery(18pts, malicious phish via known-bad infra) -> access(8pts, 2
    failed logins) -> collection(10pts, first-ever sensitive-file access) progression
    crosses into ATTACK_FORMING at the ACCESS stage (score ~31, 2 distinct stages) whether
    those three signals land 2/3 days apart or 2/3 HOURS apart — 6 days or 6 hours before a
    real 600MB exfil transfer at the chain's end. Scenarios 3/4 replay this exact cadence.

One honest design note surfaced while building this, not fixed here (out of scope for a
red-team script): Threat Level's location-based auth-anomaly weak signal is gated on the
baseline having >=10 events (threat_level_min_events_for_location_check), which is HIGHER
than the real ANOMALOUS_LOCATION detector's own gate (baseline_min_events_for_location=5) —
so a genuine new-location login in that regime trips the real detector immediately rather
than staying a sub-incident precursor signal. Scenarios 3/4 use sub-floor failed logins for
the "access" stage instead (a channel that IS verified to stay sub-incident), and this gap
is called out plainly in the closing assessment rather than papered over.

This script only ever talks to --base-url (default http://localhost:8000) — check that value
before running it. Pointing --base-url at a real deployment means the case/incident/threat-
level/early-warning data this creates is real, persisted data there — see
scripts/cleanup_sim.py to delete cases/incidents afterward (it does not currently clean up
ActorThreatLevel/EarlyWarningAlert rows, same as it doesn't clean up ActorBaseline rows from
phases 2-4 today — pre-existing scope, not something this script changes).

Usage:
    python3 scripts/attack_sim_phase5.py
    python3 scripts/attack_sim_phase5.py --base-url http://localhost:8000 --pace 0 --no-prompt

Account resolution is identical to phases 1-4. Stdlib only. Ends with a SCORECARD: per-
scenario caught/missed, PLUS (new) whether early warning fired and at which stage, overall
detection rate, false positives from the benign control, and a candid "what still gets past
us" section.
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
from pathlib import Path

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_ACCOUNT_NAME = "Aegis Demo Account"
EMAIL_ENV_VAR = "AEGIS_EMAIL"
PASSWORD_ENV_VAR = "AEGIS_PASSWORD"
FRONTEND_URL = "http://localhost:5173"

_THREAT_INTEL_HOSTNAMES_PATH = (
    Path(__file__).parent.parent / "backend" / "app" / "threat_intel" / "data" / "hostnames.txt"
)

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
    """Thin stdlib HTTP wrapper — duplicated from phases 1-4 rather than imported (matches
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
    """Identical logic to phases 1-4's — logs in if the account exists, signs up if not,
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
    # New in phase 5: did the early-warning sensor raise an "attack forming" alert for this
    # scenario's actor, and (if so) how early relative to the real incident? None = not
    # applicable to this scenario (single-shot email scenarios never accumulate 2 distinct
    # kill-chain stages, so attack_forming structurally can't fire for them).
    early_warning_fired: bool | None = None
    early_warning_detail: str | None = None


@dataclass
class Scorecard:
    entries: list[ScorecardEntry] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    def record(self, number: int, name: str, mechanism: str, caught: bool, detail: str,
               expected_to_evade: bool = True, early_warning_fired: bool | None = None,
               early_warning_detail: str | None = None) -> None:
        self.entries.append(
            ScorecardEntry(
                number, name, mechanism, caught, detail, expected_to_evade,
                early_warning_fired, early_warning_detail,
            )
        )

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
            if e.early_warning_fired is not None:
                ew_tag = (
                    _c(_BOLD + _GREEN, "EARLY WARNING FIRED")
                    if e.early_warning_fired
                    else _c(_BOLD + _RED, "EARLY WARNING NEVER FIRED")
                )
                print(f"     early warning: {ew_tag}")
                if e.early_warning_detail:
                    print(_c(_DIM, f"                    {e.early_warning_detail}"))

        print()
        print(
            f"Detection rate: "
            + _c(_BOLD + rate_color, f"{caught_count}/{total}")
            + f" scenarios raised a non-safe verdict or incident."
        )

        ew_applicable = [e for e in self.entries if e.early_warning_fired is not None]
        if ew_applicable:
            ew_fired_count = sum(1 for e in ew_applicable if e.early_warning_fired)
            print(
                f"Early warning:  "
                + _c(_BOLD + _GREEN, f"{ew_fired_count}/{len(ew_applicable)}")
                + " chain scenarios raised an 'attack forming' alert before the real incident."
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
            print(_c(_BOLD + _YELLOW, "Weakest spots (deliberate controls / still-open gaps):"))
            for e in misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        if unexpected_misses:
            print(_c(_BOLD + _RED, "Unexpected misses (should have been caught — investigate):"))
            for e in unexpected_misses:
                print(f"  - {_c(_BOLD, e.name)}: {e.mechanism}")
        if not misses and not unexpected_misses:
            print(_c(_BOLD + _GREEN, "No misses this run — every scenario was caught."))

        print()
        print(_c(_BOLD + _YELLOW, "What still gets past us, and why:"))
        for line in _HONEST_ASSESSMENT:
            print(f"  - {line}")


_HONEST_ASSESSMENT = [
    "Threat-intel enrichment is exactly as good as its snapshot and nothing more: it catches "
    "infrastructure a feed has already reported (scenario 1), and is structurally blind to "
    "anything not yet reported anywhere (scenario 2) — that's the nature of a blocklist, not "
    "a bug in the matching logic.",
    "The bundled IP/CIDR snapshot (ips.txt, meant for the Tor exit-node list) is still empty "
    "in this environment — scripts/refresh_threat_intel.py's Tor fetch remains blocked from "
    "this sandbox's network. SENDER_IP_KNOWN_MALICIOUS/EVENT_IP_KNOWN_MALICIOUS are fully "
    "wired but have no real IP data to match against here; re-run the refresh script from a "
    "network that can reach check.torproject.org to close that gap.",
    "The early-warning sensor's kill-chain corroboration is chain-POSITION-based, not "
    "time-based (scenarios 3 vs 4 fire at the identical stage regardless of whether the gaps "
    "are days or hours) — a genuinely different, attacker-speed-invariant property from every "
    "window/threshold detector elsewhere in the engine. But it still needs 2+ DISTINCT "
    "kill-chain stages to ever cross into attack_forming; a disciplined actor who never trips "
    "more than one distinct stage's worth of weak signal (pure living-off-the-land, scenario "
    "5) stays invisible to this too, exactly as documented when it shipped.",
    "Found while building this script, not fixed here: Threat Level's location-based "
    "auth-anomaly weak signal (a login from a never-seen country) is gated on the baseline "
    "having >=10 events, which is HIGHER than the real ANOMALOUS_LOCATION detector's own "
    "gate (5 events) — so that specific weak-signal channel can't actually fire without the "
    "real detector also firing at the same moment. It isn't filling a distinct gap the way "
    "the other three weak-signal channels (auth-fail count, first-sensitive-access, small "
    "transfer) do. Worth revisiting in a later stage.",
    "Also found while building this script (scenario 6c's first draft actually tripped this "
    "before being corrected — a real live result, not a hypothetical): 2+ Stage D weak-signal "
    "categories landing in the SAME batch adds Stage D's own co-occurrence bonus "
    "(STAGE_D_ACCUMULATOR_SIGNAL, 15pts) to Early Warning's tally too, chain-boosted to 27 — "
    "past the 25 elevated floor BY ITSELF, before the two original signals are even counted. "
    "That's consistent with Stage D's deliberate design (simultaneous co-occurrence IS "
    "stronger evidence than staggered occurrences), but it means the real zero-false-positive "
    "margin is narrower than 'any two coincidental weak signals within the chain window' — "
    "it specifically depends on whether they land in the same ingestion batch. Worth knowing "
    "before assuming Early Warning's false-positive rate matches Stage D's own, separately "
    "calibrated, zero-FP guarantees.",
    "None of this is a bug to patch — it's the honest ceiling of a snapshot-based intel feed "
    "plus a corroboration-based early-warning sensor: both are real, working improvements "
    "over having neither, not a general answer to unreported infrastructure or a "
    "single-stage-disciplined attacker.",
]


# --------------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------------

_NY_GEO = {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060}
_HOME_IP = "198.51.100.20"

_CONTROL_BENIGN_TARGETS = [
    "shared/roadmap/notes.docx",
    "shared/roadmap/status.pptx",
    "shared/meeting-minutes.docx",
]
_CONTROL_ACTOR_COUNT = 5
_CONTROL_SHARED_IP_GROUP_SIZE = 7  # one below cross_actor_spray_min_actors (8)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _business_days(start: datetime, count: int) -> list[datetime]:
    days: list[datetime] = []
    current = start
    while len(days) < count:
        if current.weekday() < 5:
            days.append(current)
        current += timedelta(days=1)
    return days


def _snap_to_weekday(dt: datetime) -> datetime:
    return _business_days(dt, 1)[0]


def _anchor_wednesday(before_days: int) -> datetime:
    """A datetime roughly `before_days` days before now, snapped to the nearest Wednesday at
    09:00 UTC. Wednesday is the only weekday where t+2, t+5, and t+8 CALENDAR days all land
    on weekdays too — needed since off_hours_access flags weekends unconditionally
    regardless of baseline, and the chain scenarios' exact calendar-day gaps are load-bearing
    for the early-warning decay math verified in this script's docstring."""
    target = datetime.now(timezone.utc) - timedelta(days=before_days)
    offset = (target.weekday() - 2) % 7
    target -= timedelta(days=offset)
    return target.replace(hour=9, minute=0, second=0, microsecond=0)


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


def _check_early_warning(client: AegisClient, actor: str) -> dict | None:
    resp = client.get("/api/early-warnings")
    for alert in resp.get("alerts", []):
        if alert.get("actor") == actor and alert.get("band") == "attack_forming":
            return alert
    return None


def _format_timedelta(td: timedelta) -> str:
    total_hours = td.total_seconds() / 3600
    if total_hours >= 48:
        return f"{td.days} days"
    return f"{total_hours:.0f} hours"


# Reused verbatim from phase 4: a distinct, letter-only, readable-looking domain per
# (run_id, salt) — varies across runs so a re-run never accidentally inherits a prior run's
# sender-history/threat-level state for the same identity.
_SLUG_WORDS_A = [
    "cedar", "harbor", "summit", "brightpath", "fernwood", "aldergate",
    "brookline", "westfield", "clearwater", "hillcrest", "silverpine", "oakridge",
]
_SLUG_WORDS_B = [
    "notes", "logistics", "partners", "compliance", "services", "solutions",
    "consulting", "analytics", "ventures", "systems", "worldwide", "group",
]


def _readable_domain(run_id: str, salt: str) -> str:
    digest = hashlib.sha256(f"{run_id}:{salt}".encode()).digest()
    h = int.from_bytes(digest, "big")
    word_a = _SLUG_WORDS_A[h % len(_SLUG_WORDS_A)]
    word_b = _SLUG_WORDS_B[(h // len(_SLUG_WORDS_A)) % len(_SLUG_WORDS_B)]
    return f"{word_a}-{word_b}.example"


def _run_salt_octet(run_id: str) -> int:
    return int(hashlib.sha256(run_id.encode()).hexdigest()[:2], 16)


def _pick_bundled_known_bad_host(run_id: str) -> str:
    """Reads a REAL, currently-bundled threat-intel hostname straight out of the committed
    snapshot (backend/app/threat_intel/data/hostnames.txt) — not hardcoded, so this stays
    valid as the snapshot is refreshed (see scripts/refresh_threat_intel.py)."""
    if not _THREAT_INTEL_HOSTNAMES_PATH.exists():
        raise RuntimeError(
            f"{_THREAT_INTEL_HOSTNAMES_PATH} not found — run "
            f"`python3 scripts/refresh_threat_intel.py` first to populate the bundled snapshot."
        )
    hosts: list[str] = []
    for line in _THREAT_INTEL_HOSTNAMES_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "\t" not in line:
            continue
        _, _, value = line.partition("\t")
        if value:
            hosts.append(value)
    if not hosts:
        raise RuntimeError(
            f"{_THREAT_INTEL_HOSTNAMES_PATH} has no entries — run "
            f"`python3 scripts/refresh_threat_intel.py` first to populate the bundled snapshot."
        )
    digest = hashlib.sha256(run_id.encode()).digest()
    index = int.from_bytes(digest, "big") % len(hosts)
    return hosts[index]


def _lure_email(actor: str, sender_domain: str, link_host: str, sent_at: datetime) -> str:
    return f"""From: "Dana Whitfield" <dana.whitfield@{sender_domain}>
To: {actor}
Subject: A resource you might find useful
Date: {sent_at.strftime("%a, %d %b %Y %H:%M:%S +0000")}
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom={sender_domain}; dkim=pass header.d={sender_domain}; dmarc=pass header.from={sender_domain}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi,

I came across some research that seemed relevant to what your team's been
working on lately, so I figured I'd pass it along in case it's useful.

Here's the write-up: https://{link_host}/notes/industry-trends-2026

No need to reply either way.

Dana
"""


# --------------------------------------------------------------------------------------------
# Scenario 1 — Phishing via KNOWN-BAD infrastructure
# --------------------------------------------------------------------------------------------


def run_scenario_1_known_bad_infra(client: AegisClient, run_id: str, sc: Scorecard) -> None:
    scenario(1, "PHISHING VIA KNOWN-BAD INFRASTRUCTURE")
    actor = f"knownbad.{run_id}@victimcorp.example"
    bad_host = _pick_bundled_known_bad_host(run_id)
    sender_domain = _readable_domain(run_id, "scenario1-sender")
    attacker(f"same silent, low-key lure phase 4 verified scores only 8 points on its own —")
    attacker(f"except this link's host ({_c(_BOLD, bad_host)}) is a REAL entry in the bundled")
    attacker("PhishTank threat-intel snapshot...")
    time.sleep(0.5)

    raw_email = _lure_email(actor, sender_domain, bad_host, datetime.now(timezone.utc))
    resp = client.post("/api/analyze/text", {"raw_text": raw_email})
    caught = resp["verdict"] == "malicious"
    match_ind = next((i for i in resp.get("indicators", []) if i["id"] == "LINK_KNOWN_MALICIOUS"), None)
    evidence = match_ind["evidence"][0] if match_ind and match_ind.get("evidence") else None

    color = _GREEN if caught else _RED
    cordon(f"verdict={_c(_BOLD + color, resp['verdict'].upper())} score={resp['score']}/100")
    if evidence:
        dim(f"LINK_KNOWN_MALICIOUS evidence: {evidence}")

    sc.record(
        1, "Phishing via known-bad infrastructure",
        "LINK_KNOWN_MALICIOUS matches the link host against the bundled multi-feed threat-intel snapshot",
        caught,
        f"verdict={resp['verdict']} score={resp['score']}/100"
        + (f"; evidence: {evidence}" if evidence else "; LINK_KNOWN_MALICIOUS did not fire (unexpected)"),
        expected_to_evade=False,
    )


# --------------------------------------------------------------------------------------------
# Scenario 2 — Same lure, CLEAN (unknown) infrastructure
# --------------------------------------------------------------------------------------------


def run_scenario_2_clean_infra(client: AegisClient, run_id: str, sc: Scorecard) -> None:
    scenario(2, "SAME PHISHING LURE, CLEAN (UNKNOWN) INFRASTRUCTURE")
    actor = f"cleaninfra.{run_id}@victimcorp.example"
    clean_host = _readable_domain(run_id, "scenario2-link")
    sender_domain = _readable_domain(run_id, "scenario2-sender")
    attacker(f"identical lure, but the link host ({_c(_BOLD, clean_host)}) has never been")
    attacker("reported by any feed — proving scenario 1's catch was the intel, not the lure text...")
    time.sleep(0.5)

    raw_email = _lure_email(actor, sender_domain, clean_host, datetime.now(timezone.utc))
    resp = client.post("/api/analyze/text", {"raw_text": raw_email})
    caught = resp["verdict"] != "safe"
    color = _RED if caught else _GREEN
    cordon(f"verdict={_c(_BOLD + color, resp['verdict'].upper())} score={resp['score']}/100")

    sc.record(
        2, "Same lure, clean infrastructure",
        "threat-intel enrichment only matches infrastructure a feed has actually reported — clean infra gets nothing extra",
        caught,
        f"verdict={resp['verdict']} score={resp['score']}/100 "
        f"({len(resp.get('indicators', []))} indicator(s) fired) — same lure text as scenario 1, "
        "the only difference is the link host isn't on any feed",
    )


# --------------------------------------------------------------------------------------------
# Scenarios 3 & 4 — Chained attack: does early warning fire mid-chain?
# --------------------------------------------------------------------------------------------


def _run_chain_scenario(
    client: AegisClient, run_id: str, sc: Scorecard, *,
    number: int, title: str, t0: datetime,
    stage2_gap: timedelta, stage3_gap: timedelta, stage4_gap: timedelta,
) -> None:
    scenario(number, title)
    actor = f"chain{number}.{run_id}@victimcorp.example"
    attacker(f"{_c(_BOLD, actor)}: phish via known-bad infra (delivery) -> a couple of failed")
    attacker("logins (access) -> first-ever finance-file access (collection) -> a real 600MB")
    attacker("exfil transfer — does early warning corroborate the chain before the exfil hits?")
    time.sleep(0.5)

    link_host = _pick_bundled_known_bad_host(run_id)
    sender_domain = _readable_domain(run_id, f"scenario{number}-sender")

    stage_times = {
        1: t0,
        2: t0 + stage2_gap,
        3: t0 + stage2_gap + stage3_gap,
        4: t0 + stage2_gap + stage3_gap + stage4_gap,
    }
    stage_names = {
        1: "delivery (known-bad phish)",
        2: "access (failed logins)",
        3: "collection (first sensitive access)",
        4: "exfiltration",
    }
    fired_stage: int | None = None

    # Stage 1 — delivery: phishing email via known-bad infrastructure -> MALICIOUS case.
    raw_email = _lure_email(actor, sender_domain, link_host, stage_times[1])
    resp = client.post("/api/analyze/text", {"raw_text": raw_email})
    dim(f"stage 1 (delivery, {stage_times[1].strftime('%Y-%m-%d %H:%M')}): "
        f"verdict={resp['verdict']} score={resp['score']}/100")
    if _check_early_warning(client, actor):
        fired_stage = 1

    # Stage 2 — access: a couple of sub-floor failed logins (well below brute_force's 5-floor).
    events = [
        {"timestamp": _iso(stage_times[2]), "actor": actor, "action": "auth_fail", "outcome": "failure"}
        for _ in range(2)
    ]
    client.post("/api/events", {"events": events})
    dim(f"stage 2 (access, {stage_times[2].strftime('%Y-%m-%d %H:%M')}): 2 failed logins posted")
    if fired_stage is None and _check_early_warning(client, actor):
        fired_stage = 2

    # Stage 3 — collection: first-ever finance-file access (cold-start, below the real
    # SENSITIVE_RESOURCE_FIRST_ACCESS detector's own gate).
    events = [
        {
            "timestamp": _iso(stage_times[3]), "actor": actor, "action": "file_access",
            "target": "finance/board-deck-q3.pptx", "outcome": "success",
        }
    ]
    client.post("/api/events", {"events": events})
    dim(f"stage 3 (collection, {stage_times[3].strftime('%Y-%m-%d %H:%M')}): "
        f"first finance-file access posted")
    if fired_stage is None and _check_early_warning(client, actor):
        fired_stage = 3

    # Stage 4 — exfiltration: a real, unambiguous large transfer.
    events = [
        {
            "timestamp": _iso(stage_times[4]), "actor": actor, "action": "data_transfer",
            "target": "unfamiliar-storage-relay.example.net", "bytes": 600_000_000, "outcome": "success",
        }
    ]
    incident_fired, incidents = post_events_and_check(client, events)
    dim(f"stage 4 (exfiltration, {stage_times[4].strftime('%Y-%m-%d %H:%M')}, 600MB transfer): "
        f"{'incident raised' if incident_fired else 'no incident'}")
    if fired_stage is None and _check_early_warning(client, actor):
        fired_stage = 4

    if fired_stage is not None and fired_stage < 4:
        lead_time = _format_timedelta(stage_times[4] - stage_times[fired_stage])
        ew_detail = f"fired at stage {fired_stage} ({stage_names[fired_stage]}) — {lead_time} before the incident"
        cordon(_c(_BOLD + _GREEN,
                  f"EARLY WARNING fired at stage {fired_stage} ({stage_names[fired_stage]}), "
                  f"{lead_time} before the exfil incident."))
    elif fired_stage == 4:
        ew_detail = "only fired alongside stage 4 — no lead time over the incident"
        cordon(_c(_BOLD + _YELLOW, "Early warning only fired at stage 4 — no lead time over the incident."))
    else:
        ew_detail = "never fired for this chain"
        cordon(_c(_BOLD + _RED, "Early warning never fired for this chain."))

    sc.record(
        number, title,
        "does early-warning's kill-chain corroboration raise 'attack forming' before the real incident fires",
        incident_fired,
        _describe_incidents(incidents) if incident_fired else "no incident raised — verdict stayed safe",
        expected_to_evade=False,
        early_warning_fired=(fired_stage is not None),
        early_warning_detail=ew_detail,
    )


def run_scenario_3_multi_day_chain(client: AegisClient, run_id: str, sc: Scorecard) -> None:
    t0 = _anchor_wednesday(30)
    _run_chain_scenario(
        client, run_id, sc,
        number=3, title="MULTI-STAGE CHAIN, SPREAD OVER DAYS", t0=t0,
        stage2_gap=timedelta(days=2), stage3_gap=timedelta(days=3), stage4_gap=timedelta(days=3),
    )


def run_scenario_4_fast_chain(client: AegisClient, run_id: str, sc: Scorecard) -> None:
    t0 = _anchor_wednesday(10).replace(hour=9)
    _run_chain_scenario(
        client, run_id, sc,
        number=4, title="SAME CHAIN, FAST SMASH-AND-GRAB (HOURS APART)", t0=t0,
        stage2_gap=timedelta(hours=2), stage3_gap=timedelta(hours=3), stage4_gap=timedelta(hours=3),
    )


# --------------------------------------------------------------------------------------------
# Scenario 5 — Living off the land (unchanged control, ported from phase 4)
# --------------------------------------------------------------------------------------------

_STAGING_TARGETS = [
    "shared/roadmap/notes.docx",
    "shared/roadmap/status.pptx",
    "finance/vendor-list.xlsx",
    "hr/org-chart.pdf",
    "legal/contracts-index.docx",
]


def run_scenario_5_living_off_the_land(client: AegisClient, run_id: str, t0: datetime, sc: Scorecard) -> None:
    scenario(5, "LIVING OFF THE LAND (CONTROL — UNCHANGED, EXPECTED MISS)")
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
        fired, incidents = post_events_and_check(client, events)
        any_incident = any_incident or fired
        incidents_seen.extend(incidents)

    caught = any_incident
    color = _GREEN if caught else _RED
    cordon(f"45 business days of unchanged, established-pattern activity -> "
           f"{_c(_BOLD + color, 'CAUGHT' if caught else 'NEVER FLAGGED')}")

    ew_alert = _check_early_warning(client, actor)
    ew_fired = ew_alert is not None
    cordon(f"early warning: {_c(_BOLD + _GREEN, 'fired') if ew_fired else _c(_BOLD + _RED, 'never fired')} "
           f"(expected — no distinct kill-chain stage ever trips, this is a single-stage-disciplined actor)")

    sc.record(
        5, "Living off the land",
        "every detector is a static threshold or a baseline comparison — activity matching an established pattern has nothing to cross, structurally, not by evasion",
        caught,
        _describe_incidents(incidents_seen) if caught else
        "45 business days at unchanged hours/location/volume raised nothing — there is no content or resource-sensitivity signal to detect against",
        early_warning_fired=ew_fired,
        early_warning_detail="never fired — no distinct kill-chain stage was ever tripped, so 2+ stage corroboration has nothing to work with" if not ew_fired else None,
    )


# --------------------------------------------------------------------------------------------
# Scenario 6 — Benign-heavy control
# --------------------------------------------------------------------------------------------


def run_scenario_6_benign_control(client: AegisClient, run_id: str, t0: datetime, sc: Scorecard) -> None:
    scenario(6, "BENIGN-HEAVY CONTROL")
    attacker("(no attacker this round — benign traffic to CLEAN infrastructure, a normal")
    attacker("chained-LOOKING-but-legitimate coincidence, and ordinary employee activity,")
    attacker("all held to the zero-false-positive bar)")
    time.sleep(0.5)

    any_false_positive = False

    # (a) Ordinary employee days.
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

    # (b) A genuinely benign email to CLEAN (never-reported) infrastructure — isolates
    # whether the threat-intel lookup itself ever mistakenly flags an ordinary clean host.
    clean_host = _readable_domain(run_id, "scenario6-clean-link")
    benign_email = f"""From: "IT Helpdesk" <helpdesk@ourcompany.example>
To: employee.{run_id}@victimcorp.example
Subject: Updated internal wiki page
Date: Mon, 24 Aug 2026 09:00:00 +0000
Authentication-Results: mx.ourcompany.example; spf=pass smtp.mailfrom=ourcompany.example; dkim=pass header.d=ourcompany.example; dmarc=pass header.from=ourcompany.example
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi team, the onboarding wiki page has moved: https://{clean_host}/wiki/onboarding

No action needed.
"""
    benign_resp = client.post("/api/analyze/text", {"raw_text": benign_email})
    if benign_resp["verdict"] != "safe":
        any_false_positive = True
        cordon(_c(_BOLD + _RED, f"FALSE POSITIVE: benign email to clean host {clean_host} flagged as {benign_resp['verdict']}!"))
        sc.record_false_positive(f"{clean_host}: verdict={benign_resp['verdict']} score={benign_resp['score']}")
    else:
        cordon(f"benign email to clean host {clean_host}: correctly stayed safe, 0 indicators.")

    # (c) "Looks chained but isn't" — two genuinely INDEPENDENT weak signals (an auth blip,
    # then days later and unrelated, a small transfer), numerically verified to stay at 21.3
    # (under the 25 elevated floor) before writing this.
    #
    # IMPORTANT — a real finding from building this script, kept here rather than papered
    # over: putting those same two signals in the SAME batch instead (same moment) does NOT
    # stay safe. Stage D's own co-occurrence bonus (STAGE_D_ACCUMULATOR_SIGNAL, 15pts) fires
    # whenever 2+ weak-signal categories land in one batch, and chain-boosted (x1.8) that's
    # 27 points ALONE — already past the elevated floor before the other two signals are even
    # added. This was verified live while building this scenario (a first draft that put both
    # events in one batch scored 49.4 and DID cross into attack_forming). It isn't a bug:
    # Stage D deliberately treats simultaneous co-occurrence as stronger evidence than
    # staggered occurrences, and that design intent is inherited by Early Warning too — but
    # it means the real zero-false-positive margin is narrower than "any two coincidental
    # weak signals within the chain window," and it's called out explicitly in the closing
    # assessment below rather than left for someone to discover in production.
    coincidence_actor = f"coincidence.{run_id}@victimcorp.example"
    coincidence_day_1 = _snap_to_weekday(t0 + timedelta(days=17))
    coincidence_day_2 = _snap_to_weekday(t0 + timedelta(days=20))
    client.post("/api/events", {"events": [
        {
            "timestamp": _iso(coincidence_day_1.replace(hour=14, minute=0)),
            "actor": coincidence_actor, "action": "auth_fail", "outcome": "failure",
        },
    ]})
    fired, incidents = post_events_and_check(client, [
        {
            "timestamp": _iso(coincidence_day_2.replace(hour=14, minute=0)),
            "actor": coincidence_actor, "action": "data_transfer",
            "target": "occasional-partner.example.net", "bytes": 8_000_000, "outcome": "success",
        },
    ])
    ew_alert = _check_early_warning(client, coincidence_actor)
    if fired or ew_alert is not None:
        any_false_positive = True
        cordon(_c(_BOLD + _RED,
                  f"FALSE POSITIVE: {coincidence_actor}'s two independent coincidental weak signals "
                  f"tripped {'an incident' if fired else 'an early-warning alert'}!"))
        sc.record_false_positive(f"{coincidence_actor}: incident={fired}, early_warning={ew_alert is not None}")
    else:
        cordon(f"{coincidence_actor}: one coincidental auth blip, then days later and unrelated one "
               f"small transfer — correctly stayed 'normal', no early-warning alert.")

    # (d) Employees mistyping a password from a shared office IP (below the spray floor).
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

    banner("CORDON PHASE 5 — THREAT-INTEL + EARLY-WARNING STRESS TEST (authorized, synthetic data)")
    print(_c(_DIM, f"Target backend : {args.base_url}"))
    print(_c(_DIM, f"Frontend       : {FRONTEND_URL}  (log in with the same account to watch)"))
    print()
    print("Stress-tests the two newest capabilities: multi-feed threat-intel enrichment and")
    print("the early-warning sensor's kill-chain corroboration. This script only ever talks")
    print("to the URL above — double-check it before continuing.")

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

        run_scenario_1_known_bad_infra(client, run_id, sc)
        time.sleep(min(args.pace, 2))

        run_scenario_2_clean_infra(client, run_id, sc)
        time.sleep(min(args.pace, 2))

        run_scenario_3_multi_day_chain(client, run_id, sc)
        time.sleep(min(args.pace, 2))

        run_scenario_4_fast_chain(client, run_id, sc)
        time.sleep(min(args.pace, 2))

        run_scenario_5_living_off_the_land(client, run_id, now - timedelta(days=90), sc)
        time.sleep(min(args.pace, 2))

        run_scenario_6_benign_control(client, run_id, now - timedelta(days=30), sc)

        sc.print_report()

        banner("CAMPAIGN COMPLETE")
        print(f"Run id (actor suffix) : {run_id}")
        print("Check the Cases, Detections, and Early Warnings tabs in the frontend —")
        print(f"{FRONTEND_URL}")
        print()
        print(_c(_DIM, "Re-run any time — every actor identity is freshened per run."))
        print(_c(_DIM, "scripts/cleanup_sim.py wipes cases/incidents phases 1-5 created (not"))
        print(_c(_DIM, "ActorThreatLevel/EarlyWarningAlert rows — see this script's docstring)."))
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
