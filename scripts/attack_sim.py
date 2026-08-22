#!/usr/bin/env python3
"""Red-team attack simulation against a LOCAL Aegis instance — authorized, dev-only,
synthetic data. Drives a paced, multi-stage attack "campaign" purely over Aegis's own HTTP
API (as a real authenticated tenant would) so you can watch cases/incidents/autonomous
response appear live in the React frontend.

This script NEVER talks to anything but --base-url (default http://localhost:8000). It
never touches production, never sends real email, never performs any real network attack —
every "attacker" action is a synthetic API call representing what a SIEM/EDR would have
already told Aegis happened.

Usage:
    python3 scripts/attack_sim.py
    python3 scripts/attack_sim.py --base-url http://localhost:8000 --pace 3 --no-prompt

Stdlib only — no pip install required. Re-runnable: the demo login account is fixed and
reused across runs (signup, or login on a 409 "already exists"); the simulated victim
*employee* identity inside each run's events is freshened per run so detections behave
deterministically regardless of how many times you've already run this.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_EMAIL = "redteam-demo@aegis.local"
DEFAULT_PASSWORD = "RedTeamDemo!2026"
DEFAULT_ACCOUNT_NAME = "Aegis Red Team Demo"
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
    print(_c(_BOLD + _CYAN, "=" * 72))
    print(_c(_BOLD + _CYAN, f" {title}"))
    print(_c(_BOLD + _CYAN, "=" * 72))


def stage(number: int, title: str) -> None:
    print()
    print(_c(_BOLD + _MAGENTA, f"--- STAGE {number}: {title} " + "-" * max(0, 50 - len(title))))


def attacker(msg: str) -> None:
    print(_c(_RED, "[ATTACKER] ") + msg)


def aegis(msg: str) -> None:
    print(_c(_GREEN, "[AEGIS]    ") + msg)


def setup(msg: str) -> None:
    print(_c(_YELLOW, "[SETUP]    ") + msg)


def dim(msg: str) -> None:
    print(_c(_DIM, "           " + msg))


class AegisClient:
    """Thin stdlib HTTP wrapper — no requests/httpx dependency needed to run this script."""

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
                raise RuntimeError("AegisClient.token is not set — call login()/signup() first.")
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise HTTPStatusError(exc.code, body, path) from None
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Could not reach Aegis at {self.base_url} ({exc.reason}). "
                f"Is the backend running? Start it with:\n"
                f"  cd backend && source .venv/bin/activate && uvicorn app.main:app --reload"
            ) from None

    def post(self, path: str, json_body: dict | None = None, *, auth: bool = True) -> dict:
        return self._request("POST", path, json_body=json_body, auth=auth)

    def put(self, path: str, json_body: dict | None = None, *, auth: bool = True) -> dict:
        return self._request("PUT", path, json_body=json_body, auth=auth)

    def get(self, path: str, params: dict | None = None, *, auth: bool = True) -> dict:
        return self._request("GET", path, params=params, auth=auth)


class HTTPStatusError(RuntimeError):
    def __init__(self, status: int, body: str, path: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"{status} on {path}: {body}")


def ensure_demo_account(client: AegisClient, *, email: str, password: str, account_name: str) -> None:
    """Signs up the fixed demo account, or logs in if it already exists (re-runnable)."""
    setup(f"Ensuring demo account {_c(_BOLD, email)} exists...")
    try:
        resp = client.post(
            "/api/auth/signup",
            {"account_name": account_name, "email": email, "password": password},
            auth=False,
        )
        client.token = resp["access_token"]
        aegis(f"account created. account_id={resp['user']['account_id']}")
        return
    except HTTPStatusError as exc:
        if exc.status != 409:
            raise

    resp = client.post("/api/auth/login", {"email": email, "password": password}, auth=False)
    client.token = resp["access_token"]
    aegis(f"logged into existing demo account. account_id={resp['user']['account_id']}")


def configure_autonomy_policy(client: AegisClient) -> None:
    setup("Configuring autonomy policy (level L2, MockConnector — nothing real ever fires)...")
    policy = {
        "level": "L2",
        "rules": [
            {"action_type": "QUARANTINE_EMAIL", "min_confidence": 0.15, "scopes": None, "full_auto": False},
            {"action_type": "BLOCK_SENDER_DOMAIN", "min_confidence": 0.15, "scopes": None, "full_auto": False},
            {"action_type": "FLAG_ACCOUNT_FOR_REVIEW", "min_confidence": 0.15, "scopes": None, "full_auto": False},
            {"action_type": "DISABLE_SESSION", "min_confidence": 0.15, "scopes": None, "full_auto": False},
        ],
        "exclusions": [],
        "blast_radius_limit": 25,
        "blast_radius_window_minutes": 60,
    }
    client.put("/api/autonomy/policy", policy)
    aegis("policy set: level=L2, rules configured for all 4 response actions.")
    dim("(QUARANTINE_EMAIL/BLOCK_SENDER_DOMAIN/DISABLE_SESSION each still have a hard-coded")
    dim(" minimum-confidence floor in app.autonomy.actions — a low rule threshold here just")
    dim(" means the POLICY never becomes the reason something waits for a human.)")


PHISHING_EMAIL = """From: "PayPal Support" <service@paypa1.com>
Reply-To: security-team@secure-mailer.net
To: target-employee@ourcompany.example
Subject: Urgent: Verify your account within 24 hours
Date: Mon, 27 Jul 2026 09:15:00 +0000
Authentication-Results: mx.ourcompany.example; spf=fail smtp.mailfrom=paypa1.com; dkim=fail header.d=paypa1.com; dmarc=fail header.from=paypa1.com
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_NextPart_paypal_001"

------=_NextPart_paypal_001
Content-Type: text/plain; charset="utf-8"

URGENT: Your PayPal account will be suspended.

We detected unusual sign-in activity on your account. You must verify your
account within 24 hours or your account will be suspended. This is your
final notice — failure to comply will result in permanent account closure.

Verify your account now: https://paypa1.com/verify-account

- PayPal Security Team

------=_NextPart_paypal_001
Content-Type: text/html; charset="utf-8"

<html><body>
<p><b>URGENT:</b> Your PayPal account will be suspended.</p>
<p>We detected unusual sign-in activity on your account. You must
<b>verify your account within 24 hours</b> or your account will be suspended.</p>
<p><a href="https://paypa1.com/verify-account">https://www.paypal.com/verify</a></p>
<p>Failure to comply will result in permanent account closure.</p>
<p>- PayPal Security Team</p>
</body></html>

------=_NextPart_paypal_001--
"""


def run_stage_1_phishing_lure(client: AegisClient, pace: float) -> str:
    stage(1, "RECON / PHISHING LURE")
    attacker("crafting a look-alike-domain credential-harvest email (paypa1.com) and")
    attacker("sending it in via /api/analyze/text (simulating an inbound-forwarded email)...")
    time.sleep(min(pace, 2))

    resp = client.post("/api/analyze/text", {"raw_text": PHISHING_EMAIL})
    case_id = resp["id"]
    verdict = resp["verdict"].upper()
    score = resp["score"]
    indicator_titles = [i["title"] for i in resp["indicators"]]

    color = _RED if verdict == "MALICIOUS" else _YELLOW
    aegis(f"case {case_id} analyzed -> verdict={_c(_BOLD + color, verdict)} score={score}/100")
    for title in indicator_titles:
        dim(f"- {title}")

    time.sleep(pace)
    return case_id


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _print_incident_result(resp: dict, label: str) -> str | None:
    created = resp.get("incidents_created") or []
    if not created:
        aegis(f"{label}: no incident raised (verdict stayed safe) — accepted {resp.get('accepted')} events.")
        return None
    incident = created[0]
    verdict = incident["verdict"].upper()
    color = _RED if verdict == "MALICIOUS" else _YELLOW if verdict == "SUSPICIOUS" else _GREEN
    aegis(
        f"{label}: incident {_c(_BOLD, incident['id'])} -> "
        f"{_c(_BOLD + color, verdict)} risk={incident['score']}/100"
    )
    dim("detections: " + ", ".join(incident["detection_types"]))
    return incident["id"]


def run_stage_2_brute_force(client: AegisClient, actor: str, t0: datetime, pace: float) -> tuple[str | None, datetime]:
    stage(2, "BRUTE FORCE")
    attacker(f"launching a password-spray against {_c(_BOLD, actor)} (6 failed logins in 5 minutes)...")
    time.sleep(min(pace, 2))

    success_at = t0 + timedelta(minutes=6)
    events = [
        {
            "timestamp": _iso(t0 + timedelta(minutes=i)),
            "actor": actor,
            "action": "auth_fail",
            "source_ip": "203.0.113.10",
            "outcome": "failure",
        }
        for i in range(6)
    ]
    events.append(
        {
            "timestamp": _iso(success_at),
            "actor": actor,
            "action": "login",
            "source_ip": "203.0.113.10",
            "outcome": "success",
            "geo": {"country": "US", "region": "NY", "lat": 40.7128, "lon": -74.0060},
        }
    )
    resp = client.post("/api/events", {"events": events})
    incident_id = _print_incident_result(resp, "brute-force batch")
    time.sleep(pace)
    return incident_id, success_at


def run_stage_3_account_takeover(client: AegisClient, actor: str, prior_login_at: datetime, pace: float) -> str | None:
    stage(3, "ACCOUNT TAKEOVER (IMPOSSIBLE TRAVEL)")
    attacker(f"a successful login for {_c(_BOLD, actor)} lands from Moscow just 30 minutes")
    attacker("after the New York login above — no human travels that fast.")
    time.sleep(min(pace, 2))

    takeover_at = prior_login_at + timedelta(minutes=30)
    events = [
        {
            "timestamp": _iso(takeover_at),
            "actor": actor,
            "action": "login",
            "source_ip": "91.198.174.2",
            "outcome": "success",
            "geo": {"country": "RU", "region": "Moscow", "lat": 55.7558, "lon": 37.6173},
        }
    ]
    resp = client.post("/api/events", {"events": events})
    incident_id = _print_incident_result(resp, "account-takeover batch")
    time.sleep(pace)
    return incident_id


def run_stage_4_lateral_movement(client: AegisClient, actor: str, t0: datetime, pace: float) -> str | None:
    stage(4, "LATERAL MOVEMENT / PRIVILEGE ABUSE")
    attacker(f"{_c(_BOLD, actor)} is escalated to admin and starts touching sensitive")
    attacker("finance/HR resources...")
    time.sleep(min(pace, 2))

    events = [
        {
            "timestamp": _iso(t0 + timedelta(minutes=40)),
            "actor": actor,
            "action": "privilege_change",
            "target": f"{actor} -> admin",
            "outcome": "success",
        },
        {
            "timestamp": _iso(t0 + timedelta(minutes=41)),
            "actor": actor,
            "action": "file_access",
            "target": "finance/payroll_2026.xlsx",
            "outcome": "success",
        },
        {
            "timestamp": _iso(t0 + timedelta(minutes=42)),
            "actor": actor,
            "action": "file_access",
            "target": "hr/employee_records.csv",
            "outcome": "success",
        },
    ]
    resp = client.post("/api/events", {"events": events})
    incident_id = _print_incident_result(resp, "privilege-escalation batch")
    time.sleep(pace)
    return incident_id


def run_stage_5_exfiltration(client: AegisClient, actor: str, t0: datetime, pace: float) -> str | None:
    stage(5, "EXFILTRATION")
    attacker(f"{_c(_BOLD, actor)} downloads 22 confidential files, then transfers 650MB")
    attacker("to an unrecognized external host...")
    time.sleep(min(pace, 2))

    events = [
        {
            "timestamp": _iso(t0 + timedelta(minutes=45 + i)),
            "actor": actor,
            "action": "file_download",
            "target": f"shared/confidential-doc-{i}.pdf",
            "outcome": "success",
        }
        for i in range(22)
    ]
    events.append(
        {
            "timestamp": _iso(t0 + timedelta(minutes=68)),
            "actor": actor,
            "action": "data_transfer",
            "target": "unknown-host.example.net",
            "bytes": 650_000_000,
            "outcome": "success",
        }
    )
    resp = client.post("/api/events", {"events": events})
    incident_id = _print_incident_result(resp, "exfiltration batch")
    time.sleep(pace)
    return incident_id


def _print_autonomy_rows(client: AegisClient, *, case_id: str | None = None, incident_id: str | None = None) -> None:
    params = {}
    if case_id:
        params["case_id"] = case_id
    if incident_id:
        params["incident_id"] = incident_id
    rows = client.get("/api/autonomy/actions", params=params)["items"]
    if not rows:
        dim("(no autonomy actions mapped for this finding set)")
        return
    for row in rows:
        decision = row["decision"]
        status = row["status"]
        confidence = row["confidence"]
        action_type = row["action_type"]
        if status == "executed":
            tag = _c(_BOLD + _GREEN, "AUTO-EXECUTED")
            explain = "confidence cleared the policy + action floor"
        elif status == "pending_approval":
            tag = _c(_BOLD + _YELLOW, "PENDING APPROVAL")
            explain = "irreversible, or confidence below the required floor" if decision == "require_approval" else decision
        elif status == "skipped":
            tag = _c(_DIM, "SKIPPED")
            explain = "no matching policy rule for this action type"
        else:
            tag = _c(_RED, status.upper())
            explain = decision
        aegis(f"  -> {action_type:<24} {tag:<28} confidence={confidence:.2f}  target={row['target']}")
        dim(f"     {explain}")


def run_stage_6_autonomous_response(
    client: AegisClient, *, case_id: str, incident_ids: list[str]
) -> None:
    stage(6, "AUTONOMOUS RESPONSE")
    aegis("evaluating the response playbook for the phishing case...")
    client.post(f"/api/cases/{case_id}/remediate")
    _print_autonomy_rows(client, case_id=case_id)

    for idx, incident_id in enumerate(incident_ids, start=1):
        if incident_id is None:
            continue
        print()
        aegis(f"evaluating the response playbook for incident #{idx} ({incident_id})...")
        client.post(f"/api/incidents/{incident_id}/remediate")
        _print_autonomy_rows(client, incident_id=incident_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Aegis backend URL (default: %(default)s)")
    parser.add_argument("--email", default=DEFAULT_EMAIL, help="Demo account email (default: %(default)s)")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Demo account password (default: %(default)s)")
    parser.add_argument("--account-name", default=DEFAULT_ACCOUNT_NAME)
    parser.add_argument("--pace", type=float, default=4.0, help="Seconds between stages (default: %(default)s)")
    parser.add_argument("--no-prompt", action="store_true", help="Skip the 'press Enter to start' gate")
    args = parser.parse_args()

    banner("AEGIS RED-TEAM SIMULATION — authorized, local/dev only, synthetic data")
    print(_c(_DIM, f"Target backend : {args.base_url}"))
    print(_c(_DIM, f"Demo login     : {args.email} / {args.password}"))
    print(_c(_DIM, f"Frontend       : {FRONTEND_URL}  (log in, then open the Detections tab)"))
    print()
    print("This script only ever talks to the URL above. Never point --base-url at a")
    print("production/staging deployment.")

    if not args.no_prompt:
        try:
            input(_c(_BOLD, "\nOpen the frontend and log in now, then press Enter to launch the campaign..."))
        except EOFError:
            pass

    client = AegisClient(args.base_url)
    try:
        ensure_demo_account(client, email=args.email, password=args.password, account_name=args.account_name)
        configure_autonomy_policy(client)

        case_id = run_stage_1_phishing_lure(client, args.pace)

        run_id = uuid.uuid4().hex[:8]
        actor = f"alice.chen.{run_id}@victimcorp.example"
        t0 = datetime.now(timezone.utc) - timedelta(hours=2)

        incident_ids: list[str | None] = []
        inc, last_login_at = run_stage_2_brute_force(client, actor, t0, args.pace)
        incident_ids.append(inc)
        incident_ids.append(run_stage_3_account_takeover(client, actor, last_login_at, args.pace))
        incident_ids.append(run_stage_4_lateral_movement(client, actor, t0, args.pace))
        incident_ids.append(run_stage_5_exfiltration(client, actor, t0, args.pace))

        run_stage_6_autonomous_response(
            client, case_id=case_id, incident_ids=[i for i in incident_ids if i]
        )

        banner("CAMPAIGN COMPLETE")
        print(f"Simulated victim identity : {actor}")
        print("Check the Cases, Detections, and Autonomy tabs in the frontend —")
        print(f"{FRONTEND_URL}")
        print()
        print(_c(_DIM, "Re-run this script any time — it logs into the same demo account and"))
        print(_c(_DIM, "uses a fresh synthetic actor identity each run."))
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
