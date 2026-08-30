#!/usr/bin/env python3
"""Deletes every case and every incident belonging to the account you log into — cleans
up after scripts/attack_sim.py (or any other demo data) so a re-run starts fresh.

This script only ever talks to --base-url (default http://localhost:8000) — check that
value before running it, especially if it points at a shared or production deployment.

WARNING: this deletes ALL cases and ALL incidents for whichever account you log into, not
just ones a simulation created — Aegis's API has no "created by the simulator" marker to
filter on. It asks for a typed confirmation before deleting anything unless --yes is given.

Usage:
    python3 scripts/cleanup_sim.py
    python3 scripts/cleanup_sim.py --base-url https://your-backend.example.com

Credentials resolve the same way as attack_sim.py, and are never hardcoded/printed/committed:
    1. --email / --password flags
    2. AEGIS_EMAIL / AEGIS_PASSWORD environment variables
    3. an interactive prompt at startup (password entry hidden via getpass)
This only ever LOGS IN — it never creates an account. If login fails, there's nothing to
clean up.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://localhost:8000"
EMAIL_ENV_VAR = "AEGIS_EMAIL"
PASSWORD_ENV_VAR = "AEGIS_PASSWORD"
PAGE_SIZE = 100

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"


def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def banner(title: str) -> None:
    print()
    print(_c(_BOLD + _CYAN, "=" * 72))
    print(_c(_BOLD + _CYAN, f" {title}"))
    print(_c(_BOLD + _CYAN, "=" * 72))


def info(msg: str) -> None:
    print(_c(_YELLOW, "[INFO]     ") + msg)


def ok(msg: str) -> None:
    print(_c(_GREEN, "[DONE]     ") + msg)


class HTTPStatusError(RuntimeError):
    def __init__(self, status: int, body: str, path: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"{status} on {path}: {body}")


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
                raise RuntimeError("AegisClient.token is not set — call login() first.")
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
            raise RuntimeError(f"Could not reach Aegis at {self.base_url} ({exc.reason}).") from None

    def post(self, path: str, json_body: dict | None = None, *, auth: bool = True) -> dict:
        return self._request("POST", path, json_body=json_body, auth=auth)

    def get(self, path: str, params: dict | None = None, *, auth: bool = True) -> dict:
        return self._request("GET", path, params=params, auth=auth)

    def delete(self, path: str, *, auth: bool = True) -> dict:
        return self._request("DELETE", path, auth=auth)


def resolve_credentials(args: argparse.Namespace) -> tuple[str, str]:
    """--email/--password flags > AEGIS_EMAIL/AEGIS_PASSWORD env vars > interactive prompt
    (password entry hidden via getpass). Never hardcoded, never logged, never committed."""
    email = args.email or os.environ.get(EMAIL_ENV_VAR)
    if not email:
        email = input("Aegis account email: ").strip()

    password = args.password or os.environ.get(PASSWORD_ENV_VAR)
    if not password:
        password = getpass.getpass("Aegis account password (hidden): ")

    if not email or not password:
        raise RuntimeError("An email and password are required (flags, env vars, or the prompt).")
    return email, password


def login(client: AegisClient, *, email: str, password: str) -> dict:
    """Logs in only — NEVER creates an account (unlike attack_sim.py's ensure_account)."""
    try:
        resp = client.post("/api/auth/login", {"email": email, "password": password}, auth=False)
    except HTTPStatusError as exc:
        if exc.status == 401:
            raise RuntimeError(
                f"Could not log in as {email} on {client.base_url} — either the credentials "
                f"are wrong or this account doesn't exist there. Nothing to clean up."
            ) from None
        raise
    client.token = resp["access_token"]
    return resp["user"]


def _fetch_all(client: AegisClient, path: str) -> list[dict]:
    items: list[dict] = []
    page = 1
    while True:
        resp = client.get(path, {"page": page, "page_size": PAGE_SIZE})
        batch = resp["items"]
        items.extend(batch)
        if not batch or len(items) >= resp["total"]:
            break
        page += 1
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Aegis backend URL (default: %(default)s)")
    parser.add_argument(
        "--email", default=None,
        help=f"Account email. Falls back to ${EMAIL_ENV_VAR}, then an interactive prompt.",
    )
    parser.add_argument(
        "--password", default=None,
        help=f"Account password. Falls back to ${PASSWORD_ENV_VAR}, then a hidden prompt. "
        f"Prefer the env var or prompt over this flag — command-line args are visible in "
        f"your shell history and `ps`.",
    )
    parser.add_argument("--yes", "-y", action="store_true", help="Skip the typed DELETE confirmation")
    args = parser.parse_args()

    banner("AEGIS DEMO-DATA CLEANUP")
    print(_c(_DIM, f"Target backend : {args.base_url}"))
    print("This deletes EVERY case and EVERY incident for the account you log into below —")
    print("not just ones a simulation created. Double-check --base-url before continuing,")
    print("especially if it points at a shared or production deployment.")

    email, password = resolve_credentials(args)
    print(_c(_DIM, f"\nRunning as     : {email}"))

    client = AegisClient(args.base_url)
    try:
        user = login(client, email=email, password=password)
        ok(f"logged in. account_id={user['account_id']}")

        info("Fetching cases and incidents for this account...")
        cases = _fetch_all(client, "/api/cases")
        incidents = _fetch_all(client, "/api/incidents")

        if not cases and not incidents:
            ok("Nothing to clean up — 0 cases, 0 incidents.")
            return 0

        print()
        print(_c(_BOLD, f"Found {len(cases)} case(s) and {len(incidents)} incident(s) for {email}"))
        print(_c(_BOLD, f"on {client.base_url}."))

        if not args.yes:
            confirm = input(_c(_BOLD + _RED, "\nType DELETE to permanently remove all of it: "))
            if confirm.strip() != "DELETE":
                print("Aborted — nothing was deleted.")
                return 1

        print()
        deleted_cases = 0
        for case in cases:
            try:
                client.delete(f"/api/cases/{case['id']}")
                deleted_cases += 1
            except HTTPStatusError as exc:
                print(_c(_RED, f"  failed to delete case {case['id']}: {exc}"), file=sys.stderr)
        ok(f"deleted {deleted_cases}/{len(cases)} case(s).")

        deleted_incidents = 0
        for incident in incidents:
            try:
                client.delete(f"/api/incidents/{incident['id']}")
                deleted_incidents += 1
            except HTTPStatusError as exc:
                print(_c(_RED, f"  failed to delete incident {incident['id']}: {exc}"), file=sys.stderr)
        ok(f"deleted {deleted_incidents}/{len(incidents)} incident(s).")

        banner("CLEANUP COMPLETE")
        return 0
    except RuntimeError as exc:
        print(_c(_RED, f"\n[ERROR] {exc}"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
