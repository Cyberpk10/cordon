#!/usr/bin/env python3
"""One-off extraction: pulls just the hostnames out of the locally-downloaded PhishTank feed
(ml/data/raw/phishtank/online-valid.csv, produced by ml/aegis_ml/download/phishtank.py — NOT
committed, gitignored) into a small, committed, deduplicated hostname list at
backend/app/indicators/data/phishtank_hosts.txt.

Run this once, locally, whenever you want to refresh the list (re-run
`python3 -m aegis_ml.download.phishtank` first to get a fresh CSV) — NOT part of any
deploy/build/CI step. The output file goes stale within days (PhishTank verifies and takes
down phishing URLs quickly) — see the staleness note in app/indicators/known_bad_urls.py.

Usage: python3 scripts/extract_phishtank_hosts.py
"""
from __future__ import annotations

import csv
from pathlib import Path
from urllib.parse import urlsplit

SRC = Path(__file__).parent.parent / "ml" / "data" / "raw" / "phishtank" / "online-valid.csv"
DEST = Path(__file__).parent.parent / "backend" / "app" / "indicators" / "data" / "phishtank_hosts.txt"


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"{SRC} not found — run `python3 -m aegis_ml.download.phishtank` first.")

    hosts: set[str] = set()
    with SRC.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            try:
                netloc = urlsplit(row.get("url", "")).netloc
            except ValueError:
                continue
            netloc = netloc.rsplit("@", 1)[-1].split(":", 1)[0].lower()
            if netloc:
                hosts.add(netloc)

    DEST.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Hostnames extracted from PhishTank's verified-phishing-URL feed "
        "(https://phishtank.org), Cisco Talos, under Cisco's Terms of Use.\n"
        "# Extracted via scripts/extract_phishtank_hosts.py from a one-time local snapshot of\n"
        "# ml/data/raw/phishtank/online-valid.csv — NOT auto-refreshed. PhishTank verifies and\n"
        "# takes down reported phishing infrastructure quickly, so this list goes stale within\n"
        "# days; treat a match as corroborating evidence, not a live reputation feed. Re-run\n"
        "# this script against a freshly-downloaded CSV to refresh.\n"
    )
    DEST.write_text(header + "\n".join(sorted(hosts)) + "\n", encoding="utf-8")
    print(f"Wrote {len(hosts)} unique hostnames to {DEST}")


if __name__ == "__main__":
    main()
