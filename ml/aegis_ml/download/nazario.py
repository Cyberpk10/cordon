"""Downloads Jose Nazario's phishing corpus.

Verified 2026-08-07: the primary host (monkey.org) was unreachable from the environment
this was written in, but general internet access was fine from that same shell — likely a
sandbox-specific network policy, not the site being down. A recent (2026-06-07) Wayback
Machine snapshot of the corpus index confirmed the classic files below are still listed, so
this downloader tries monkey.org directly first and falls back to the Wayback Machine. The
fallback requests the content-serving endpoint directly with a generic timestamp (relying on
its normal 302-to-closest-snapshot redirect behavior) rather than first resolving an exact
snapshot via the separate `/wayback/available` lookup API — see `_try_wayback`'s docstring for
why (that lookup API proved aggressively, persistently rate-limited during this project's own
usage).

CORE_FILES: the well-known, unambiguously-a-file classic corpus (phishing0-3.mbox,
20051114.mbox).

YEARLY_FILES: re-verified 2026-10-06 (still unreachable directly from this sandbox; same
Wayback fallback used). The 2026-08-07 pass had left `phishing-2015` .. `phishing-2025` out
specifically because their directory-vs-file shape was unconfirmed. This pass fetched the
live Apache directory listing via Wayback and confirmed each one IS a plain file (real,
distinct byte sizes shown in the listing — an Apache directory entry would show no size), and
spot-checked `phishing-2023` by actually downloading it: real mbox content, "From "-delimited,
real headers, a 2023-dated DKIM-signed phishing message. `phishing-2025` has no Wayback
snapshot yet (too recent) and isn't reachable directly from here, so it's silently skipped by
`_try_wayback`'s normal "not found" path, same as any other temporarily-unavailable file —
not an error. See ml/corpus/sources.md for the full license discussion, including the one
new gap this pass surfaced: a `LICENSE.txt` now exists on the live site (confirmed via the
same directory listing, 18KB) but has no Wayback snapshot and the site itself is unreachable
from here, so its actual terms could not be read this session.
"""

from __future__ import annotations

from pathlib import Path

import requests

from aegis_ml.paths import RAW_NAZARIO_DIR, ensure_dirs

BASE_URL = "https://monkey.org/~jose/phishing/"
CORE_FILES = ["phishing0.mbox", "phishing1.mbox", "phishing2.mbox", "phishing3.mbox", "20051114.mbox"]
YEARLY_FILES = [f"phishing-{year}" for year in range(2015, 2026)]

USER_AGENT = "aegis-ml-corpus-builder/0.1 (defensive-security research; contact via GitHub)"
_HEADERS = {"User-Agent": USER_AGENT}


def _looks_like_html(content: bytes) -> bool:
    head = content[:512].lstrip().lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html")


def _try_direct(filename: str, timeout: int = 15) -> bytes | None:
    try:
        resp = requests.get(BASE_URL + filename, timeout=timeout, headers=_HEADERS)
    except requests.RequestException:
        return None
    if resp.status_code == 200 and resp.content and not _looks_like_html(resp.content):
        return resp.content
    return None


def _try_wayback(filename: str, timeout: int = 20) -> bytes | None:
    """Requests the content-serving endpoint directly with a generic/future timestamp instead
    of first resolving an exact snapshot via the `/wayback/available` lookup API.

    Found 2026-10-06: that lookup API is aggressively rate-limited (repeated 429s, still
    failing after several minutes of backoff/retry, during this same session's own earlier
    research calls to it) in a way `_fetch_one`'s per-file retry loop can't reasonably wait
    out. The content endpoint doesn't share that limit, and a timestamp after the newest real
    snapshot (e.g. "2026") 302-redirects to the closest actual one with no separate lookup
    call needed — verified directly: `phishing-2023` via this path returns the same real,
    "From "-delimited mbox content (258 messages) as the old lookup-then-fetch path did for
    other files earlier in this session. requests.get follows redirects by default.
    """
    # "id_" = unmodified original bytes, no Wayback Machine HTML rewriting.
    raw_url = f"https://web.archive.org/web/2026id_/https://monkey.org/~jose/phishing/{filename}"
    try:
        resp = requests.get(raw_url, timeout=timeout, headers=_HEADERS)
    except requests.RequestException:
        return None
    if resp.status_code == 200 and resp.content and not _looks_like_html(resp.content):
        return resp.content
    return None


def _fetch_one(filename: str, local_name: str) -> Path | None:
    """local_name may differ from the remote filename — the yearly files have no extension
    remotely, but are saved locally as `{filename}.mbox` so normalize.py's existing
    `RAW_NAZARIO_DIR.glob("*.mbox")` picks them up with no further changes; the content
    itself (confirmed by direct inspection, see module docstring) is genuine mbox regardless
    of what the remote server names it."""
    dest = RAW_NAZARIO_DIR / local_name
    if dest.exists():
        return dest

    content = _try_direct(filename) or _try_wayback(filename)
    if content is None:
        return None

    dest.write_bytes(content)
    return dest


def download_nazario(include_yearly: bool = True) -> list[Path]:
    """Fetches each core corpus file (skipping ones already on disk), monkey.org first,
    Wayback Machine second. Returns the list of local file paths actually available
    (partial results are fine — the pipeline works with whatever came through).

    include_yearly=True (default) also fetches the modern phishing-2015..2025 files — the
    single biggest lever this pipeline has for the corpus's "trained on a 2000s-2015 era
    vintage" limitation (see ml/models/CARD.md), since it's 10+ more years of the SAME
    already-vetted source/maintainer/convention rather than a new one to separately clear.
    """
    ensure_dirs()
    saved: list[Path] = []
    missing: list[str] = []

    for filename in CORE_FILES:
        result = _fetch_one(filename, filename)
        if result:
            saved.append(result)
        else:
            missing.append(filename)

    if include_yearly:
        for filename in YEARLY_FILES:
            result = _fetch_one(filename, f"{filename}.mbox")
            if result:
                saved.append(result)
            else:
                missing.append(filename)

    if missing:
        print(
            f"[nazario] WARNING: could not fetch {len(missing)} file(s) from monkey.org or "
            f"the Wayback Machine, skipping: {', '.join(missing)}"
        )
    if not saved:
        print(
            "[nazario] WARNING: no Nazario corpus files were downloaded. The phishing class "
            "will have zero records from this source."
        )
    return saved
