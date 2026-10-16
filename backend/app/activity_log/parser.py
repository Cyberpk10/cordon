"""Parses a pasted CSV activity log into the existing ActivityEvent model (app.events.schema)
— pure, no DB, no detection logic. The only job here is mapping one external, coarse-grained
CSV shape onto the normalized event schema the existing intrusion-detection engine already
consumes; app.detections itself is never touched.

Expected header (case-insensitive, exact column order), with `bytes` optional:
    timestamp,account,source_ip,geo,result
    timestamp,account,source_ip,geo,result,bytes

One data row per line. Tolerant of whitespace, blank lines, and '#'-prefixed comment lines
anywhere (including before the header). A row this parser can't make sense of is skipped
rather than failing the whole input — "don't crash" on one bad line — but if that leaves zero
usable events, the caller gets a clear validation error rather than silently analyzing nothing.

`bytes` is optional both as a column (the 5-column header is still accepted, unchanged) and
per-row (an empty or non-numeric value in that column just means "no size given" for that
row — never a parse failure). Nothing here invents a byte count that wasn't in the input.
"""

from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
from uuid import uuid4

from app.events.schema import ActivityEvent, EventAction, GeoLocation

MAX_ROWS = 5000

HEADER_WITHOUT_BYTES = ["timestamp", "account", "source_ip", "geo", "result"]
HEADER_WITH_BYTES = [*HEADER_WITHOUT_BYTES, "bytes"]


class ActivityLogParseError(ValueError):
    """Raised for anything that should surface as a clean 400 to the caller — a missing/
    wrong header, zero usable rows, or more rows than MAX_ROWS."""


def _strip_bom(text: str) -> str:
    return text.lstrip("﻿")


def _is_skippable(line: str) -> bool:
    stripped = line.strip()
    return stripped == "" or stripped.startswith("#")


def _parse_timestamp(raw: str) -> datetime:
    value = raw.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _map_result_to_event_fields(result: str) -> dict:
    """Maps one CSV `result` value onto the existing EventAction taxonomy. An unrecognized
    result value degrades to a generic CONFIG_CHANGE ("something happened, not further
    specified") rather than crashing or being silently dropped — explicitly required by the
    task ("treat unknown result values as a generic event, don't crash")."""
    key = result.strip().upper()
    if key == "SUCCESS":
        return {"action": EventAction.LOGIN, "outcome": "success"}
    if key == "FAIL":
        return {"action": EventAction.AUTH_FAIL, "outcome": "fail"}
    if key == "MFA_DISABLED":
        return {
            "action": EventAction.PRIVILEGE_CHANGE,
            "outcome": "mfa_disabled",
            "target": "mfa_settings",
        }
    if key == "MAIL_RULE_CREATED":
        return {
            "action": EventAction.CONFIG_CHANGE,
            "outcome": "mail_rule_created",
            "target": "inbox_rules",
        }
    if key == "BULK_DOWNLOAD":
        return {
            "action": EventAction.FILE_DOWNLOAD,
            "outcome": "bulk_download",
            "target": "bulk_export",
        }
    return {"action": EventAction.CONFIG_CHANGE, "outcome": key.lower() or "unknown"}


def _parse_bytes(raw: str) -> int | None:
    """Empty, missing, or non-numeric is "no size given," never a parse failure — this
    parser must not invent a byte count the source didn't actually provide."""
    value = raw.strip()
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _row_to_event(fields: list[str], *, has_bytes_column: bool) -> ActivityEvent | None:
    expected_len = 6 if has_bytes_column else 5
    if len(fields) != expected_len:
        return None
    if has_bytes_column:
        timestamp_raw, account, source_ip, geo, result, bytes_raw = (
            f.strip() for f in fields
        )
    else:
        timestamp_raw, account, source_ip, geo, result = (f.strip() for f in fields)
        bytes_raw = ""
    if not timestamp_raw or not account or not result:
        return None
    try:
        timestamp = _parse_timestamp(timestamp_raw)
    except ValueError:
        return None

    kwargs: dict = {
        "id": uuid4(),
        "timestamp": timestamp,
        "actor": account,
        "source_ip": source_ip or None,
        "geo": GeoLocation(country=geo) if geo else None,
        "bytes": _parse_bytes(bytes_raw),
    }
    kwargs.update(_map_result_to_event_fields(result))
    try:
        return ActivityEvent(**kwargs)
    except Exception:  # noqa: BLE001 - one malformed row must never fail the whole batch
        return None


def parse_activity_log_csv(raw_text: str) -> list[ActivityEvent]:
    """Returns every row that parsed into a valid ActivityEvent, in file order. Raises
    ActivityLogParseError (never anything else) for a missing/wrong header, zero usable
    rows, or more data rows than MAX_ROWS — every one of those is a 400-shaped caller error,
    never a 500."""
    text = _strip_bom(raw_text)
    all_lines = text.splitlines()

    content_lines = [line for line in all_lines if not _is_skippable(line)]
    if not content_lines:
        raise ActivityLogParseError("No data found in the pasted log.")

    header_fields = next(csv.reader(StringIO(content_lines[0])), [])
    normalized_header = [f.strip().lower() for f in header_fields]
    if normalized_header == HEADER_WITH_BYTES:
        has_bytes_column = True
    elif normalized_header == HEADER_WITHOUT_BYTES:
        has_bytes_column = False
    else:
        raise ActivityLogParseError(
            "Expected CSV header: timestamp,account,source_ip,geo,result "
            "(optionally with a trailing bytes column)"
        )

    data_lines = content_lines[1:]
    if len(data_lines) > MAX_ROWS:
        raise ActivityLogParseError(
            f"Too many rows in pasted log (max {MAX_ROWS}); split it into smaller batches."
        )

    events: list[ActivityEvent] = []
    for line in data_lines:
        fields = next(csv.reader(StringIO(line)), [])
        event = _row_to_event(fields, has_bytes_column=has_bytes_column)
        if event is not None:
            events.append(event)

    if not events:
        raise ActivityLogParseError(
            "No valid rows could be parsed from the pasted log. Check that it matches the "
            "expected header: timestamp,account,source_ip,geo,result"
        )

    return events
