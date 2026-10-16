from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import settings
from app.detections.base import ActorEventWindow
from app.detections.data_exfiltration import evaluate
from app.events.schema import ActivityEvent, EventAction

_TS = datetime(2026, 1, 6, 14, 0, tzinfo=timezone.utc)


def _transfer(bytes_: int, target: str = "unknown-host.example.net") -> ActivityEvent:
    return ActivityEvent(
        timestamp=_TS,
        actor="erin@corp.com",
        action=EventAction.DATA_TRANSFER,
        target=target,
        bytes=bytes_,
        outcome="success",
    )


def _db_export(bytes_: int) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_TS,
        actor="frank@corp.com",
        action=EventAction.DB_QUERY,
        target="customers_db",
        bytes=bytes_,
        outcome="success",
    )


def test_fires_for_large_transfer_to_unfamiliar_destination():
    window = ActorEventWindow(actor="erin@corp.com", events=[_transfer(600_000_000)])
    findings = evaluate(window)
    ids = [f.id for f in findings]
    assert "DATA_EXFIL_LARGE_TRANSFER" in ids


def test_does_not_fire_for_small_transfer():
    window = ActorEventWindow(actor="erin@corp.com", events=[_transfer(1_000_000)])
    assert evaluate(window) == []


def test_does_not_fire_for_large_transfer_to_allowlisted_destination(monkeypatch):
    monkeypatch.setattr(settings, "exfil_allowlisted_destinations", ["trusted.example.com"])
    window = ActorEventWindow(
        actor="erin@corp.com", events=[_transfer(600_000_000, target="trusted.example.com")]
    )
    assert evaluate(window) == []


def test_fires_for_large_db_export():
    window = ActorEventWindow(actor="frank@corp.com", events=[_db_export(300_000_000)])
    findings = evaluate(window)
    ids = [f.id for f in findings]
    assert "DATA_EXFIL_LARGE_DB_EXPORT" in ids


def test_does_not_fire_for_small_db_query():
    window = ActorEventWindow(actor="frank@corp.com", events=[_db_export(5_000_000)])
    assert evaluate(window) == []


def test_both_findings_can_fire_independently_in_same_window():
    window = ActorEventWindow(
        actor="erin@corp.com", events=[_transfer(600_000_000), _db_export(300_000_000)]
    )
    ids = {f.id for f in evaluate(window)}
    assert ids == {"DATA_EXFIL_LARGE_TRANSFER", "DATA_EXFIL_LARGE_DB_EXPORT"}


def _bulk_download(bytes_: int | None) -> ActivityEvent:
    return ActivityEvent(
        timestamp=_TS,
        actor="gina@corp.com",
        action=EventAction.FILE_DOWNLOAD,
        target="bulk_export",
        bytes=bytes_,
        outcome="bulk_download",
    )


def test_bulk_download_with_a_real_byte_count_cites_the_actual_figure():
    window = ActorEventWindow(actor="gina@corp.com", events=[_bulk_download(900_000_000)])
    findings = evaluate(window)
    ids = [f.id for f in findings]
    assert "DATA_EXFIL_LARGE_TRANSFER" in ids
    finding = next(f for f in findings if f.id == "DATA_EXFIL_LARGE_TRANSFER")
    assert "GB" in finding.description or "MB" in finding.description
    assert "750" not in finding.description


def test_bulk_download_with_no_byte_count_still_fires_but_states_no_number():
    window = ActorEventWindow(actor="gina@corp.com", events=[_bulk_download(None)])
    findings = evaluate(window)
    ids = [f.id for f in findings]
    assert "DATA_EXFIL_LARGE_TRANSFER" in ids
    finding = next(f for f in findings if f.id == "DATA_EXFIL_LARGE_TRANSFER")
    description = finding.description
    for unit in ("B ", "KB", "MB", "GB", "TB", "bytes"):
        assert unit not in description, f"description should cite no size unit: {description!r}"
    assert "750" not in description


def test_bulk_download_without_bytes_never_falls_back_to_the_old_placeholder():
    window = ActorEventWindow(actor="gina@corp.com", events=[_bulk_download(None)])
    findings = evaluate(window)
    for finding in findings:
        assert "750" not in finding.description


def test_bulk_download_does_not_fire_for_allowlisted_destination(monkeypatch):
    monkeypatch.setattr(settings, "exfil_allowlisted_destinations", ["bulk_export"])
    window = ActorEventWindow(actor="gina@corp.com", events=[_bulk_download(None)])
    assert evaluate(window) == []


def test_large_transfer_still_takes_priority_over_unsized_bulk_marker():
    # An event that both clears the byte threshold AND carries the bulk_download outcome
    # marker must still be reported through the normal sized path, not duplicated.
    event = ActivityEvent(
        timestamp=_TS,
        actor="gina@corp.com",
        action=EventAction.FILE_DOWNLOAD,
        target="bulk_export",
        bytes=600_000_000,
        outcome="bulk_download",
    )
    window = ActorEventWindow(actor="gina@corp.com", events=[event])
    findings = evaluate(window)
    assert len(findings) == 1
    assert "GB" in findings[0].description or "MB" in findings[0].description
