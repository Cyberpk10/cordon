"""Short-lived, in-process cache of pipeline results for the public /v1 API.

Why it exists: with persist="if_not_clean" a clean email is analyzed but never saved, so
there is no Case to reuse. The Outlook add-in analyzes an email and then asks follow-up
questions about it (POST /v1/assistant), and each question needs the same analysis. Without
this cache every chat turn would re-run the whole pipeline (and the LLM analyst, when it is
enabled) and could drift from the verdict the user is looking at.

Keyed by (account id, sha256 of the raw bytes), so one account can never see another's
result. Bounded in both entry count and per-entry size, since a PipelineResult holds the
parsed body. Process-local by design: the backend runs as a single instance (the same
assumption app.auth.rate_limit documents), and a miss just re-runs the pipeline.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import OrderedDict

from app.analysis.email_pipeline import PipelineResult

TTL_SECONDS = 30 * 60
MAX_ENTRIES = 64
# Don't cache unusually large emails: bounds worst-case memory to roughly MAX_ENTRIES MiB.
MAX_CACHEABLE_BYTES = 1024 * 1024

_lock = threading.Lock()
_entries: "OrderedDict[tuple[uuid.UUID, str], tuple[float, PipelineResult]]" = OrderedDict()


def get(account_id: uuid.UUID, content_hash: str) -> PipelineResult | None:
    key = (account_id, content_hash)
    now = time.monotonic()
    with _lock:
        hit = _entries.get(key)
        if hit is None:
            return None
        stored_at, result = hit
        if now - stored_at > TTL_SECONDS:
            del _entries[key]
            return None
        _entries.move_to_end(key)
        return result


def put(account_id: uuid.UUID, content_hash: str, result: PipelineResult, size_bytes: int) -> None:
    if size_bytes > MAX_CACHEABLE_BYTES:
        return
    key = (account_id, content_hash)
    with _lock:
        _entries[key] = (time.monotonic(), result)
        _entries.move_to_end(key)
        while len(_entries) > MAX_ENTRIES:
            _entries.popitem(last=False)


def clear() -> None:
    with _lock:
        _entries.clear()
