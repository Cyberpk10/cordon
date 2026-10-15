"""Rate limiting for the auth endpoints (M8 Stage 2, expanded in the Stage 5 security-hardening
pass) — login, signup, password-reset request/confirm, refresh, and invite-accept are the
endpoints an attacker would brute-force, credential-stuff, or token-guess against, so they're
the only ones limited. 10/minute per IP is conservative enough that a real user retrying a
mistyped password a few times, or a page that double-submits a form, is never affected, while
still bounding an automated attacker to a few hundred guesses an hour per source IP.

In-memory storage (slowapi's default) — correct for the current single-instance Render
deployment (`render.yaml` has no `numInstances` override, i.e. it's 1): all requests hit the
same process, so one shared in-memory counter is accurate. If this ever moves to multiple
instances (horizontal scaling, blue/green with both serving traffic), in-memory storage would
under-count — each instance enforces the limit independently, so an attacker spread across N
instances effectively gets N times the limit. At that point this needs a shared backend (e.g.
Redis via slowapi's RedisStorage) so every instance enforces against the same counters; not
built now since it isn't needed yet — a real scope boundary, not an oversight.

Fails open, not closed, if the limiter backend itself errors (e.g. a future Redis outage):
slowapi's SlowAPIMiddleware only raises RateLimitExceeded when a limit is actually exceeded —
a storage backend error propagates as a normal exception caught by app.main's generic
exception handler, which logs it and returns a 500 rather than silently admitting every
request unlimited. For the in-memory backend used today this is a non-issue (no network call
that can fail), but it's the reason the generic exception handler is also what keeps a future
Redis blip from becoming a silent, unbounded brute-force window.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

AUTH_RATE_LIMIT = "10/minute"
