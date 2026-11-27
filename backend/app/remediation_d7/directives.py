"""Signed single-message directives. Pure.

A directive names exactly ONE Gmail message id, the sender+subject fingerprint the add-on
computed when it read that message, the label, a nonce and an expiry, HMAC-SHA256 signed with
settings.d7_directive_secret. The add-on cannot verify the signature (it has no secret); it
echoes the directive back on /claim and /result, where the server verifies it and checks it
against the stored row. There is no list or query form of a directive.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

FIELDS = ("id", "kind", "gmail_message_id", "fingerprint", "label", "nonce", "expires_at")
# Gmail API message ids are lowercase hex (16 today); allow a little headroom, nothing else.
GMAIL_ID_RE = re.compile(r"^[0-9a-f]{10,32}$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical(d: dict) -> bytes:
    return json.dumps({k: d[k] for k in FIELDS}, sort_keys=True, separators=(",", ":")).encode()


def sign(d: dict, secret: str) -> str:
    return hmac.new(secret.encode(), _canonical(d), hashlib.sha256).hexdigest()


def build(fields: dict, secret: str) -> dict:
    d = {k: fields[k] for k in FIELDS}
    return {**d, "sig": sign(d, secret)}


def verify(d: dict, secret: str) -> bool:
    if not secret or not isinstance(d, dict) or set(d) != set(FIELDS) | {"sig"}:
        return False
    if not all(isinstance(d[k], str) for k in FIELDS + ("sig",)):
        return False
    return hmac.compare_digest(sign(d, secret), d["sig"])
