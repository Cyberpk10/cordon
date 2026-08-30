from __future__ import annotations

from app.core.config import settings
from app.indicators import known_bad_urls
from app.parsing.eml_parser import Link, ParsedEmail


def test_flags_link_matching_known_phishing_host(monkeypatch):
    monkeypatch.setattr(
        known_bad_urls, "_load_known_bad_hosts", lambda: frozenset({"evil-phish.example"})
    )
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://evil-phish.example/x", href_domain="evil-phish.example")]
    )
    ids = {i.id for i in known_bad_urls.evaluate(email)}
    assert "LINK_KNOWN_PHISHING_HOST" in ids


def test_no_flag_for_link_not_in_list(monkeypatch):
    monkeypatch.setattr(
        known_bad_urls, "_load_known_bad_hosts", lambda: frozenset({"evil-phish.example"})
    )
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://safe.example/x", href_domain="safe.example")]
    )
    assert known_bad_urls.evaluate(email) == []


def test_disabled_via_settings_flag(monkeypatch):
    monkeypatch.setattr(settings, "enable_known_bad_url_list", False)
    monkeypatch.setattr(
        known_bad_urls, "_load_known_bad_hosts", lambda: frozenset({"evil-phish.example"})
    )
    email = ParsedEmail(
        links=[Link(display_text="click", href="https://evil-phish.example/x", href_domain="evil-phish.example")]
    )
    assert known_bad_urls.evaluate(email) == []
