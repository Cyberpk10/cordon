from __future__ import annotations

from app.indicators import domain_age_heuristic
from app.parsing.eml_parser import ParsedEmail


def test_flags_high_entropy_alphanumeric_domain():
    email = ParsedEmail(from_address="alerts@xk29fq7z3m1p.com")
    ids = {i.id for i in domain_age_heuristic.evaluate(email)}
    assert "DOMAIN_LOOKS_RANDOMLY_GENERATED" in ids


def test_no_flag_for_real_looking_brand_domain():
    email = ParsedEmail(from_address="billing@acme-vendor.example")
    assert domain_age_heuristic.evaluate(email) == []


def test_no_flag_for_short_domain_label():
    email = ParsedEmail(from_address="hi@ab1.com")
    assert domain_age_heuristic.evaluate(email) == []


def test_disabled_via_settings_flag(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "enable_newly_registered_domain_heuristic", False)
    email = ParsedEmail(from_address="alerts@xk29fq7z3m1p.com")
    assert domain_age_heuristic.evaluate(email) == []
