from __future__ import annotations

import httpx
import respx

from app.core.config import settings
from app.simulation.dns_check import (
    domain_is_verified_by,
    resolve_txt,
    verification_record_name,
    verification_record_value,
)


def test_verification_record_name_and_value_shape():
    assert verification_record_name("example.com") == "_cordon-verify.example.com"
    assert verification_record_value("abc123") == "cordon-domain-verification=abc123"


def test_resolve_txt_returns_matching_value():
    with respx.mock() as mock:
        mock.get(settings.simulation_dns_over_https_url).mock(
            return_value=httpx.Response(
                200,
                json={"Answer": [{"data": '"cordon-domain-verification=abc123"'}]},
            )
        )
        values = resolve_txt("_cordon-verify.example.com")

    assert values == ["cordon-domain-verification=abc123"]


def test_resolve_txt_no_answer_returns_empty_list():
    with respx.mock() as mock:
        mock.get(settings.simulation_dns_over_https_url).mock(
            return_value=httpx.Response(200, json={})
        )
        values = resolve_txt("_cordon-verify.example.com")

    assert values == []


def test_resolve_txt_malformed_json_does_not_raise():
    with respx.mock() as mock:
        mock.get(settings.simulation_dns_over_https_url).mock(
            return_value=httpx.Response(200, content=b"not json")
        )
        values = resolve_txt("_cordon-verify.example.com")

    assert values == []


def test_resolve_txt_http_error_does_not_raise():
    with respx.mock() as mock:
        mock.get(settings.simulation_dns_over_https_url).mock(
            return_value=httpx.Response(503)
        )
        values = resolve_txt("_cordon-verify.example.com")

    assert values == []


def test_domain_is_verified_by_true_on_match():
    with respx.mock() as mock:
        mock.get(settings.simulation_dns_over_https_url).mock(
            return_value=httpx.Response(
                200,
                json={"Answer": [{"data": '"cordon-domain-verification=abc123"'}]},
            )
        )
        assert domain_is_verified_by("abc123", "example.com") is True


def test_domain_is_verified_by_false_on_mismatch():
    with respx.mock() as mock:
        mock.get(settings.simulation_dns_over_https_url).mock(
            return_value=httpx.Response(
                200,
                json={"Answer": [{"data": '"cordon-domain-verification=different-token"'}]},
            )
        )
        assert domain_is_verified_by("abc123", "example.com") is False
