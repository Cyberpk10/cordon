from __future__ import annotations

from app.indicators.domain_utils import looks_randomly_generated


def test_flags_high_entropy_digit_letter_mix():
    assert looks_randomly_generated("xk29fq7z3m1p", entropy_threshold=3.0) is True


def test_no_flag_for_real_looking_word():
    assert looks_randomly_generated("acme-vendor", entropy_threshold=3.0) is False


def test_no_flag_for_short_label():
    assert looks_randomly_generated("ab1", entropy_threshold=3.0) is False


def test_no_flag_without_digit_letter_mix():
    assert looks_randomly_generated("clearwaterworldwide", entropy_threshold=3.0) is False
