from __future__ import annotations

from app.simulation.policy import advance_status


def test_click_promotes_pending_to_clicked():
    assert advance_status("pending", "click") == "clicked"


def test_click_promotes_sent_to_clicked():
    assert advance_status("sent", "click") == "clicked"


def test_submit_promotes_clicked_to_submitted():
    assert advance_status("clicked", "submit") == "submitted"


def test_submit_without_prior_click_still_reaches_submitted():
    assert advance_status("sent", "submit") == "submitted"


def test_click_never_regresses_an_already_submitted_recipient():
    assert advance_status("submitted", "click") == "submitted"


def test_submit_never_regresses_an_already_submitted_recipient():
    assert advance_status("submitted", "submit") == "submitted"


def test_click_after_send_failed_still_promotes_to_clicked():
    """A click is direct proof the link was reachable — it overrides our own bookkeeping
    even if we'd recorded the send itself as failed."""
    assert advance_status("send_failed", "click") == "clicked"


def test_repeated_clicks_do_not_regress_status():
    assert advance_status("clicked", "click") == "clicked"
