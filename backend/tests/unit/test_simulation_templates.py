from __future__ import annotations

from app.simulation.templates import TEMPLATES


def test_every_template_has_required_fields_populated():
    for template_id, template in TEMPLATES.items():
        assert template.id == template_id
        assert template.subject
        assert template.sender_local_part
        assert template.sender_display_name
        assert template.landing_page_headline
        assert template.landing_page_teaching_points


def test_every_template_body_contains_the_tracking_url_placeholder():
    for template in TEMPLATES.values():
        assert "{tracking_url}" in template.html_body_template
        assert "{tracking_url}" in template.text_body_template


def test_template_bodies_format_cleanly_with_only_tracking_url():
    for template in TEMPLATES.values():
        html = template.html_body_template.format(tracking_url="https://sim.example.com/t/abc")
        text = template.text_body_template.format(tracking_url="https://sim.example.com/t/abc")
        assert "https://sim.example.com/t/abc" in html
        assert "https://sim.example.com/t/abc" in text
