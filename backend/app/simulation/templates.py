"""The phishing-simulation template catalog (M9 Stage 1) — a small, fixed, reviewable set of
generic (non-trademarked, no real-brand impersonation) pretexts, mirroring
app.autonomy.actions.ACTIONS: a frozen-dataclass dict, not a DB table, since Stage 1 templates
are not user-authorable.

Every `html_body_template`/`text_body_template` interpolates exactly one placeholder,
`{tracking_url}` — nothing else in a template body is ever dynamic, so there is no
user-controlled-string interpolation risk on the send side.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SimulationTemplate:
    id: str
    name: str
    category: str
    subject: str
    sender_display_name: str
    sender_local_part: str
    html_body_template: str
    text_body_template: str
    landing_page_headline: str
    landing_page_teaching_points: list[str]
    has_fake_login_form: bool


TEMPLATES: dict[str, SimulationTemplate] = {
    "it_password_reset": SimulationTemplate(
        id="it_password_reset",
        name="IT: password expiring today",
        category="generic_it",
        subject="Action Required: Your Password Expires Today",
        sender_display_name="IT Support",
        sender_local_part="it-support",
        html_body_template=(
            "<p>Hello,</p>"
            "<p>Our records show your network password expires within 24 hours. "
            "To avoid losing access to your account, please confirm your password "
            'now: <a href="{tracking_url}">Keep my account active</a>.</p>'
            "<p>If you do not act before the deadline, your account will be locked "
            "and you will need to contact the helpdesk to restore access.</p>"
            "<p>IT Support</p>"
        ),
        text_body_template=(
            "Hello,\n\nOur records show your network password expires within 24 hours. "
            "To avoid losing access to your account, please confirm your password now: "
            "{tracking_url}\n\nIf you do not act before the deadline, your account will "
            "be locked and you will need to contact the helpdesk to restore access.\n\n"
            "IT Support"
        ),
        landing_page_headline="This was a phishing simulation.",
        landing_page_teaching_points=[
            "Urgency language (\"expires today\", \"act now\") is a classic pressure tactic — "
            "slow down and verify before clicking.",
            "Hover over links before clicking to check where they actually lead.",
            "Legitimate IT teams never ask you to \"confirm your password\" by clicking an "
            "emailed link.",
        ],
        has_fake_login_form=True,
    ),
    "hr_benefits_deadline": SimulationTemplate(
        id="hr_benefits_deadline",
        name="HR: benefits enrollment deadline moved up",
        category="generic_hr",
        subject="Please Review: Benefits Enrollment Deadline Moved Up",
        sender_display_name="HR Team",
        sender_local_part="hr-team",
        html_body_template=(
            "<p>Hi there,</p>"
            "<p>The open-enrollment deadline has been moved up. Please log in to review "
            'and confirm your benefits elections before it closes: '
            '<a href="{tracking_url}">Review my benefits</a>.</p>'
            "<p>Thank you,<br>HR Team</p>"
        ),
        text_body_template=(
            "Hi there,\n\nThe open-enrollment deadline has been moved up. Please log in "
            "to review and confirm your benefits elections before it closes: "
            "{tracking_url}\n\nThank you,\nHR Team"
        ),
        landing_page_headline="This was a phishing simulation.",
        landing_page_teaching_points=[
            "A sudden, unannounced deadline change is a common social-engineering hook.",
            "Go to your HR system directly by typing its address yourself, rather than "
            "clicking a link in an email.",
            "When in doubt, verify with HR through a known channel (phone, in person) "
            "before entering credentials anywhere.",
        ],
        has_fake_login_form=True,
    ),
    "shared_document_notice": SimulationTemplate(
        id="shared_document_notice",
        name="Generic: a document was shared with you",
        category="generic_file_share",
        subject="A document has been shared with you",
        sender_display_name="Document Notifications",
        sender_local_part="notifications",
        html_body_template=(
            "<p>A colleague has shared a document with you.</p>"
            '<p><a href="{tracking_url}">View document</a></p>'
            "<p>This link will expire in 48 hours.</p>"
        ),
        text_body_template=(
            "A colleague has shared a document with you.\n\nView document: {tracking_url}\n\n"
            "This link will expire in 48 hours."
        ),
        landing_page_headline="This was a phishing simulation.",
        landing_page_teaching_points=[
            "Generic \"a document was shared\" emails with no sender name or file name are "
            "a common phishing pattern.",
            "Check whether you were actually expecting a shared file from anyone before "
            "clicking.",
            "If a \"sign in to view\" page appears after clicking, stop — legitimate file "
            "shares from your own organization's tools rarely require re-entering your "
            "password from an email link.",
        ],
        has_fake_login_form=True,
    ),
}
