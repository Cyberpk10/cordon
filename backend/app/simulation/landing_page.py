"""Renders the safe, Cordon-hosted phishing-simulation landing page (M9 Stage 1) — plain
Python string building, no templating engine, matching this codebase's existing convention of
building output documents directly in Python (e.g. app.audit.report_builder uses reportlab
directly; nothing renders server-side HTML via a templating engine anywhere in this repo).

CRITICAL: this module never accepts or interpolates anything a trainee typed into the fake
login form — the route that calls this (app.api.routes.simulation.track) never reads a request
body at all, so there is nothing credential-shaped for this module to ever receive. All
interpolated values here come from the fixed, developer-authored template catalog
(app.simulation.templates), not from the recipient, but every interpolation still runs through
html.escape() defensively.
"""

from __future__ import annotations

from html import escape

from app.simulation.templates import SimulationTemplate

_PAGE_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #0f172a; color: #e2e8f0; margin: 0; padding: 0; }}
  .card {{ max-width: 560px; margin: 10vh auto; background: #1e293b; border-radius: 16px;
           padding: 40px; box-shadow: 0 20px 60px rgba(0,0,0,0.4); }}
  h1 {{ color: #ffffff; font-size: 1.5rem; margin-top: 0; }}
  ul {{ line-height: 1.7; }}
  .badge {{ display: inline-block; background: #2f6bff; color: white; font-size: 0.75rem;
            font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
            padding: 4px 12px; border-radius: 999px; margin-bottom: 16px; }}
  form {{ margin-top: 24px; padding: 20px; background: #0f172a; border-radius: 12px; }}
  input {{ display: block; width: 100%; box-sizing: border-box; margin-bottom: 12px;
           padding: 10px; border-radius: 8px; border: 1px solid #334155;
           background: #1e293b; color: #e2e8f0; }}
  button {{ background: #2f6bff; color: white; border: none; padding: 10px 20px;
            border-radius: 8px; font-weight: 600; cursor: pointer; }}
  .note {{ font-size: 0.85rem; color: #94a3b8; margin-top: 16px; }}
</style>
</head>
<body>
<div class="card">
{body}
</div>
</body>
</html>
"""


def render_teaching_page(
    template: SimulationTemplate, *, show_fake_form: bool, already_submitted: bool
) -> str:
    headline = escape(template.landing_page_headline)
    points = "".join(f"<li>{escape(point)}</li>" for point in template.landing_page_teaching_points)

    if already_submitted:
        body = (
            f'<span class="badge">Simulation</span>'
            f"<h1>{headline}</h1>"
            "<p>Nothing you typed was recorded — this page never collects real credentials. "
            "We logged that this form was submitted so your organization can measure and "
            "improve its security-awareness training.</p>"
            f"<ul>{points}</ul>"
        )
    else:
        form_html = ""
        if show_fake_form:
            form_html = (
                '<form id="cordon-sim-form" onsubmit="return cordonSimSubmit(event)">'
                '<input type="text" placeholder="Username" autocomplete="off">'
                '<input type="password" placeholder="Password" autocomplete="off">'
                '<button type="submit">Sign in</button>'
                "</form>"
                "<script>"
                "function cordonSimSubmit(event) {"
                "  event.preventDefault();"
                "  var url = new URL(window.location.href);"
                "  url.searchParams.set('event', 'submit');"
                "  window.location.href = url.toString();"
                "  return false;"
                "}"
                "</script>"
            )
        body = (
            f'<span class="badge">Simulation</span>'
            f"<h1>{headline}</h1>"
            "<p>You just clicked a link in a simulated phishing email sent by your own "
            "organization for security-awareness training. No real threat was involved.</p>"
            f"<ul>{points}</ul>"
            f"{form_html}"
            '<p class="note">Nothing typed into the form above is ever transmitted or stored '
            "— it only records that the form was submitted.</p>"
        )

    return _PAGE_SHELL.format(title="Security awareness simulation", body=body)


def render_invalid_link_page() -> str:
    body = (
        "<h1>This link is no longer valid</h1>"
        "<p>This simulation link has expired or does not exist. If you believe this is an "
        "error, contact your security team.</p>"
    )
    return _PAGE_SHELL.format(title="Link not found", body=body)
