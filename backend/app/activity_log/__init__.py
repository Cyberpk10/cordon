"""Pasted raw activity-log analyzer (demo-facing) — parses a CSV of login/activity events
into the existing ActivityEvent model and runs it through the existing intrusion-detection
engine (app.detections / app.api.routes.events.ingest_activity_events), so a user can paste
a raw log and get the same verdict/narrative plumbing the email analyzer already provides.
No new detection logic lives here; see app.activity_log.parser for the input mapping.
"""
