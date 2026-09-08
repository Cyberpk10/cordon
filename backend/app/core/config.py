"""Application configuration."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Loads variables from a local .env file (if present) into os.environ. Real
# environment variables already set (shell, CI) always take precedence —
# load_dotenv() defaults to override=False. .env itself is gitignored; see
# .env.example for the documented set of variables.
load_dotenv()

_TRUTHY = {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


def _normalize_database_url(url: str) -> str:
    """Managed Postgres providers (Render, Heroku, ...) hand back a bare `postgres://` or
    `postgresql://` connection string, which implies SQLAlchemy's legacy default driver
    (psycopg2). This app depends on psycopg (v3, via `psycopg[binary]`) instead — without
    this rewrite, `create_engine()` tries to import psycopg2 (not installed) and crashes
    immediately at process startup, before the app or Alembic ever run."""
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


@dataclass
class Settings:
    # M8 Stage 1 (production hosting). "development" locally by default; Render sets this to
    # "production", which gates HTTPS enforcement in app.main.
    environment: str = field(default_factory=lambda: os.environ.get("ENVIRONMENT", "development"))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))

    # Comma-separated allowed CORS origins, e.g. the deployed Vercel URL in production. Falls
    # back to the local Vite dev server origins when unset, so local dev is unaffected.
    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
        ]
        or ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MiB
    # Security review (M8 Stage 4): a hard ceiling on ANY request body, enforced from the
    # declared Content-Length before Starlette/FastAPI reads a single byte of it (see
    # app.main's MaxBodySizeMiddleware) — every route below this already re-checks its own,
    # tighter limit (e.g. max_upload_bytes) AFTER reading the body, which is too late to stop
    # an oversized request from being fully buffered/spooled first. Generous headroom over
    # max_upload_bytes for multipart/JSON framing overhead, not meant to be tuned per-route.
    max_request_body_bytes: int = 20 * 1024 * 1024  # 20 MiB

    # LLM reasoning layer (M2): off by default so the app and test suite stay
    # fully offline and deterministic unless explicitly opted in.
    enable_llm_reasoning: bool = field(
        default_factory=lambda: _env_bool("ENABLE_LLM_REASONING", False)
    )
    llm_model: str = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5")
    )

    # Persistence (M3/Stage 2). SQLite by default so the app and test suite run with zero
    # setup; point DATABASE_URL at the docker-compose Postgres for a real deployment.
    database_url: str = field(
        default_factory=lambda: _normalize_database_url(
            os.environ.get("DATABASE_URL", "sqlite:///./aegis.db")
        )
    )
    # Raw .eml files are stored on disk (never in the DB) and purged after this many days —
    # only a path pointer lives in the `cases` table.
    raw_email_storage_dir: str = field(
        default_factory=lambda: os.environ.get("RAW_EMAIL_STORAGE_DIR", "./data/raw_emails")
    )
    raw_email_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("RAW_EMAIL_RETENTION_DAYS", "30"))
    )

    # Audit Mode (M4 Stage 1). Generated evidence-pack PDF/JSON files live here — under
    # backend/data/ by default, already covered by .gitignore.
    audit_report_storage_dir: str = field(
        default_factory=lambda: os.environ.get("AUDIT_REPORT_STORAGE_DIR", "./data/audit_reports")
    )

    # Closed-loop remediation + targeted training (M4 Stage 3). A recipient hit by this
    # many non-safe cases gets flagged for a stored micro-training recommendation.
    target_training_threshold: int = field(
        default_factory=lambda: int(os.environ.get("TARGET_TRAINING_THRESHOLD", "3"))
    )

    # Natural-language threat copilot (M4 Stage 4). Off by default — separate from
    # enable_llm_reasoning since this is a broader, cross-case data-access surface than
    # the single-email analyst narrative, and a deployer should opt into it independently.
    enable_copilot: bool = field(default_factory=lambda: _env_bool("ENABLE_COPILOT", False))

    # Intrusion & data-exfiltration detection (M5 Stage 1). How far back from an actor's
    # latest event in an ingest batch the detection engine looks for correlated activity
    # (brute force, mass access, etc). Anchored to event timestamps, not wall-clock.
    intrusion_lookback_hours: int = field(
        default_factory=lambda: int(os.environ.get("INTRUSION_LOOKBACK_HOURS", "24"))
    )
    # Static business-hours window (UTC, 24h clock) for the off-hours-access detector.
    business_hours_start: int = field(
        default_factory=lambda: int(os.environ.get("BUSINESS_HOURS_START", "8"))
    )
    business_hours_end: int = field(
        default_factory=lambda: int(os.environ.get("BUSINESS_HOURS_END", "18"))
    )
    # Data-exfiltration thresholds: a single transfer/download over this many bytes to a
    # non-allowlisted destination, or a single db_query export over this many bytes, fires.
    exfil_large_transfer_bytes: int = field(
        default_factory=lambda: int(os.environ.get("EXFIL_LARGE_TRANSFER_BYTES", str(500_000_000)))
    )
    exfil_large_db_export_bytes: int = field(
        default_factory=lambda: int(
            os.environ.get("EXFIL_LARGE_DB_EXPORT_BYTES", str(200_000_000))
        )
    )
    # Comma-separated list of transfer/download targets considered "known" destinations
    # (never flagged as exfiltration regardless of size). Empty by default — everything is
    # "unfamiliar" until a deployer allowlists their own known-good destinations.
    exfil_allowlisted_destinations: list[str] = field(
        default_factory=lambda: [
            d.strip()
            for d in os.environ.get("EXFIL_ALLOWLISTED_DESTINATIONS", "").split(",")
            if d.strip()
        ]
    )

    # Cross-actor / coordinated-campaign correlation (Stage 1 detection hardening). See
    # app.detections.cross_actor. Distinct from brute_force's own per-actor sub-window —
    # this counts distinct ACTORS sharing a source-IP /24 subnet, not one actor's own
    # failures.
    cross_actor_spray_window_minutes: int = field(
        default_factory=lambda: int(os.environ.get("CROSS_ACTOR_SPRAY_WINDOW_MINUTES", "15"))
    )
    # Minimum distinct actors failing auth from the same /24 subnet within the window above
    # before this is treated as a spray rather than a handful of ordinary users mistyping a
    # password from a shared office/VPN NAT IP.
    cross_actor_spray_min_actors: int = field(
        default_factory=lambda: int(os.environ.get("CROSS_ACTOR_SPRAY_MIN_ACTORS", "8"))
    )
    # Minimum number of independently non-safe actors, correlated via a shared source-IP /24
    # subnet drawn only from each actor's own triggering evidence events (never their
    # incidental/benign traffic), within the same ingestion batch, before their individual
    # incidents are merged into one coordinated-attack incident.
    coordinated_attack_min_actors: int = field(
        default_factory=lambda: int(os.environ.get("COORDINATED_ATTACK_MIN_ACTORS", "3"))
    )

    # Cumulative-volume exfiltration (Stage 1 detection hardening). Rolling window,
    # meaningfully longer than intrusion_lookback_hours (24h), that a "low and slow" exfil
    # spread across many small transfers/downloads would otherwise evade entirely (each
    # daily ingest batch's 24h window never overlaps the previous day's).
    exfil_cumulative_window_days: int = field(
        default_factory=lambda: int(os.environ.get("EXFIL_CUMULATIVE_WINDOW_DAYS", "7"))
    )
    # Total data_transfer/file_download bytes to non-allowlisted destinations within the
    # rolling window above before this fires — well under exfil_large_transfer_bytes (500MB)
    # since the whole point is catching volume that never crosses that single-event bar.
    exfil_cumulative_volume_bytes: int = field(
        default_factory=lambda: int(
            os.environ.get("EXFIL_CUMULATIVE_VOLUME_BYTES", str(250_000_000))
        )
    )
    # Requires at least this many qualifying transfers before firing — a single moderately
    # large (but sub-500MB) transfer isn't "low and slow structuring," it's just one
    # transfer; DATA_EXFIL_LARGE_TRANSFER already covers genuinely large single events.
    exfil_cumulative_min_transfers: int = field(
        default_factory=lambda: int(os.environ.get("EXFIL_CUMULATIVE_MIN_TRANSFERS", "2"))
    )

    # Detection max-out Stage C — multi-window cumulative exfiltration
    # (app.detections.cumulative_exfiltration). The settings above (7 days / 250MB) are the
    # "short" tier, unchanged. These add two longer tiers evaluated at the same time so
    # pacing transfers beyond the short window's reach (e.g. every 12 days) still gets
    # caught once enough of them accumulate over a month or a quarter — exfil_cumulative_
    # min_transfers is shared across all three tiers (window length differentiates
    # strictness, not transfer count).
    exfil_cumulative_window_days_medium: int = field(
        default_factory=lambda: int(os.environ.get("EXFIL_CUMULATIVE_WINDOW_DAYS_MEDIUM", "30"))
    )
    exfil_cumulative_volume_bytes_medium: int = field(
        default_factory=lambda: int(
            os.environ.get("EXFIL_CUMULATIVE_VOLUME_BYTES_MEDIUM", str(600_000_000))
        )
    )
    exfil_cumulative_window_days_long: int = field(
        default_factory=lambda: int(os.environ.get("EXFIL_CUMULATIVE_WINDOW_DAYS_LONG", "90"))
    )
    exfil_cumulative_volume_bytes_long: int = field(
        default_factory=lambda: int(
            os.environ.get("EXFIL_CUMULATIVE_VOLUME_BYTES_LONG", str(1_000_000_000))
        )
    )
    # Ratio weighting: heavy but mostly-legitimate data movement (most of it to allowlisted
    # destinations) shouldn't score at full strength just because a wide window is large
    # enough to also see a smaller non-allowlisted side-channel. Weight reaches 1.0 once
    # non-allowlisted transfers make up at least this share of the actor's total transfer
    # volume in the firing window...
    exfil_cumulative_ratio_full_weight_at: float = field(
        default_factory=lambda: float(
            os.environ.get("EXFIL_CUMULATIVE_RATIO_FULL_WEIGHT_AT", "0.5")
        )
    )
    # ...and never drops below this floor — a low-ratio actor still surfaces the finding at
    # reduced confidence, rather than being suppressed outright.
    exfil_cumulative_ratio_min_weight: float = field(
        default_factory=lambda: float(os.environ.get("EXFIL_CUMULATIVE_RATIO_MIN_WEIGHT", "0.4"))
    )

    # Per-account sender-history-aware phishing detection (M8 Stage 3a). How far back
    # app.sender_history.loader looks at an account's own past Case rows to build its
    # correspondence-history snapshot.
    sender_history_lookback_days: int = field(
        default_factory=lambda: int(os.environ.get("SENDER_HISTORY_LOOKBACK_DAYS", "180"))
    )
    # A domain must appear in at least this many past cases...
    sender_history_established_min_occurrences: int = field(
        default_factory=lambda: int(
            os.environ.get("SENDER_HISTORY_ESTABLISHED_MIN_OCCURRENCES", "3")
        )
    )
    # ...spanning at least this many real days (not all in one burst) before it counts as
    # ESTABLISHED — the comparison basis for LOOKALIKE_OF_KNOWN_SENDER. Guards against a
    # single prior email (possibly the attacker's own reconnaissance message) seeding a
    # trusted baseline for a later look-alike attack against itself.
    sender_history_established_min_span_days: int = field(
        default_factory=lambda: int(
            os.environ.get("SENDER_HISTORY_ESTABLISHED_MIN_SPAN_DAYS", "1")
        )
    )

    # Known-bad-URL cross-reference against a static PhishTank hostname snapshot (M8 Stage
    # 3a) — see app.indicators.known_bad_urls. Zero-network, on by default like every other
    # purely-offline indicator (LINK_SUSPICIOUS_TLD, lookalike_domain, ...).
    enable_known_bad_url_list: bool = field(
        default_factory=lambda: _env_bool("ENABLE_KNOWN_BAD_URL_LIST", True)
    )

    # Newly-registered-domain heuristic proxy (M8 Stage 3a) — a zero-network domain-entropy
    # signal, NOT a real WHOIS/RDAP registration-age check (that would require a live
    # outbound call the analyzer deliberately never makes). See
    # app.indicators.domain_age_heuristic.
    enable_newly_registered_domain_heuristic: bool = field(
        default_factory=lambda: _env_bool("ENABLE_NEWLY_REGISTERED_DOMAIN_HEURISTIC", True)
    )
    newly_registered_domain_entropy_threshold: float = field(
        default_factory=lambda: float(
            os.environ.get("NEWLY_REGISTERED_DOMAIN_ENTROPY_THRESHOLD", "3.0")
        )
    )

    # Behavioral baselines / UEBA (M5 Stage 2). Cold-start gates: an actor's baseline isn't
    # trusted over the Stage 1 static thresholds until it has this much history.
    baseline_min_events_for_hours: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_EVENTS_FOR_HOURS", "5"))
    )
    # An hour-of-day must have been seen at least this many times to count as "typical".
    baseline_min_hour_occurrences: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_HOUR_OCCURRENCES", "2"))
    )
    baseline_min_events_for_location: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_EVENTS_FOR_LOCATION", "5"))
    )
    # Minimum days of daily_volume history before the volume baseline is trusted over the
    # Stage 1 static count/distinct-target thresholds.
    baseline_min_days_for_volume: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_DAYS_FOR_VOLUME", "5"))
    )
    # A day's file-access volume fires if it exceeds mean + this-many-stddevs of the actor's
    # rolling daily_volume history.
    baseline_volume_stddev_multiplier: float = field(
        default_factory=lambda: float(os.environ.get("BASELINE_VOLUME_STDDEV_MULTIPLIER", "3.0"))
    )
    # Rolling window size (days) for daily_volume — oldest days are dropped as new ones are
    # added, so the baseline can adapt if an actor's normal workload genuinely changes.
    baseline_daily_volume_window_days: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_DAILY_VOLUME_WINDOW_DAYS", "30"))
    )

    # Detection max-out Stage B — resource-sensitivity tagging (app.baselines.
    # resource_sensitivity). Comma-separated path prefixes (case-insensitive) per class;
    # a target matching any prefix in a class counts as that class for baseline/detection
    # purposes. Empty by default would mean nothing is ever sensitive — each has a sensible
    # default matching this codebase's own event-fixture convention (finance/, hr/, legal/
    # top-level folders).
    sensitive_resource_prefixes_finance: list[str] = field(
        default_factory=lambda: [
            p.strip().lower()
            for p in os.environ.get("SENSITIVE_RESOURCE_PREFIXES_FINANCE", "finance/").split(",")
            if p.strip()
        ]
    )
    sensitive_resource_prefixes_hr: list[str] = field(
        default_factory=lambda: [
            p.strip().lower()
            for p in os.environ.get("SENSITIVE_RESOURCE_PREFIXES_HR", "hr/").split(",")
            if p.strip()
        ]
    )
    sensitive_resource_prefixes_legal: list[str] = field(
        default_factory=lambda: [
            p.strip().lower()
            for p in os.environ.get("SENSITIVE_RESOURCE_PREFIXES_LEGAL", "legal/").split(",")
            if p.strip()
        ]
    )

    # Detection max-out Stage B — first-time sensitive-class access
    # (app.detections.sensitive_resource_access). Cold-start gate: an actor's baseline isn't
    # trusted to say "this class is new for them" until it has this much history — otherwise
    # a brand-new actor's very first activity (which is trivially "new" in every class) would
    # flag constantly.
    baseline_min_events_for_resource_class: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_EVENTS_FOR_RESOURCE_CLASS", "5"))
    )

    # Detection max-out Stage B — anti-poisoning ramp detection (app.baselines.aggregation.
    # evaluate_ramp_anomaly, app.detections.baseline_ramp). Closes the gap where a gradual,
    # multi-week increase never crosses the single-day mean+stddev check because the TREND
    # itself, not any one day, is the anomaly.
    baseline_min_days_for_ramp: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_MIN_DAYS_FOR_RAMP", "10"))
    )
    # Raw daily-volume ramp fires if the recent half of the window's mean is at least this
    # many times the early half's mean. Weighted low on its own (see baseline_ramp.py) since
    # organic volume growth is common and often benign.
    baseline_ramp_ratio_threshold: float = field(
        default_factory=lambda: float(os.environ.get("BASELINE_RAMP_RATIO_THRESHOLD", "1.5"))
    )
    # Sensitive-access-ratio ramp fires if the recent half's mean sensitive-share is at least
    # this many percentage points (0-1 scale) above the early half's. Weighted higher than the
    # raw-volume ramp — a rising SHARE of sensitive touches specifically is rare and sharply
    # suspicious, unlike raw volume alone.
    baseline_ramp_sensitive_ratio_increase_threshold: float = field(
        default_factory=lambda: float(
            os.environ.get("BASELINE_RAMP_SENSITIVE_RATIO_INCREASE_THRESHOLD", "0.15")
        )
    )
    # Long-term anchor window (days) — deliberately much longer than
    # baseline_daily_volume_window_days (30) so a ramp patient enough to outlast the recent
    # rolling window still has an older, harder-to-poison reference point to be compared
    # against (see app.baselines.aggregation's long_term_daily_volume/
    # long_term_daily_sensitive_count fields).
    baseline_long_term_window_days: int = field(
        default_factory=lambda: int(os.environ.get("BASELINE_LONG_TERM_WINDOW_DAYS", "180"))
    )
    # Minimum days of long-term history OLDER than the current recent window before the
    # long-term anchor is trusted — this is what makes it poison-resistant: only history the
    # recent window has already rolled past counts toward this gate.
    baseline_min_days_for_long_term_anchor: int = field(
        default_factory=lambda: int(
            os.environ.get("BASELINE_MIN_DAYS_FOR_LONG_TERM_ANCHOR", "20")
        )
    )

    # Detection max-out Stage D — long-dwell / low-signal correlation (app.baselines.
    # aggregation.project_suspicious_pattern_score, app.detections.low_signal_accumulation).
    # Half-life (days) for the decayed per-actor "suspicious pattern" score — chosen after
    # numeric calibration (see the Stage D plan) so a genuine multi-category attacker
    # pacing every ~12 days clears the chronic threshold with room, while even a rare
    # (~60-day) benign co-occurrence stays far under it.
    low_signal_half_life_days: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_HALF_LIFE_DAYS", "45.0"))
    )
    # Per-category point values for one batch. Each category is only counted when it is
    # structurally incapable of ALSO satisfying an existing detector's own firing condition
    # (see low_signal_accumulation's module docstring) — these are not "below threshold by
    # coincidence," they're a disjoint, deliberately-weak residue.
    low_signal_points_auth_fail: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_POINTS_AUTH_FAIL", "3.0"))
    )
    low_signal_points_transfer: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_POINTS_TRANSFER", "3.0"))
    )
    low_signal_points_sensitive: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_POINTS_SENSITIVE", "5.0"))
    )
    low_signal_points_hour: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_POINTS_HOUR", "2.0"))
    )
    # Cap on how much a single batch can add to the chronic score, even if every category
    # fires at once — bounds how fast one unusually noisy batch can move the needle.
    low_signal_batch_cap: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_BATCH_CAP", "12.0"))
    )
    # Absolute ceiling on the persisted decayed score — prevents unbounded growth from a
    # pathological run of back-to-back multi-category batches.
    low_signal_score_cap: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_SCORE_CAP", "100.0"))
    )
    # LOW_SIGNAL_PATTERN_ACCUMULATION fires once the projected decayed score crosses this.
    low_signal_chronic_threshold: float = field(
        default_factory=lambda: float(os.environ.get("LOW_SIGNAL_CHRONIC_THRESHOLD", "40.0"))
    )
    # A batch's auth_fail count counts as the weak "auth" category only up to this many —
    # strictly below brute_force's 5-event burst floor, so the same events can never trip
    # both.
    low_signal_auth_fail_ceiling: int = field(
        default_factory=lambda: int(os.environ.get("LOW_SIGNAL_AUTH_FAIL_CEILING", "4"))
    )
    # Minimum overall baseline event_count before an atypical hour counts as a weak "hour"
    # signal — without this gate, a brand-new baseline (every hour still atypical) would
    # flag constantly.
    low_signal_min_events_for_hour_check: int = field(
        default_factory=lambda: int(os.environ.get("LOW_SIGNAL_MIN_EVENTS_FOR_HOUR_CHECK", "20"))
    )

    # Early-warning sensor Stage 1 — per-actor Threat Level (app.threat_level.aggregation,
    # app.threat_level.hooks). A live, decayed 0-100 score fed by precursor signals from both
    # the email and events pipelines, deliberately faster-reacting than Stage D's 90-day
    # chronic horizon (see the Stage 1 plan for the half-life/chain-window calibration).
    threat_level_half_life_days: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_HALF_LIFE_DAYS", "14.0"))
    )
    # Multiplier applied to a NEW signal's points when the actor already has a signal at an
    # EARLIER kill-chain stage within threat_level_chain_window_days — this is what makes a
    # forming chain (delivery -> access -> collection -> exfiltration) escalate faster than
    # either signal alone. Strictly forward-progressing: a repeat of the same or an earlier
    # stage never gets this bonus.
    threat_level_chain_multiplier: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_CHAIN_MULTIPLIER", "1.8"))
    )
    threat_level_chain_window_days: int = field(
        default_factory=lambda: int(os.environ.get("THREAT_LEVEL_CHAIN_WINDOW_DAYS", "21"))
    )
    # Bounds recent_signals — same bounded-state discipline as every other per-actor JSON
    # field in this codebase.
    threat_level_signal_history_cap: int = field(
        default_factory=lambda: int(os.environ.get("THREAT_LEVEL_SIGNAL_HISTORY_CAP", "20"))
    )
    # How far back in score_history "trend" looks for its comparison point.
    threat_level_trend_window_days: int = field(
        default_factory=lambda: int(os.environ.get("THREAT_LEVEL_TREND_WINDOW_DAYS", "7"))
    )
    # Level bands — deliberately separate from Verdict's SAFE/SUSPICIOUS/MALICIOUS naming to
    # avoid confusing a watchlist tier with an actual case/incident verdict.
    threat_level_elevated_at: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_ELEVATED_AT", "25.0"))
    )
    threat_level_high_at: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_HIGH_AT", "50.0"))
    )
    threat_level_critical_at: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_CRITICAL_AT", "75.0"))
    )
    # Base points per precursor signal type — see the Stage 1 plan's signal catalog for the
    # numeric calibration behind each value.
    threat_level_points_phishing_received_suspicious: float = field(
        default_factory=lambda: float(
            os.environ.get("THREAT_LEVEL_POINTS_PHISHING_RECEIVED_SUSPICIOUS", "10.0")
        )
    )
    threat_level_points_phishing_received_malicious: float = field(
        default_factory=lambda: float(
            os.environ.get("THREAT_LEVEL_POINTS_PHISHING_RECEIVED_MALICIOUS", "18.0")
        )
    )
    threat_level_points_simulation_clicked: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_POINTS_SIMULATION_CLICKED", "12.0"))
    )
    threat_level_points_auth_anomaly: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_POINTS_AUTH_ANOMALY", "8.0"))
    )
    threat_level_points_sensitive_access_cold_start: float = field(
        default_factory=lambda: float(
            os.environ.get("THREAT_LEVEL_POINTS_SENSITIVE_ACCESS_COLD_START", "10.0")
        )
    )
    # Damping factor applied to the REAL SENSITIVE_RESOURCE_FIRST_ACCESS finding's own points
    # when it fires (mature baseline) — the same signal meaning as the cold-start weak
    # version above, just observed later, so it shouldn't dominate the sensor on its own.
    threat_level_finding_weight: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_FINDING_WEIGHT", "0.3"))
    )
    threat_level_points_small_transfer: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_POINTS_SMALL_TRANSFER", "8.0"))
    )
    threat_level_points_accumulator_signal: float = field(
        default_factory=lambda: float(os.environ.get("THREAT_LEVEL_POINTS_ACCUMULATOR_SIGNAL", "15.0"))
    )
    # New-location auth-anomaly check (app.threat_level.hooks) — gated on the baseline having
    # at least this many events so a brand-new actor's very first login isn't flagged as
    # "new location" (everything is new for a cold-start baseline).
    threat_level_min_events_for_location_check: int = field(
        default_factory=lambda: int(os.environ.get("THREAT_LEVEL_MIN_EVENTS_FOR_LOCATION_CHECK", "10"))
    )

    # Continuous Control Monitoring (M7 Stage A). How far back evidence queries look when
    # computing per-control freshness and drift.
    monitoring_lookback_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_LOOKBACK_DAYS", "180"))
    )
    # A control is "operating" if its most recent evidence is within this many days,
    # unless overridden per-control (see control_monitor.CONTROL_INTERVAL_OVERRIDES_DAYS).
    monitoring_default_interval_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_DEFAULT_INTERVAL_DAYS", "14"))
    )
    # Multiplied against a control's expected interval to get the degraded/stale boundary.
    monitoring_stale_multiplier: float = field(
        default_factory=lambda: float(os.environ.get("MONITORING_STALE_MULTIPLIER", "3.0"))
    )
    # Window size (days) for the two adjacent SPF/DKIM/DMARC pass-rate comparison periods.
    monitoring_auth_window_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_AUTH_WINDOW_DAYS", "14"))
    )
    # Minimum cases required in BOTH windows before an auth-pass-rate-drop alert can fire —
    # guards against a handful of emails manufacturing a false drift signal.
    monitoring_auth_min_sample: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_AUTH_MIN_SAMPLE", "5"))
    )
    # Minimum pass-rate drop (fraction, e.g. 0.15 = 15 points) between windows to alert.
    monitoring_auth_drop_threshold: float = field(
        default_factory=lambda: float(os.environ.get("MONITORING_AUTH_DROP_THRESHOLD", "0.15"))
    )
    # How far back the "prior" framework-coverage snapshot is taken from, for comparison
    # against the current one.
    monitoring_coverage_comparison_days: int = field(
        default_factory=lambda: int(os.environ.get("MONITORING_COVERAGE_COMPARISON_DAYS", "30"))
    )
    # Minimum operating-coverage drop (fraction) between snapshots to alert.
    monitoring_coverage_drop_threshold: float = field(
        default_factory=lambda: float(os.environ.get("MONITORING_COVERAGE_DROP_THRESHOLD", "0.10"))
    )

    # Multi-channel detection (M7 Stage B). Display names considered protected against
    # impersonation by an external chat sender — comma-separated, empty by default (same
    # sensible-default-list pattern as exfil_allowlisted_destinations/autonomy exclusions).
    chat_protected_display_names: list[str] = field(
        default_factory=lambda: [
            n.strip()
            for n in os.environ.get("CHAT_PROTECTED_DISPLAY_NAMES", "").split(",")
            if n.strip()
        ]
    )
    # Live Slack/Teams ingestion is not implemented yet (see app.channels.slack_client /
    # teams_client) — these flags exist as the seam for when it is, off by default.
    enable_live_slack_ingestion: bool = field(
        default_factory=lambda: _env_bool("ENABLE_LIVE_SLACK_INGESTION", False)
    )
    enable_live_teams_ingestion: bool = field(
        default_factory=lambda: _env_bool("ENABLE_LIVE_TEAMS_INGESTION", False)
    )

    # Authentication (M8 Stage 2). No safe default for production — if JWT_SECRET_KEY isn't
    # set, a random value is generated per-process so local dev still works, but every
    # restart invalidates every existing session. Render MUST have this set explicitly.
    jwt_secret_key: str = field(
        default_factory=lambda: os.environ.get("JWT_SECRET_KEY") or secrets.token_urlsafe(64)
    )
    jwt_access_token_ttl_minutes: int = field(
        default_factory=lambda: int(os.environ.get("JWT_ACCESS_TOKEN_TTL_MINUTES", "15"))
    )
    jwt_refresh_token_ttl_days: int = field(
        default_factory=lambda: int(os.environ.get("JWT_REFRESH_TOKEN_TTL_DAYS", "7"))
    )

    # Email forwarding intake (M8 Stage 3). No safe default for the signing key — an unset
    # value means the webhook hard-rejects everything (see app.api.routes.inbound) rather
    # than silently accepting unsigned requests. Get this from Mailgun's Sending -> Webhooks
    # page (a different value from the API key).
    #
    # TODO(deploy): the code path is fully built and tested, but inert in production until a
    # real domain is registered and pointed at Mailgun. Once you have one:
    #   1. Mailgun -> Sending -> Domains -> add a receiving subdomain (e.g. in.yourdomain.com),
    #      add the MX records it gives you at your DNS provider.
    #   2. Mailgun -> Receiving -> Routes -> create one route:
    #      match_recipient("^pilot-[a-z0-9]+@in\.yourdomain\.com$")
    #      -> forward("https://<backend>.onrender.com/api/inbound/email/mime")
    #   3. Set MAILGUN_WEBHOOK_SIGNING_KEY (Sending -> Webhooks) and INBOUND_EMAIL_DOMAIN on
    #      Render, redeploy. Full walkthrough: DEPLOYMENT.md section 8.
    mailgun_webhook_signing_key: str = field(
        default_factory=lambda: os.environ.get("MAILGUN_WEBHOOK_SIGNING_KEY", "")
    )
    # The domain forwarding addresses are shown as (pilot-<token>@<this>) — must match the
    # domain the Mailgun receiving route is actually configured on. See DEPLOYMENT.md.
    inbound_email_domain: str = field(
        default_factory=lambda: os.environ.get("INBOUND_EMAIL_DOMAIN", "in.aegis.example.com")
    )
    # Replay-attack defense in depth — Mailgun's own HMAC signature never expires on its own,
    # so a captured payload could otherwise be replayed indefinitely.
    inbound_email_signature_max_age_seconds: int = field(
        default_factory=lambda: int(os.environ.get("INBOUND_EMAIL_SIGNATURE_MAX_AGE_SECONDS", "900"))
    )
    # Per-account cap on inbound-forwarded emails per hour — a provider's webhook traffic all
    # comes from a small set of source IPs, so per-IP rate limiting (as used on /api/auth/*)
    # doesn't actually throttle per-tenant abuse here; this does.
    inbound_email_rate_limit_per_account_per_hour: int = field(
        default_factory=lambda: int(
            os.environ.get("INBOUND_EMAIL_RATE_LIMIT_PER_ACCOUNT_PER_HOUR", "30")
        )
    )

    # Real Microsoft Graph autonomous-response connector (M6 Stage 2). A single Azure AD app
    # registration shared across every account (multi-tenant; each customer's admin consents
    # it into their own tenant) — these two are the only Graph secrets that exist, and there's
    # exactly one of each, not one per account. Either unset means every account falls back to
    # MockConnector (see app.autonomy.connector_factory) — no real action ever fires
    # unconfigured. See DEPLOYMENT.md for the full Azure app registration walkthrough.
    microsoft_graph_client_id: str = field(
        default_factory=lambda: os.environ.get("MICROSOFT_GRAPH_CLIENT_ID", "")
    )
    microsoft_graph_client_secret: str = field(
        default_factory=lambda: os.environ.get("MICROSOFT_GRAPH_CLIENT_SECRET", "")
    )

    # ML classifier signal (M3). Off by default so the app and test suite stay fully offline
    # and deterministic unless explicitly opted in — same idiom as enable_llm_reasoning. Even
    # when on, app.ml.classifier degrades to (None, None) if the artifact files aren't present.
    enable_ml_classifier: bool = field(
        default_factory=lambda: _env_bool("ENABLE_ML_CLASSIFIER", False)
    )
    # Empty string means "use the default backend/app/ml/artifacts/ location" (see
    # app.ml.classifier) — only needs overriding for a non-standard deployment layout.
    ml_artifacts_dir: str = field(default_factory=lambda: os.environ.get("ML_ARTIFACTS_DIR", ""))

    # Authorized phishing-simulation campaigns (M9 Stage 1). Off by default — same idiom as
    # every other optional feature. Even when on, app.simulation.mailgun_sender degrades to a
    # dry run (no real email sent) unless mailgun_api_key AND simulation_sending_domain are
    # both set, so a campaign can never accidentally email real employees from an
    # unconfigured deployment.
    enable_phishing_simulation: bool = field(
        default_factory=lambda: _env_bool("ENABLE_PHISHING_SIMULATION", False)
    )
    mailgun_api_key: str = field(default_factory=lambda: os.environ.get("MAILGUN_API_KEY", ""))
    mailgun_api_base_url: str = field(
        default_factory=lambda: os.environ.get("MAILGUN_API_BASE_URL", "https://api.mailgun.net/v3")
    )
    mailgun_send_timeout_seconds: float = field(
        default_factory=lambda: float(os.environ.get("MAILGUN_SEND_TIMEOUT_SECONDS", "15"))
    )
    # A domain Cordon itself owns and has registered in Mailgun — simulation email is always
    # sent from here, NEVER from the customer's own domain (that would be spoofing the
    # customer's real senders, not simulating a third-party attacker). Empty means every send
    # degrades to dry-run — see app.simulation.mailgun_sender.
    simulation_sending_domain: str = field(
        default_factory=lambda: os.environ.get("SIMULATION_SENDING_DOMAIN", "")
    )
    # Public base URL recipients' browsers hit for GET /api/sim/track/{token}. Required (checked
    # at send time, not import time) for any non-dry-run send — a misconfigured/blank value
    # would otherwise email a real employee a broken or wrong link.
    simulation_tracking_base_url: str = field(
        default_factory=lambda: os.environ.get("SIMULATION_TRACKING_BASE_URL", "")
    )
    # DNS-over-HTTPS resolver used to check a domain-verification TXT record (see
    # app.simulation.dns_check) — httpx-based like every other network call in this codebase,
    # so it's respx-mockable in tests rather than needing a raw-socket DNS library.
    simulation_dns_over_https_url: str = field(
        default_factory=lambda: os.environ.get(
            "SIMULATION_DNS_OVER_HTTPS_URL", "https://cloudflare-dns.com/dns-query"
        )
    )

    # Human-risk scoring (M9 Stage 2) — how soon after a simulation email was sent a "report
    # this email" click still counts as a fast, high-value catch. See app.human_risk.scoring.
    human_risk_fast_report_window_minutes: int = field(
        default_factory=lambda: int(os.environ.get("HUMAN_RISK_FAST_REPORT_WINDOW_MINUTES", "60"))
    )


settings = Settings()
