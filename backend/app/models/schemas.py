"""Pydantic response/data models shared across the API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.events.schema import ActivityEvent


class AuthResultValue(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class AuthResults(BaseModel):
    spf: AuthResultValue = AuthResultValue.UNKNOWN
    dkim: AuthResultValue = AuthResultValue.UNKNOWN
    dmarc: AuthResultValue = AuthResultValue.UNKNOWN
    raw_header: str | None = None


class LinkInfo(BaseModel):
    display_text: str
    href: str
    href_domain: str | None = None


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str | None = None
    size_bytes: int = 0


class EmailSummary(BaseModel):
    from_display: str | None = None
    from_address: str | None = None
    reply_to_address: str | None = None
    to: list[str] = Field(default_factory=list)
    subject: str | None = None
    date: str | None = None
    auth_results: AuthResults = Field(default_factory=AuthResults)
    link_count: int = 0
    attachment_count: int = 0


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Indicator(BaseModel):
    id: str
    category: str
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    severity: Severity
    score: float


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class FrameworkControlRef(BaseModel):
    indicator_id: str
    control_id: str
    control_name: str
    url: str | None = None


class AnalyzeTextRequest(BaseModel):
    """Raw pasted email content for POST /api/analyze/text — full RFC822/MIME, or just a
    subject+body fragment, or plain unstructured text. Fed through the same parse_eml()/
    run_email_pipeline() as a file upload; missing headers simply degrade to empty fields."""

    raw_text: str


class AnalyzeResponse(BaseModel):
    id: UUID
    created_at: datetime
    verdict: Verdict
    score: int
    summary: EmailSummary
    indicators: list[Indicator]
    framework_mappings: dict[str, list[FrameworkControlRef]]
    analyst_narrative: str | None = None
    analyst_model: str | None = None
    ml_probability: float | None = None
    ml_model_version: str | None = None


class InboundEmailResponse(BaseModel):
    """Response for POST /api/inbound/email/mime (M8 Stage 3) — deliberately lighter than
    AnalyzeResponse: the provider (Mailgun) never reads this body, it only needs a 2xx, and
    the "duplicate" status is a short-circuit before a fresh EmailSummary would ever exist."""

    status: Literal["created", "duplicate", "rejected"]
    case_id: UUID | None = None
    verdict: Verdict | None = None
    score: int | None = None


class ChatMessageSummary(BaseModel):
    """The `summary` shape for a chat (Slack/Teams) analyze response — EmailSummary's
    email-only fields (reply_to_address, auth_results) don't apply here."""

    channel: Literal["slack", "teams"]
    channel_name: str | None = None
    from_display: str | None = None
    from_address: str | None = None
    is_direct_message: bool = False
    link_count: int = 0
    mentions_count: int = 0


class MessageAnalyzeResponse(BaseModel):
    id: UUID
    created_at: datetime
    verdict: Verdict
    score: int
    summary: ChatMessageSummary
    indicators: list[Indicator]
    framework_mappings: dict[str, list[FrameworkControlRef]]


class MessageLinkInput(BaseModel):
    display_text: str
    href: str


class MessageAnalyzeRequest(BaseModel):
    """An already-normalized chat message — the same shape
    app.channels.slack_adapter.normalize_slack_message / teams_adapter.normalize_teams_message
    produce. Source-agnostic: a caller runs the adapter first, then POSTs this."""

    channel: Literal["slack", "teams"]
    channel_name: str | None = None
    from_display: str | None = None
    from_address: str | None = None
    is_direct_message: bool = False
    is_external_sender: bool = False
    text: str
    links: list[MessageLinkInput] = Field(default_factory=list)
    mentions: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None


class CaseSummary(BaseModel):
    """A single row in the paginated case list."""

    id: UUID
    created_at: datetime
    filename: str
    channel: str = "email"
    verdict: Verdict
    score: int
    from_addr: str | None = None
    subject: str | None = None

    model_config = {"from_attributes": True}


class CaseListResponse(BaseModel):
    items: list[CaseSummary]
    total: int
    page: int
    page_size: int


class LabelRequest(BaseModel):
    analyst_verdict: Verdict
    note: str | None = Field(default=None, max_length=5000)


class LabelResponse(BaseModel):
    id: UUID
    case_id: UUID | None = None
    incident_id: UUID | None = None
    analyst_verdict: Verdict
    note: str | None = None
    labeled_by: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CaseDetailResponse(BaseModel):
    """Everything persisted for a case, except the raw-email disk pointer (not exposed
    via the API)."""

    id: UUID
    created_at: datetime
    filename: str
    channel: str = "email"
    verdict: Verdict
    score: int
    from_addr: str | None = None
    subject: str | None = None
    indicators: list[Indicator]
    framework_mappings: dict[str, list[FrameworkControlRef]]
    analyst_narrative: str | None = None
    analyst_model: str | None = None
    ml_probability: float | None = None
    ml_model_version: str | None = None
    latest_label: LabelResponse | None = None

    model_config = {"from_attributes": True}


class PeriodCount(BaseModel):
    """A count for the current period alongside the prior period-of-equal-length, for
    the dashboard's period-over-period deltas."""

    current: int
    previous: int
    delta: int
    delta_pct: float | None = None


class VerdictCounts(BaseModel):
    malicious: PeriodCount
    suspicious: PeriodCount
    safe: PeriodCount


class TopIndicator(BaseModel):
    indicator_id: str
    title: str
    category: str
    severity: Severity
    count: int


class MonthlyThreatCount(BaseModel):
    month: str
    count: int


class FrameworkCoverage(BaseModel):
    framework_key: str
    framework_name: str
    total_controls: int
    covered_controls: int
    coverage_pct: float


class AgreementRate(BaseModel):
    rate_pct: float | None = None
    labeled_count: int
    agreeing_count: int


class KRIs(BaseModel):
    malicious_catch_rate_pct: float | None = None
    false_positive_rate_pct: float | None = None
    mean_unlabeled_backlog_days: float | None = None
    unlabeled_count: int
    labeled_count: int


class DashboardSummaryResponse(BaseModel):
    period_start: datetime
    period_end: datetime
    previous_period_start: datetime
    previous_period_end: datetime
    total_analyzed: PeriodCount
    verdict_counts: VerdictCounts
    analyst_agreement: AgreementRate
    top_indicators: list[TopIndicator]
    monthly_threat_trend: list[MonthlyThreatCount]
    kris: KRIs
    framework_coverage: list[FrameworkCoverage]


class AuditFramework(str, Enum):
    NIST = "nist"
    ISO = "iso"
    SOC2 = "soc2"
    MITRE = "mitre"


class AuditCaseRef(BaseModel):
    id: UUID
    verdict: Verdict
    created_at: datetime


class AuditControlEvidence(BaseModel):
    control_id: str
    control_name: str
    detection_count: int
    sample_cases: list[AuditCaseRef]
    operating: bool
    # M9 Stage 2 — populated only for the small, fixed set of controls in
    # app.human_risk.framework_mapping.HUMAN_RISK_CONTROL_IDS; None for every other control.
    human_risk_evidence: "HumanRiskEvidenceResponse | None" = None


class AuditEvidenceResponse(BaseModel):
    framework_key: str
    framework_name: str
    period_start: datetime
    period_end: datetime
    controls: list[AuditControlEvidence]
    total_controls: int
    operating_controls: int


class AuditReportRequest(BaseModel):
    framework: AuditFramework
    date_from: datetime | None = None
    date_to: datetime | None = None


class AuditReportSummary(BaseModel):
    id: UUID
    created_at: datetime
    framework_key: str
    framework_name: str
    period_start: datetime
    period_end: datetime
    total_controls: int
    operating_controls: int
    total_supporting_cases: int


class AuditReportListResponse(BaseModel):
    items: list[AuditReportSummary]
    total: int
    page: int
    page_size: int


class RemediationStatus(str, Enum):
    RECOMMENDED = "recommended"
    APPROVED = "approved"
    DONE = "done"


class RemediationControlRef(BaseModel):
    framework_key: str
    control_id: str
    control_name: str


class PlaybookStepResponse(BaseModel):
    step_id: str
    title: str
    description: str
    category: str
    related_indicator_ids: list[str]
    control_refs: list[RemediationControlRef]
    status: RemediationStatus
    actor: str | None = None
    note: str | None = None
    acted_at: datetime | None = None


class RemediationPlaybookResponse(BaseModel):
    case_id: UUID
    generated_at: datetime
    steps: list[PlaybookStepResponse]


class RemediationActionRequest(BaseModel):
    status: Literal["approved", "done"]
    note: str | None = None


class RemediationActionResponse(BaseModel):
    id: UUID
    case_id: UUID | None = None
    incident_id: UUID | None = None
    step_id: str
    status: str
    actor: str
    note: str | None = None
    created_at: datetime


class TargetSummaryResponse(BaseModel):
    recipient: str
    hit_count: int
    flagged_for_training: bool
    top_indicator_id: str | None = None
    top_indicator_title: str | None = None
    recommendation: str | None = None
    sample_case_ids: list[UUID]
    first_flagged_at: datetime | None = None


class TargetsListResponse(BaseModel):
    threshold: int
    targets: list[TargetSummaryResponse]


class CopilotQueryRequest(BaseModel):
    # app.copilot.llm truncates to 500 chars before ever building a prompt; capping here
    # too means an oversized question is rejected with a 422 up front rather than fully
    # parsed/validated first and silently truncated later.
    question: str = Field(min_length=1, max_length=2000)


class CopilotTemplateUsed(BaseModel):
    template: str
    params: dict


class CopilotQueryResponse(BaseModel):
    question: str
    narrative: str
    template_used: CopilotTemplateUsed
    result: dict
    generated_at: datetime


class RiskAttackTypeBreakdown(BaseModel):
    attack_type: str
    count: int
    avg_loss_usd: float
    prevention_weight: float
    subtotal_usd: float


class RiskExposureAvoided(BaseModel):
    total_usd: float
    by_attack_type: list[RiskAttackTypeBreakdown]


class RiskResidualRisk(BaseModel):
    total_usd: float
    false_negative_count: int
    by_attack_type: list[RiskAttackTypeBreakdown]
    note: str


class RiskDetectionCounts(BaseModel):
    malicious: int
    suspicious: int
    safe: int


class RiskAssumption(BaseModel):
    value: float
    source: str


class FinancialRiskResponse(BaseModel):
    period_start: datetime
    period_end: datetime
    exposure_avoided: RiskExposureAvoided
    residual_risk: RiskResidualRisk
    detection_counts: RiskDetectionCounts
    assumptions: dict[str, RiskAssumption]
    generated_at: datetime


class Finding(BaseModel):
    """One detection rule firing over a window of activity events (M5 Stage 1) — the
    intrusion-detection analog of Indicator, with `points` instead of `score` and
    references to the actual triggering Event rows instead of free-text evidence."""

    id: str
    category: str
    title: str
    description: str
    severity: Severity
    points: float
    evidence_event_ids: list[UUID] = Field(default_factory=list)
    # Stage 1 cross-actor correlation: which actor this specific finding is about. None for
    # every finding produced by the single-actor engine (app.detections.engine) — those
    # already live inside a single-actor Incident and don't need self-description. Only set
    # (via .model_copy(update={"actor": ...})) when a finding is copied into a merged
    # multi-actor incident's unioned findings list.
    actor: str | None = None


class IncidentSummary(BaseModel):
    id: UUID
    created_at: datetime
    title: str
    actor: str
    verdict: Verdict
    score: int
    detection_types: list[str]
    window_start: datetime
    window_end: datetime
    # Populated only for a merged coordinated-attack or cross-actor-spray incident (Stage 1).
    related_actors: list[str] | None = None

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    items: list[IncidentSummary]
    total: int
    page: int
    page_size: int


class IncidentDetailResponse(BaseModel):
    id: UUID
    created_at: datetime
    title: str
    actor: str
    verdict: Verdict
    score: int
    detection_types: list[str]
    findings: list[Finding]
    framework_mappings: dict[str, list[FrameworkControlRef]]
    window_start: datetime
    window_end: datetime
    evidence_events: list[ActivityEvent]
    latest_label: LabelResponse | None = None
    # Populated only for a merged coordinated-attack or cross-actor-spray incident (Stage 1).
    related_actors: list[str] | None = None


class EventBatchResponse(BaseModel):
    accepted: int
    incidents_created: list[IncidentSummary]


class AutonomyLevel(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class AutonomyPolicyRuleSchema(BaseModel):
    action_type: str
    min_confidence: float
    scopes: list[str] | None = None
    full_auto: bool = False


class AutonomyPolicyRequest(BaseModel):
    level: AutonomyLevel
    rules: list[AutonomyPolicyRuleSchema] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    blast_radius_limit: int = Field(default=10, ge=1)
    blast_radius_window_minutes: int = Field(default=60, ge=1)


class AutonomyPolicyResponse(BaseModel):
    account_id: UUID
    level: AutonomyLevel
    rules: list[AutonomyPolicyRuleSchema]
    exclusions: list[str]
    blast_radius_limit: int
    blast_radius_window_minutes: int
    halted_at: datetime | None = None
    updated_at: datetime


class AutonomyActionResponse(BaseModel):
    id: UUID
    account_id: UUID
    created_at: datetime
    case_id: UUID | None = None
    incident_id: UUID | None = None
    trigger_finding_id: str
    action_type: str
    target: str
    confidence: float
    policy_rule: dict | None = None
    decision: str
    status: str
    result: dict | None = None
    reversible: bool
    mapped_controls: dict[str, list[FrameworkControlRef]]

    model_config = {"from_attributes": True}


class AutonomyActionListResponse(BaseModel):
    items: list[AutonomyActionResponse]
    total: int
    page: int
    page_size: int


class AutonomyHaltResponse(BaseModel):
    account_id: UUID
    level: AutonomyLevel
    halted_at: datetime
    halted_pending_count: int


class GraphIntegrationRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=200)


class GraphIntegrationResponse(BaseModel):
    connected: bool
    tenant_id: str | None = None
    connected_at: datetime | None = None
    is_enabled: bool = False


class ControlHealthResponse(BaseModel):
    framework_key: str
    control_id: str
    control_name: str
    status: str
    last_evidence_at: datetime | None = None
    evidence_count: int
    expected_interval_days: int


class ControlHealthListResponse(BaseModel):
    items: list[ControlHealthResponse]
    total: int


class DriftAlertResponse(BaseModel):
    framework_key: str
    control_id: str
    control_name: str
    type: str
    since: datetime
    severity: str
    detail: str


class DriftAlertListResponse(BaseModel):
    items: list[DriftAlertResponse]
    total: int


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"


class UserResponse(BaseModel):
    id: UUID
    email: str
    role: UserRole
    account_id: UUID
    account_name: str
    # The account's inbound-email forwarding address (M8 Stage 3) — pilot-<token>@<domain>,
    # shown on the frontend onboarding/Settings screen with a copy-to-clipboard button.
    forwarding_address: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None

    model_config = {"from_attributes": True}


class SignupRequest(BaseModel):
    account_name: str = Field(min_length=1, max_length=200)
    email: str
    password: str = Field(min_length=12, max_length=200)


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    user: UserResponse


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class InviteRequest(BaseModel):
    email: str
    role: UserRole = UserRole.ANALYST


class InviteResponse(BaseModel):
    id: UUID
    email: str
    role: UserRole
    expires_at: datetime
    # Stubbed email delivery (M8 Stage 2) — the raw invite link is returned directly rather
    # than emailed; see app.api.routes.auth.
    invite_link: str


class InviteAcceptRequest(BaseModel):
    token: str
    password: str = Field(min_length=12, max_length=200)


class PasswordResetRequestRequest(BaseModel):
    email: str


class PasswordResetRequestResponse(BaseModel):
    message: str
    # Stubbed email delivery (M8 Stage 2), same as InviteResponse — only ever populated when
    # the email actually exists, otherwise the message is a generic no-enumeration response.
    reset_link: str | None = None


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=200)


class UserListResponse(BaseModel):
    items: list[UserResponse]


class UserRoleUpdateRequest(BaseModel):
    role: UserRole


# ---- Phishing simulation (M9 Stage 1) --------------------------------------------------


class SimulationDomainStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"


class DomainVerifyRequest(BaseModel):
    domain: str


class DomainVerifyResponse(BaseModel):
    domain: str
    status: SimulationDomainStatus
    verification_record_name: str
    verification_record_value: str
    verified_at: datetime | None = None
    checked_at: datetime


class SimulationTemplateResponse(BaseModel):
    id: str
    name: str
    category: str
    subject: str
    sender_display_name: str
    landing_page_headline: str
    landing_page_teaching_points: list[str]
    has_fake_login_form: bool


class TemplateListResponse(BaseModel):
    items: list[SimulationTemplateResponse]


class CampaignRecipientInput(BaseModel):
    email: str
    # Free text, admin-supplied (M9 Stage 2) — there is no employee directory in this
    # codebase, so this is whatever the admin types at campaign-creation time. Used for the
    # Human Risk view's department breakdown; see app.db.models.SimulationRecipient.
    department: str | None = None


class CampaignCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    template_id: str
    recipients: list[CampaignRecipientInput] = Field(min_length=1)


class SimulationCampaignStatus(str, Enum):
    DRAFT = "draft"
    AUTHORIZED = "authorized"
    SENDING = "sending"
    SENT = "sent"
    SEND_FAILED = "send_failed"


class SimulationRecipientStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    SEND_FAILED = "send_failed"
    CLICKED = "clicked"
    SUBMITTED = "submitted"


class CampaignRecipientSummary(BaseModel):
    id: UUID
    email: str
    department: str | None
    status: SimulationRecipientStatus
    sent_at: datetime | None
    clicked_at: datetime | None
    click_count: int
    submitted_at: datetime | None
    submit_count: int
    # M9 Stage 2 — independent of `status` (see app.db.models.SimulationRecipient).
    reported_at: datetime | None
    report_count: int
    # Only ever populated when the campaign was sent in dry-run mode (Mailgun unconfigured) —
    # lets a developer/demo user click through the real landing-page flow with no live
    # mailbox. Never populated for a real send, so a live campaign's per-employee tracking
    # links are never exposed back through this read API.
    dry_run_tracking_url: str | None = None


class CampaignDetailResponse(BaseModel):
    id: UUID
    name: str
    template_id: str
    status: SimulationCampaignStatus
    dry_run: bool
    from_address: str | None
    created_at: datetime
    created_by_user_id: UUID | None
    authorized_by_user_id: UUID | None
    authorized_at: datetime | None
    sent_at: datetime | None
    recipients: list[CampaignRecipientSummary]


class CampaignSendRequest(BaseModel):
    # Required, no default — omitting it entirely is a 422 (structurally can't be forgotten
    # by accident); present but false is an explicit 400 (see app.api.routes.simulation).
    authorization_accepted: bool


# ---- Human Risk (M9 Stage 2) ------------------------------------------------------------


class RiskiestUserResponse(BaseModel):
    email: str
    department: str
    risk_score: int
    click_count: int
    submit_count: int
    report_count: int
    last_failure_at: datetime | None


class ClickRatePeriodResponse(BaseModel):
    period_start: datetime
    period_end: datetime
    sent_count: int
    click_count: int
    submit_count: int
    report_count: int
    click_rate: float
    submit_rate: float


class LureEffectivenessResponse(BaseModel):
    template_id: str
    template_name: str
    sent_count: int
    click_count: int
    submit_count: int
    click_rate: float
    submit_rate: float


class DepartmentBreakdownResponse(BaseModel):
    department: str
    employees_tested: int
    click_count: int
    submit_count: int
    report_count: int
    avg_risk_score: float


class HumanRiskSummaryResponse(BaseModel):
    period_start: datetime
    period_end: datetime
    riskiest_users: list[RiskiestUserResponse]
    click_rate_over_time: list[ClickRatePeriodResponse]
    lure_effectiveness: list[LureEffectivenessResponse]
    department_breakdown: list[DepartmentBreakdownResponse]
    generated_at: datetime


class SimulationTrainingRecommendationResponse(BaseModel):
    recipient: str
    template_id: str
    template_name: str
    risk_score: int
    recommendation: str
    first_flagged_at: datetime
    updated_at: datetime


class SimulationTrainingRecommendationsListResponse(BaseModel):
    items: list[SimulationTrainingRecommendationResponse]
    total: int


class HumanRiskEvidenceResponse(BaseModel):
    campaigns_run: int
    distinct_employees_tested: int
    distinct_employees_trained: int
    sample_campaign_ids: list[UUID]
