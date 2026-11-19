"""Structured parse responses."""
from typing import Literal
from datetime import date
from pydantic import BaseModel, ConfigDict, Field


class DeploymentSummary(BaseModel):
    name: str
    namespace: str
    replicas: int
    container_name: str
    image: str
    api_version: Literal["apps/v1"] = "apps/v1"
    kind: Literal["Deployment"] = "Deployment"
    os: Literal["linux"] = "linux"
    os_assumed: bool


class RequirementHint(BaseModel):
    requirement: Literal["api_access", "privileged_access", "non_root_compatibility"]
    suggested_value: Literal["unknown", "required", "not_required", "compatible", "incompatible"]
    evidence: list[str]
    limitation: str
    needs_confirmation: Literal[True] = True


class ParseResponse(BaseModel):
    status: Literal["parsed"] = "parsed"
    deployment: DeploymentSummary
    warnings: list[str]
    requirement_hints: list[RequirementHint] = Field(default_factory=list)


class GuidanceDocument(BaseModel):
    """A reviewed local paraphrase and its original reference."""
    model_config = ConfigDict(extra="forbid", str_min_length=1)

    document_id: str
    title: str
    category: str
    check_ids: list[str] = Field(min_length=1)
    tags: list[str] = Field(min_length=1)
    source_url: str
    reviewed_on: date
    applicable_condition: str
    guidance: str
    limitation: str


class GuidanceResult(BaseModel):
    status: Literal["available", "missing", "unavailable"]
    documents: list[GuidanceDocument]
    message: str


class SecurityFinding(BaseModel):
    check_id: str
    description: str
    category: str
    resource: str
    file: str = "deployment.yaml"
    line_range: list[int]
    evaluated_keys: list[str]
    guidance: GuidanceResult = Field(default_factory=lambda: GuidanceResult(
        status="missing", documents=[], message="No reviewed guidance has been retrieved for this finding.",
    ))


class ScanResponse(BaseModel):
    status: Literal["completed", "incomplete"]
    scanner: Literal["Checkov"] = "Checkov"
    scanner_version: str
    deployment: DeploymentSummary
    supported_checks: list[str]
    passed_checks: list[str]
    skipped_checks: list[str]
    findings: list[SecurityFinding]
    warnings: list[str]


class ApplicationRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    api_access: Literal["unknown", "required", "not_required"] = "unknown"
    privileged_access: Literal["unknown", "required", "not_required"] = "unknown"
    non_root_compatibility: Literal["unknown", "compatible", "incompatible"] = "unknown"


class CandidateChange(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: Literal[
        "/spec/template/spec/containers/0/securityContext/privileged",
        "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
        "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
        "/spec/template/spec/containers/0/securityContext/capabilities/drop",
        "/spec/template/spec/securityContext/seccompProfile/type",
        "/spec/template/spec/containers/0/securityContext/seccompProfile/type",
        "/spec/template/spec/automountServiceAccountToken",
    ]
    value: bool | str | list[str]
    rationale: str = Field(min_length=1, max_length=1000)


class AIProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    check_id: str = Field(min_length=1, max_length=32)
    explanation: str = Field(min_length=1, max_length=4000)
    candidates: list[CandidateChange] = Field(max_length=3)
    source_document_ids: list[str] = Field(min_length=1, max_length=3)
    limitations: list[str] = Field(min_length=1, max_length=5)


class AIUsage(BaseModel):
    external_requests_this_action: int
    estimated_input_tokens: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    process_requests_attempted: int
    process_requests_succeeded: int
    process_requests_failed: int
    process_reported_total_tokens: int


class ConstraintResult(BaseModel):
    requirement: str
    status: Literal["preserved", "conflict", "unverifiable"]
    message: str


class ConstraintReport(BaseModel):
    status: Literal["conflict", "manual_review", "preserved"]
    results: list[ConstraintResult]


class CandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    filename: str = Field(min_length=1, max_length=255)
    original_yaml: str = Field(min_length=1, max_length=256 * 1024)
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposal: AIProposal
    requirements: ApplicationRequirements
    approved: bool = False
    acknowledge_manual_review: bool = False


class CandidateChangeDetail(BaseModel):
    path: str
    original_present: bool
    original_value: str
    candidate_value: str
    rationale: str


class CandidateResponse(BaseModel):
    status: Literal["review_required", "blocked", "candidate_created", "no_changes"]
    original_sha256: str
    constraint_report: ConstraintReport
    semantic_changed_paths: list[str]
    change_details: list[CandidateChangeDetail] = Field(default_factory=list)
    candidate_yaml: str | None = None
    warnings: list[str]


class AIExplanationResponse(BaseModel):
    status: Literal["mock", "generated"]
    provider: Literal["mock", "gemini"]
    model: str
    proposal: AIProposal
    requirements: ApplicationRequirements
    usage: AIUsage
    warnings: list[str]
    original_sha256: str
    constraint_report: ConstraintReport


class SchemaValidation(BaseModel):
    status: Literal["passed", "failed", "unavailable"]
    code: str
    message: str
    validator_version: str = "v0.8.0"
    kubernetes_version: str = "1.35.0"


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    filename: str = Field(min_length=1, max_length=255)
    original_yaml: str = Field(min_length=1, max_length=256 * 1024)
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_yaml: str = Field(min_length=1, max_length=256 * 1024)
    proposal: AIProposal
    requirements: ApplicationRequirements


class VerificationCheck(BaseModel):
    name: str
    status: Literal["passed", "failed", "unavailable", "not_run", "manual_review"]
    message: str


class VerificationResponse(BaseModel):
    status: Literal["verified_supported_checks", "failed_validation", "new_security_findings", "requirement_conflict", "incomplete", "manual_review"]
    original_sha256: str
    candidate_sha256: str
    checks: list[VerificationCheck]
    schema_validation: SchemaValidation | None = None
    original_scan: ScanResponse | None = None
    candidate_scan: ScanResponse | None = None
    resolved_findings: list[SecurityFinding]
    new_findings: list[SecurityFinding]
    remaining_findings: list[SecurityFinding]
    targeted_finding_resolved: bool | None = None
    constraint_report: ConstraintReport | None = None
    semantic_changed_paths: list[str]
    unexpected_changed_paths: list[str]
    manual_review_required: bool = True
    warnings: list[str]
