"""Validated request and response models for the scan API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(strict=True, min_length=1, max_length=2_048)


class FindingResponse(BaseModel):
    id: str | None = None
    check_id: str
    title: str
    category: str
    severity: str
    status: str
    summary: str
    why_it_matters: str
    evidence: dict[str, Any]
    remediation: str
    affected_url: str
    metadata: dict[str, Any]


class TechnologyResponse(BaseModel):
    name: str
    category: str
    confidence: str | None
    evidence: list[Any]


class CheckResultResponse(BaseModel):
    check_id: str
    status: str
    severity: str | None
    scoring_relevant: bool
    scoring_version: str
    check_version: str
    reason: str
    evidence: dict[str, Any]
    score_explanation: dict[str, Any]


class ScanErrorResponse(BaseModel):
    code: str
    message: str


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class ScanSummaryResponse(BaseModel):
    id: str
    target_url: str
    normalized_url: str | None
    status: Literal["pending", "running", "completed", "failed"]
    score: int | None
    score_available: bool
    confidence: Literal["complete", "partial", "limited"] | None
    created_at: str
    completed_at: str | None
    duration_ms: int | None
    finding_count: int | None
    severity_counts: SeverityCounts | None


class ScanListResponse(BaseModel):
    items: list[ScanSummaryResponse]
    total: int
    limit: int
    offset: int


class ScanResponse(BaseModel):
    id: str
    target_url: str
    normalized_url: str | None = None
    status: Literal["pending", "running", "completed", "failed"]
    created_at: str | None = None
    completed_at: str | None = None
    duration_ms: int | None = None
    score: int | None
    score_available: bool
    confidence: Literal["complete", "partial", "limited"] | None
    scoring_version: str | None
    score_unavailability_reasons: list[str]
    score_details: dict[str, Any]
    summary: str
    findings: list[FindingResponse]
    technologies: list[TechnologyResponse]
    check_results: list[CheckResultResponse]
    ai_available: bool = False
    ai_summary: "StoredAiSummary | None" = None
    ai_explanations: list["StoredAiExplanation"] = Field(default_factory=list)
    error: ScanErrorResponse | None = None


class FindingAiContent(BaseModel):
    what_it_means: str
    why_it_matters: str
    observed_evidence: str
    remediation: str
    limitations: str


class SummaryAiContent(BaseModel):
    posture: str
    strongest_observed_controls: list[str]
    important_observed_weaknesses: list[str]
    recommended_next_steps: list[str]
    limitations: str


class StoredAiSummary(BaseModel):
    generated_at: str
    provider: str
    model: str
    prompt_version: str
    cached: bool = True
    content: SummaryAiContent


class StoredAiExplanation(BaseModel):
    finding_id: str
    generated_at: str
    provider: str
    model: str
    prompt_version: str
    cached: bool = True
    content: FindingAiContent


class AiSummaryResponse(StoredAiSummary):
    cached: bool = False


class AiExplanationResponse(StoredAiExplanation):
    cached: bool = False


class ScanFailureResponse(BaseModel):
    id: str
    target_url: str
    status: Literal["failed"]
    error: ScanErrorResponse


ScanResponse.model_rebuild()
