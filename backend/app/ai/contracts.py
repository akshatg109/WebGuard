"""Strict data and generated-output contracts for optional AI guidance."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

FindingStatusValue = Literal["pass", "fail", "warn", "not_applicable", "error"]
SeverityValue = Literal["critical", "high", "medium", "low", "informational"]
CategoryValue = Literal["transport", "headers", "exposure", "cookies", "content", "technology"]


class AiFindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    finding_id: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=160)
    category: CategoryValue
    severity: SeverityValue
    status: FindingStatusValue
    summary: str = Field(min_length=1, max_length=600)
    why_it_matters: str = Field(min_length=1, max_length=600)
    evidence: dict[str, object] = Field(default_factory=dict)
    remediation_hints: str = Field(min_length=1, max_length=800)
    scoring_impact: dict[str, object] = Field(default_factory=dict)


class FindingAiOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    what_it_means: str = Field(min_length=1, max_length=1_500)
    why_it_matters: str = Field(min_length=1, max_length=1_500)
    observed_evidence: str = Field(min_length=1, max_length=1_000)
    remediation: str = Field(min_length=1, max_length=2_500)
    limitations: str = Field(min_length=1, max_length=1_000)

    @field_validator("*")
    @classmethod
    def validate_nonblank_text(cls, value: object) -> object:
        if isinstance(value, str):
            if not value.strip() or any(
                (ord(char) < 0x20 and char not in {"\n", "\t"}) or ord(char) == 0x7F
                for char in value
            ):
                raise ValueError("AI text fields must contain printable text.")
            return value.strip()
        return value


class ScanSummaryAiOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    posture: str = Field(min_length=1, max_length=1_500)
    strongest_observed_controls: list[str] = Field(min_length=0, max_length=5)
    important_observed_weaknesses: list[str] = Field(min_length=0, max_length=5)
    recommended_next_steps: list[str] = Field(min_length=1, max_length=5)
    limitations: str = Field(min_length=1, max_length=1_000)

    @field_validator("posture", "limitations")
    @classmethod
    def validate_nonblank_text(cls, value: str) -> str:
        if not value.strip() or any(
            (ord(char) < 0x20 and char not in {"\n", "\t"}) or ord(char) == 0x7F
            for char in value
        ):
            raise ValueError("AI text fields must contain printable text.")
        return value.strip()

    @field_validator(
        "strongest_observed_controls",
        "important_observed_weaknesses",
        "recommended_next_steps",
    )
    @classmethod
    def validate_list_items(cls, value: list[str]) -> list[str]:
        if any(
            not item.strip()
            or len(item) > 500
            or any(
                (ord(char) < 0x20 and char not in {"\n", "\t"}) or ord(char) == 0x7F
                for char in item
            )
            for item in value
        ):
            raise ValueError("AI summary lists contain invalid items.")
        return [item.strip() for item in value]


class AiGenerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    regenerate: bool = False
