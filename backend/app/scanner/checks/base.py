"""Check interface and common context/finding helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from app.scanner.errors import ScannerError
from app.scanner.findings import (
    Finding,
    FindingCategory,
    FindingStatus,
    Severity,
    affected_url_for_context,
)
from app.scanner.models import ScanContext


class SecurityCheck(Protocol):
    check_id: str
    name: str
    description: str
    category: FindingCategory
    default_severity: Severity
    default_why_it_matters: str

    def run(self, context: ScanContext) -> tuple[Finding, ...]: ...


class BaseCheck(ABC):
    check_id: str
    name: str
    description: str
    category: FindingCategory
    default_severity: Severity
    default_remediation: str
    default_why_it_matters: str

    def finding(
        self,
        context: ScanContext,
        *,
        status: FindingStatus,
        severity: Severity,
        summary: str,
        why_it_matters: str | None = None,
        evidence: dict[str, object],
        remediation: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            title=self.name,
            severity=severity,
            category=self.category,
            status=status,
            summary=summary,
            why_it_matters=why_it_matters or self.default_why_it_matters,
            evidence=evidence,
            remediation=remediation or self.default_remediation,
            affected_url=affected_url_for_context(context),
            metadata=metadata or {},
        )

    def response_error(self, context: ScanContext) -> Finding | None:
        if context.http_status is not None:
            return None
        scanner_error: ScannerError | None = context.error
        evidence: dict[str, object] = {"response_available": False}
        if scanner_error is not None:
            evidence["scanner_error_code"] = scanner_error.code.value
        return self.finding(
            context,
            status=FindingStatus.ERROR,
            severity=Severity.INFORMATIONAL,
            summary="This check could not run because no HTTP response was captured.",
            why_it_matters="Without a captured response, this check has no evidence to evaluate.",
            evidence=evidence,
            remediation="Retry the assessment after resolving the scanner request error.",
        )

    @abstractmethod
    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        raise NotImplementedError
