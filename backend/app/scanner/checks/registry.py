"""Explicit deterministic registry and runner for Phase 4B/4C checks."""

from __future__ import annotations

from collections.abc import Iterable
import re

from app.scanner.checks.base import SecurityCheck
from app.scanner.checks.header_checks import (
    ContentSecurityPolicyCheck,
    FrameProtectionCheck,
    HstsCheck,
    PermissionsPolicyCheck,
    ReferrerPolicyCheck,
    ServerInformationExposureCheck,
    XContentTypeOptionsCheck,
)
from app.scanner.checks.transport import (
    FinalUrlSchemeCheck,
    HttpsAvailabilityCheck,
    HttpToHttpsRedirectCheck,
)
from app.scanner.errors import ScannerErrorCode
from app.scanner.findings import Finding, FindingStatus, Severity, affected_url_for_context
from app.scanner.models import ScanContext

DEFAULT_CHECKS: tuple[SecurityCheck, ...] = (
    HttpsAvailabilityCheck(),
    HttpToHttpsRedirectCheck(),
    FinalUrlSchemeCheck(),
    HstsCheck(),
    ContentSecurityPolicyCheck(),
    XContentTypeOptionsCheck(),
    ReferrerPolicyCheck(),
    PermissionsPolicyCheck(),
    FrameProtectionCheck(),
    ServerInformationExposureCheck(),
)
_CHECK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_.]*$")


class CheckRegistry:
    """Fixed-order check inventory; checks are explicit rather than import-discovered."""

    def __init__(self, checks: Iterable[SecurityCheck]) -> None:
        self.checks = tuple(checks)
        check_ids = [check.check_id for check in self.checks]
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("Security check IDs must be unique.")
        if any(not _CHECK_ID_PATTERN.fullmatch(check_id) for check_id in check_ids):
            raise ValueError("Security check IDs must be stable lowercase identifiers.")

class CheckEngine:
    """Run a registry in order and isolate per-check failures safely."""

    def __init__(self, registry: CheckRegistry) -> None:
        self.registry = registry

    def evaluate(self, context: ScanContext) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for check in self.registry.checks:
            try:
                results = tuple(check.run(context))
                if any(
                    not isinstance(finding, Finding) or finding.check_id != check.check_id
                    for finding in results
                ):
                    raise ValueError("Check returned an invalid finding shape.")
                findings.extend(results)
            except Exception:
                findings.append(
                    Finding(
                        check_id=check.check_id,
                        title=check.name,
                        severity=Severity.INFORMATIONAL,
                        category=check.category,
                        status=FindingStatus.ERROR,
                        summary="This check could not be completed; no security conclusion was made.",
                        why_it_matters="The check produced no evidence, so its security question remains undetermined.",
                        evidence={"error_code": ScannerErrorCode.SCANNER_FAILURE.value},
                        remediation="Review the captured response and retry the assessment if the issue persists.",
                        affected_url=affected_url_for_context(context),
                        metadata={"check_version": "1"},
                    )
                )
        return tuple(findings)


DEFAULT_REGISTRY = CheckRegistry(DEFAULT_CHECKS)
DEFAULT_ENGINE = CheckEngine(DEFAULT_REGISTRY)


def run_security_checks(context: ScanContext) -> tuple[Finding, ...]:
    """Run registered checks over ScanContext without performing network requests."""
    return DEFAULT_ENGINE.evaluate(context)
