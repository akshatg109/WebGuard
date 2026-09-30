"""Pure, deterministic implementation of the WebGuard score methodology v1.0.

This module consumes already-produced scanner findings. It performs no target
validation, I/O, network access, persistence, or severity-based arithmetic.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from fractions import Fraction
import json
from types import MappingProxyType

from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity

SCORING_VERSION = "1.0"
MIN_APPLICABLE_POINTS = 60
MIN_COVERAGE_PERCENT = 80


class ScoreConfidence(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    LIMITED = "limited"


class CategoryState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    check_id: str
    name: str
    category: FindingCategory
    points: int
    role: str
    legacy_catalog_id: str | None = None
    check_version: str = "1"

    @property
    def is_score_bearing(self) -> bool:
        return self.points > 0


# Canonical IDs exactly match the current Phase 4B/4C registry. `legacy_catalog_id`
# is reconciliation metadata only; score_findings never accepts it as an alias.
CHECK_CATALOG: tuple[CheckDefinition, ...] = (
    CheckDefinition("transport.https", "HTTPS availability", FindingCategory.TRANSPORT, 30, "scored", "https"),
    CheckDefinition("transport.http_to_https_redirect", "HTTP-to-HTTPS redirect", FindingCategory.TRANSPORT, 0, "diagnostic", "http_to_https"),
    CheckDefinition("transport.final_scheme", "Final URL scheme", FindingCategory.TRANSPORT, 0, "diagnostic"),
    CheckDefinition("headers.hsts", "HTTP Strict Transport Security", FindingCategory.HEADERS, 12, "scored", "hsts"),
    CheckDefinition("headers.csp", "Content Security Policy", FindingCategory.HEADERS, 14, "scored", "csp"),
    CheckDefinition("headers.x_content_type_options", "X-Content-Type-Options", FindingCategory.HEADERS, 4, "scored", "x_content_type_options"),
    CheckDefinition("headers.referrer_policy", "Referrer Policy", FindingCategory.HEADERS, 3, "scored", "referrer_policy"),
    CheckDefinition("headers.permissions_policy", "Permissions Policy", FindingCategory.HEADERS, 3, "scored", "permissions_policy"),
    CheckDefinition("headers.frame_protection", "Frame protection", FindingCategory.HEADERS, 9, "scored", "frame_protection"),
    CheckDefinition("exposure.server_headers", "Server information exposure", FindingCategory.EXPOSURE, 0, "informational", "server_header"),
    CheckDefinition("cookies.security_attributes", "Cookie security attributes", FindingCategory.COOKIES, 15, "scored", "secure_cookies"),
    CheckDefinition("content.mixed_http_resources", "Mixed-content references", FindingCategory.CONTENT, 10, "scored", "mixed_content"),
    CheckDefinition("technology.passive_indicators", "Passive technology indicators", FindingCategory.TECHNOLOGY, 0, "informational"),
)

SCORING_CHECKS: tuple[CheckDefinition, ...] = tuple(
    definition for definition in CHECK_CATALOG if definition.is_score_bearing
)
CHECKS_BY_ID: Mapping[str, CheckDefinition] = MappingProxyType(
    {definition.check_id: definition for definition in CHECK_CATALOG}
)
CATEGORY_BUDGETS: Mapping[FindingCategory, int] = MappingProxyType(
    {
        FindingCategory.TRANSPORT: 30,
        FindingCategory.HEADERS: 45,
        FindingCategory.COOKIES: 15,
        FindingCategory.CONTENT: 10,
    }
)

# These rows document exact semantic correspondence for catalog/history
# reconciliation. They intentionally do not rewrite finding IDs at runtime.
LEGACY_CATALOG_RECONCILIATION: Mapping[str, str] = MappingProxyType(
    {
        definition.legacy_catalog_id: definition.check_id
        for definition in CHECK_CATALOG
        if definition.legacy_catalog_id is not None
    }
)
NEW_CANONICAL_CHECK_IDS: tuple[str, ...] = tuple(
    definition.check_id
    for definition in CHECK_CATALOG
    if definition.legacy_catalog_id is None
)


@dataclass(frozen=True, slots=True)
class CategoryBreakdown:
    category: FindingCategory
    budget_points: int
    available_points: int
    resolved_points: int
    unassessed_points: int
    deductions: int
    resulting_points: int
    state: CategoryState

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category.value,
            "budget_points": self.budget_points,
            "available_points": self.available_points,
            "resolved_points": self.resolved_points,
            "unassessed_points": self.unassessed_points,
            "deductions": self.deductions,
            "resulting_points": self.resulting_points,
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class CheckExplanation:
    check_id: str
    category: FindingCategory
    scoring: bool
    check_version: str
    status: FindingStatus | None
    severity: Severity | None
    state: str
    weight_points: int
    applicable_points: int
    resolved_points: int
    deduction_points: int
    reason_code: str
    reason: str
    observed_conditions: tuple[str, ...] = ()
    evidence_reference: str | None = None
    partial_evidence: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "category": self.category.value,
            "scoring": self.scoring,
            "check_version": self.check_version,
            "status": self.status.value if self.status is not None else None,
            "severity": self.severity.value if self.severity is not None else None,
            "state": self.state,
            "weight_points": self.weight_points,
            "applicable_points": self.applicable_points,
            "resolved_points": self.resolved_points,
            "deduction_points": self.deduction_points,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "observed_conditions": list(self.observed_conditions),
            "evidence_reference": self.evidence_reference,
            "partial_evidence": self.partial_evidence,
        }


@dataclass(frozen=True, slots=True)
class ScoreResult:
    score: int | None
    available: bool
    scoring_version: str
    confidence: ScoreConfidence
    applicable_points: int
    resolved_points: int
    unassessed_points: int
    deductions: int
    point_coverage_percent: float | None
    applicable_checks: int
    resolved_checks: int
    check_coverage_percent: float | None
    categories: tuple[CategoryBreakdown, ...]
    weakest_categories: tuple[FindingCategory, ...]
    checks: tuple[CheckExplanation, ...]
    unavailability_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-friendly explanation/result contract."""
        return {
            "score": self.score,
            "available": self.available,
            "scoring_version": self.scoring_version,
            "confidence": self.confidence.value,
            "applicable_points": self.applicable_points,
            "resolved_points": self.resolved_points,
            "unassessed_points": self.unassessed_points,
            "deductions": self.deductions,
            "point_coverage_percent": self.point_coverage_percent,
            "applicable_checks": self.applicable_checks,
            "resolved_checks": self.resolved_checks,
            "check_coverage_percent": self.check_coverage_percent,
            "categories": [category.to_dict() for category in self.categories],
            "weakest_categories": [category.value for category in self.weakest_categories],
            "checks": [check.to_dict() for check in self.checks],
            "unavailability_reasons": list(self.unavailability_reasons),
        }


@dataclass(frozen=True, slots=True)
class _Evaluation:
    state: str
    deduction: int = 0
    reason_code: str = ""
    reason: str = ""
    observed_conditions: tuple[str, ...] = ()
    partial_evidence: bool = False

    @property
    def resolved(self) -> bool:
        return self.state in {"passed", "failed", "warning"}


def score_findings(findings: Iterable[Finding]) -> ScoreResult:
    """Score canonical scanner findings without I/O or implicit status inference.

    Every score-bearing check is expected. Missing, conflicting, erroneous, or
    inconclusive results remain applicable but unresolved. Exact duplicate
    findings collapse to one observation; conflicting duplicates are unresolved.
    """
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError("score_findings accepts only scanner Finding instances.")
        definition = CHECKS_BY_ID.get(finding.check_id)
        if definition is None:
            raise ValueError(
                f"Unknown scanner check ID {finding.check_id!r}; legacy catalog IDs are not score aliases."
            )
        if finding.category != definition.category:
            raise ValueError(
                f"Finding category for {finding.check_id!r} does not match the canonical check catalog."
            )
        grouped[finding.check_id].append(finding)

    explanations: list[CheckExplanation] = []
    partial_evidence_seen = False
    for definition in CHECK_CATALOG:
        observations = _distinct_observations(grouped.get(definition.check_id, ()))
        if not observations:
            if definition.is_score_bearing:
                explanations.append(
                    _explanation(
                        definition,
                        finding=None,
                        state="unresolved",
                        applicable_points=definition.points,
                        resolved_points=0,
                        deduction=0,
                        reason_code="missing_result",
                        reason="Expected scoring result was not provided.",
                    )
                )
            continue

        if len(observations) > 1:
            explanations.append(
                _explanation(
                    definition,
                    finding=None,
                    state="unresolved",
                    applicable_points=definition.points,
                    resolved_points=0,
                    deduction=0,
                    reason_code="conflicting_duplicate_results",
                    reason="Conflicting duplicate results make this check inconclusive.",
                )
            )
            continue

        finding = observations[0]
        if not definition.is_score_bearing:
            explanations.append(_informational_explanation(definition, finding))
            continue

        observed_check_version = finding.metadata.get("check_version")
        if observed_check_version is not None and observed_check_version != definition.check_version:
            evaluation = _unresolved(
                "unsupported_check_version",
                "The finding was produced by a check version not supported by this scoring catalog.",
            )
        else:
            evaluation = _evaluate_scoring_check(definition, finding)
        if evaluation.resolved:
            expected_state = "warning" if finding.status == FindingStatus.WARN else "failed" if finding.status == FindingStatus.FAIL else "passed"
            if evaluation.state != expected_state:
                evaluation = replace(evaluation, state=expected_state)
        partial_evidence_seen = partial_evidence_seen or evaluation.partial_evidence
        applicable_points = 0 if evaluation.state == "not_applicable" else definition.points
        resolved_points = definition.points if evaluation.resolved else 0
        explanations.append(
            _explanation(
                definition,
                finding=finding,
                state=evaluation.state,
                applicable_points=applicable_points,
                resolved_points=resolved_points,
                deduction=evaluation.deduction,
                reason_code=evaluation.reason_code,
                reason=evaluation.reason,
                observed_conditions=evaluation.observed_conditions,
                partial_evidence=evaluation.partial_evidence,
            )
        )

    scoring_explanations = tuple(check for check in explanations if check.scoring)
    applicable_points = sum(check.applicable_points for check in scoring_explanations)
    resolved_points = sum(check.resolved_points for check in scoring_explanations)
    deductions = sum(check.deduction_points for check in scoring_explanations)
    applicable_checks = sum(check.applicable_points > 0 for check in scoring_explanations)
    resolved_checks = sum(check.resolved_points > 0 for check in scoring_explanations)
    unassessed_points = applicable_points - resolved_points

    point_coverage = _coverage_percent(resolved_points, applicable_points)
    check_coverage = _coverage_percent(resolved_checks, applicable_checks)
    reasons = _unavailability_reasons(
        applicable_points=applicable_points,
        resolved_points=resolved_points,
        applicable_checks=applicable_checks,
        resolved_checks=resolved_checks,
        has_unresolved=any(
            check.scoring and check.state in {"unresolved", "error"}
            for check in explanations
        ),
    )
    available = not reasons
    if not available:
        confidence = ScoreConfidence.LIMITED
        score = None
    else:
        confidence = (
            ScoreConfidence.PARTIAL
            if unassessed_points > 0 or partial_evidence_seen
            else ScoreConfidence.COMPLETE
        )
        # Integer arithmetic implements decimal half-up rounding exactly.
        raw_numerator = 100 * (resolved_points - deductions)
        score = min(100, max(0, _round_half_up(raw_numerator, resolved_points)))

    categories = tuple(
        _category_breakdown(category, budget, scoring_explanations)
        for category, budget in CATEGORY_BUDGETS.items()
    )
    ordered_explanations = tuple(sorted(explanations, key=_check_explanation_order))
    return ScoreResult(
        score=score,
        available=available,
        scoring_version=SCORING_VERSION,
        confidence=confidence,
        applicable_points=applicable_points,
        resolved_points=resolved_points,
        unassessed_points=unassessed_points,
        deductions=deductions,
        point_coverage_percent=point_coverage,
        applicable_checks=applicable_checks,
        resolved_checks=resolved_checks,
        check_coverage_percent=check_coverage,
        categories=categories,
        weakest_categories=_weakest_categories(categories),
        checks=ordered_explanations,
        unavailability_reasons=reasons,
    )


def _distinct_observations(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    distinct: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        serialized = finding.to_dict()
        signature = json.dumps(
            {
                "check_id": finding.check_id,
                "status": finding.status.value,
                "evidence": serialized["evidence"],
                "check_version": finding.metadata.get("check_version"),
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        distinct[signature].append(finding)
    return tuple(
        min(distinct[key], key=_representative_observation_order)
        for key in sorted(distinct)
    )


def _representative_observation_order(finding: Finding) -> tuple[str, str, str, str]:
    severity_order = {
        Severity.CRITICAL: "0",
        Severity.HIGH: "1",
        Severity.MEDIUM: "2",
        Severity.LOW: "3",
        Severity.INFORMATIONAL: "4",
    }
    return (
        severity_order[finding.severity],
        finding.title,
        finding.summary,
        json.dumps(finding.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")),
    )


def _evaluate_scoring_check(definition: CheckDefinition, finding: Finding) -> _Evaluation:
    status = finding.status
    evidence = finding.evidence
    check_id = definition.check_id

    if status == FindingStatus.ERROR:
        return _unresolved("check_error", "The check returned an error; no target penalty was applied.", state="error")
    if status == FindingStatus.NOT_APPLICABLE:
        if _legitimate_not_applicable(check_id, evidence):
            return _Evaluation("not_applicable", reason_code="legitimate_not_applicable", reason="This check does not apply to the observed response.")
        return _unresolved(
            "incomplete_not_applicable",
            "The not-applicable result is based on missing or incomplete evidence, so the check remains in coverage.",
        )

    if check_id == "transport.https":
        final_scheme = _string(evidence, "final_scheme")
        if status == FindingStatus.PASS and final_scheme == "https":
            return _passed("https_observed", "The final response was observed over HTTPS.")
        if status == FindingStatus.FAIL and final_scheme == "http":
            return _failed(30, "final_response_over_http", "The final response used HTTP.")
        return _unresolved("inconsistent_or_missing_evidence", "The HTTPS result does not contain matching final-scheme evidence.")

    if check_id == "headers.hsts":
        present = _bool(evidence, "header_present")
        final_scheme = _string(evidence, "final_scheme")
        max_age = _integer(evidence, "max_age")
        header_count = _integer(evidence, "header_count")
        parse_errors = _sequence(evidence, "parse_errors")
        if status == FindingStatus.PASS:
            if final_scheme == "https" and present is True and max_age is not None and max_age > 0 and header_count == 1 and parse_errors == ():
                return _passed("hsts_positive_max_age", "A single parseable HSTS header with positive max-age was observed.")
            return _unresolved("inconsistent_or_missing_evidence", "The HSTS pass lacks complete positive max-age evidence.")
        if final_scheme == "https" and present is False and status == FindingStatus.FAIL:
            return _failed(12, "hsts_missing", "No HSTS header was observed on the HTTPS response.")
        if final_scheme == "https" and present is True and max_age == 0 and status in {FindingStatus.FAIL, FindingStatus.WARN}:
            return _failed(12, "hsts_disabled", "HSTS explicitly sets max-age to zero.")
        if final_scheme == "https" and present is True and header_count is not None and header_count > 0 and status == FindingStatus.WARN:
            if parse_errors is not None and (parse_errors or header_count > 1 or max_age is None):
                return _failed(6, "hsts_incomplete_policy", "The HSTS header is present but malformed, duplicated, or incomplete.")
        return _unresolved("inconsistent_or_missing_evidence", "The HSTS result does not identify a supported policy condition.")

    if check_id == "headers.csp":
        present = _bool(evidence, "header_present")
        header_count = _integer(evidence, "header_count")
        unsafe_inline = _bool(evidence, "unsafe_inline_observed")
        unsafe_eval = _bool(evidence, "unsafe_eval_observed")
        broad_sources = _sequence(evidence, "broad_source_kinds")
        malformed = _integer(evidence, "malformed_policy_count")
        duplicates = _sequence(evidence, "duplicate_directives")
        if status == FindingStatus.FAIL and present is False:
            return _failed(14, "csp_missing", "No Content-Security-Policy header was observed.")
        if status == FindingStatus.PASS:
            if (
                present is True
                and header_count is not None
                and header_count > 0
                and unsafe_inline is False
                and unsafe_eval is False
                and broad_sources == ()
                and malformed == 0
                and duplicates == ()
            ):
                return _passed("csp_parseable_observed", "CSP was present and no configured weak or structural indicator was observed.")
            return _unresolved("inconsistent_or_missing_evidence", "The CSP pass lacks complete evidence or conflicts with an observed weakness.")
        if status == FindingStatus.WARN and present is True:
            weak_evidence = unsafe_inline is True or unsafe_eval is True or bool(broad_sources)
            structural_evidence = (malformed is not None and malformed > 0) or bool(duplicates)
            if weak_evidence:
                return _failed(9, "csp_permissive_sources", "CSP contains one or more observed unsafe or broad source tokens.", ("unsafe_or_broad_source",))
            if structural_evidence:
                return _failed(5, "csp_structural_issue", "CSP has a malformed policy or duplicate directive.", ("structural_or_duplicate_directive",))
        return _unresolved("inconsistent_or_missing_evidence", "The CSP result does not identify a supported weakness or conclusive pass.")

    if check_id == "headers.x_content_type_options":
        present = _bool(evidence, "header_present")
        header_count = _integer(evidence, "header_count")
        unexpected = _integer(evidence, "unexpected_value_count")
        nosniff = _integer(evidence, "nosniff_values")
        if status == FindingStatus.PASS and present is True and header_count is not None and header_count > 0 and unexpected == 0 and nosniff is not None and nosniff > 0:
            return _passed("nosniff_observed", "Every observed X-Content-Type-Options value was nosniff.")
        if status == FindingStatus.FAIL and (present is False or (present is True and unexpected is not None and unexpected > 0)):
            return _failed(4, "x_content_type_options_missing_or_unexpected", "X-Content-Type-Options was missing or had an unexpected value.")
        return _unresolved("inconsistent_or_missing_evidence", "The X-Content-Type-Options result lacks matching header evidence.")

    if check_id == "headers.referrer_policy":
        present = _bool(evidence, "header_present")
        selected = _string(evidence, "effective_policy_candidate")
        recognized = _sequence(evidence, "recognized_policies")
        unrecognized = _integer(evidence, "unrecognized_token_count")
        weaker = _bool(evidence, "weaker_policy_candidate")
        if status == FindingStatus.FAIL and present is False:
            return _failed(3, "referrer_policy_missing", "No Referrer-Policy header was observed.")
        if (
            status == FindingStatus.PASS
            and present is True
            and recognized
            and selected is not None
            and selected in recognized
            and selected not in {"unsafe-url", "no-referrer-when-downgrade"}
            and unrecognized == 0
            and weaker is False
        ):
            return _passed("referrer_policy_recognized", "A recognized Referrer-Policy candidate was observed.")
        if status == FindingStatus.WARN and present is True:
            if selected == "unsafe-url":
                return _failed(3, "referrer_policy_unsafe_url", "The effective Referrer-Policy candidate is unsafe-url.")
            if (selected == "no-referrer-when-downgrade" or unrecognized is not None and unrecognized > 0 or recognized == ()):
                return _failed(1, "referrer_policy_review", "The observed Referrer-Policy has a weaker, malformed, or unrecognized candidate.")
        return _unresolved("inconsistent_or_missing_evidence", "The Referrer-Policy result lacks matching policy evidence.")

    if check_id == "headers.permissions_policy":
        present = _bool(evidence, "header_present")
        header_count = _integer(evidence, "header_count")
        parse_errors = _sequence(evidence, "parse_errors")
        if status == FindingStatus.FAIL and present is False:
            return _failed(3, "permissions_policy_missing", "No Permissions-Policy header was observed.")
        if status == FindingStatus.PASS and present is True and header_count is not None and header_count > 0 and parse_errors == ():
            return _passed("permissions_policy_parseable", "Permissions-Policy was present and structurally parseable.")
        if status == FindingStatus.WARN and present is True and header_count is not None and header_count > 0 and parse_errors:
            return _failed(2, "permissions_policy_malformed", "Permissions-Policy is present but has a parse error.")
        return _unresolved("inconsistent_or_missing_evidence", "The Permissions-Policy result lacks matching syntax evidence.")

    if check_id == "headers.frame_protection":
        via = _sequence(evidence, "protection_observed_via")
        xfo_present = _bool(evidence, "x_frame_options_present")
        xfo_count = _integer(evidence, "x_frame_options_count")
        xfo_recognized = _string(evidence, "x_frame_options_recognized")
        allow_from = _bool(evidence, "x_frame_options_allow_from_observed")
        csp_restrictive = _bool(evidence, "csp_frame_ancestors_restrictive_observed")
        recognized_via = all(item in {"x-frame-options", "csp-frame-ancestors"} for item in via)
        xfo_protection = "x-frame-options" in via and xfo_recognized in {"DENY", "SAMEORIGIN"}
        csp_protection = "csp-frame-ancestors" in via and csp_restrictive is True
        if status == FindingStatus.PASS and via and recognized_via and (xfo_protection or csp_protection):
            return _passed("frame_restriction_observed", "A recognized frame restriction was observed through at least one supported mechanism.")
        if status == FindingStatus.FAIL and not via and xfo_present is False and csp_restrictive is False:
            return _failed(9, "frame_restriction_missing", "No recognized frame restriction was observed.")
        if status == FindingStatus.WARN and not via and xfo_present is True and csp_restrictive is False:
            if (xfo_count is not None and xfo_count > 0 and xfo_recognized is None) or allow_from is True:
                return _failed(5, "frame_header_unrecognized", "X-Frame-Options was present but not reliably recognized, without restrictive CSP frame-ancestors.")
        return _unresolved("inconsistent_or_missing_evidence", "The frame-protection result lacks matching evidence.")

    if check_id == "cookies.security_attributes":
        cookie_evaluation = _evaluate_cookies(status, evidence)
        return cookie_evaluation

    if check_id == "content.mixed_http_resources":
        return _evaluate_mixed_content(status, evidence)

    # Catalog changes must add an explicit rule above; a new scored check cannot
    # silently inherit a generic severity or deduction formula.
    raise RuntimeError(f"No scoring rule is defined for {check_id!r}.")


def _evaluate_cookies(status: FindingStatus, evidence: Mapping[str, object]) -> _Evaluation:
    required_sequences = (
        "secure_missing_cookie_names",
        "same_site_none_without_secure_cookie_names",
        "domain_scope_outside_target_cookie_names",
        "prefix_requirement_violation_cookie_names",
        "same_site_missing_cookie_names",
        "same_site_invalid_cookie_names",
        "http_only_missing_sensitive_name_candidates",
        "invalid_attribute_cookie_names",
    )
    values = {key: _sequence(evidence, key) for key in required_sequences}
    header_count = _integer(evidence, "set_cookie_header_count")
    malformed_count = _integer(evidence, "malformed_set_cookie_header_count")
    if header_count is None or header_count < 0 or malformed_count is None or malformed_count < 0 or any(value is None for value in values.values()):
        return _unresolved("inconsistent_or_missing_evidence", "Cookie issue classes were not completely reported.")
    if header_count == 0:
        return _unresolved("inconsistent_or_missing_evidence", "A cookie result with no Set-Cookie headers should be not_applicable.")

    secure_issue = bool(values["secure_missing_cookie_names"] or values["same_site_none_without_secure_cookie_names"])
    scope_issue = bool(
        values["domain_scope_outside_target_cookie_names"]
        or values["prefix_requirement_violation_cookie_names"]
    )
    advisory_issue = bool(
        values["same_site_missing_cookie_names"]
        or values["same_site_invalid_cookie_names"]
        or values["http_only_missing_sensitive_name_candidates"]
        or values["invalid_attribute_cookie_names"]
        or malformed_count > 0
    )
    issues = secure_issue or scope_issue or advisory_issue
    if status == FindingStatus.PASS and not issues:
        return _passed("cookie_attributes_observed", "No configured cookie-attribute issue class was observed.")
    if status not in {FindingStatus.WARN, FindingStatus.FAIL} or not issues:
        return _unresolved("inconsistent_or_missing_evidence", "Cookie status and aggregated issue evidence do not agree.")

    deduction = (10 if secure_issue else 0) + (5 if scope_issue else 0) + (3 if advisory_issue else 0)
    deduction = min(15, deduction)
    conditions = tuple(
        code
        for present, code in (
            (secure_issue, "secure_or_same_site_none_issue"),
            (scope_issue, "cookie_prefix_or_domain_scope_issue"),
            (advisory_issue, "cookie_advisory_issue"),
        )
        if present
    )
    return _failed(deduction, "cookie_issue_classes", "Observed cookie issue classes were aggregated once and capped at 15 points.", conditions)


def _evaluate_mixed_content(status: FindingStatus, evidence: Mapping[str, object]) -> _Evaluation:
    count = _integer(evidence, "detected_reference_count")
    resource_types = _resource_type_counts(evidence.get("resource_type_counts"))
    inspected = _bool(evidence, "body_inspected")
    body_truncated = _bool(evidence, "body_analysis_truncated")
    reference_truncated = _bool(evidence, "reference_scan_truncated")
    if count is None or count < 0 or resource_types is None:
        return _unresolved("inconsistent_or_missing_evidence", "Mixed-content reference evidence is incomplete.")
    if count > 0:
        if not resource_types or sum(resource_types.values()) <= 0:
            return _unresolved("inconsistent_or_missing_evidence", "Mixed-content references were counted without resource-type evidence.")
        if inspected is not True or body_truncated is None or reference_truncated is None:
            return _unresolved(
                "incomplete_content_evidence",
                "A mixed-content hit was reported without complete inspection/truncation metadata.",
                partial_evidence=body_truncated is True or reference_truncated is True,
            )
        active_types = {"script", "stylesheet", "iframe", "frame", "embed", "object"}
        if status not in {FindingStatus.WARN, FindingStatus.FAIL}:
            return _unresolved("inconsistent_or_missing_evidence", "A positive mixed-content observation conflicts with the reported status.")
        active = any(resource_type in active_types and amount > 0 for resource_type, amount in resource_types.items())
        partial = body_truncated is True or reference_truncated is True
        return _failed(
            10 if active else 5,
            "active_mixed_content" if active else "passive_mixed_content",
            "At least one HTTP resource reference was observed; repeated references do not multiply the deduction.",
            ("active_resource_reference" if active else "passive_resource_reference",),
            partial_evidence=partial,
        )
    if status == FindingStatus.PASS and inspected is True and body_truncated is False and reference_truncated is False and not resource_types:
        return _passed("mixed_content_not_observed", "The complete bounded HTML inspection found no configured HTTP resource references.")
    if status == FindingStatus.WARN and inspected is True and (body_truncated is True or reference_truncated is True):
        return _unresolved(
            "partial_content_without_hit",
            "No reference was observed, but content inspection was truncated; this is not a pass.",
            partial_evidence=True,
        )
    return _unresolved("inconsistent_or_missing_evidence", "The mixed-content result lacks a complete inspection or matching status.")


def _legitimate_not_applicable(check_id: str, evidence: Mapping[str, object]) -> bool:
    if check_id == "headers.hsts":
        return _string(evidence, "final_scheme") == "http"
    if check_id == "cookies.security_attributes":
        return (
            _integer(evidence, "set_cookie_header_count") == 0
            and _integer(evidence, "cookie_count") == 0
        )
    if check_id == "content.mixed_http_resources":
        if _string(evidence, "final_scheme") == "http":
            return True
        content_types = _sequence(evidence, "content_types")
        if content_types is None or not content_types:
            return False
        normalized: list[str] = []
        for content_type in content_types:
            if not isinstance(content_type, str) or not content_type.strip():
                return False
            normalized.append(content_type.split(";", 1)[0].strip().casefold())
        if len(set(normalized)) != 1 or normalized[0] in {"text/html", "application/xhtml+xml"}:
            return False
        return True
    return False


def _informational_explanation(definition: CheckDefinition, finding: Finding) -> CheckExplanation:
    if definition.role == "diagnostic":
        reason_code = "diagnostic_only"
        reason = "This transport observation is diagnostic-only and does not change the score."
    else:
        reason_code = "informational_only"
        reason = "This observation is informational and does not change the score."
    return _explanation(
        definition,
        finding=finding,
        state=finding.status.value,
        applicable_points=0,
        resolved_points=0,
        deduction=0,
        reason_code=reason_code,
        reason=reason,
    )


def _explanation(
    definition: CheckDefinition,
    *,
    finding: Finding | None,
    state: str,
    applicable_points: int,
    resolved_points: int,
    deduction: int,
    reason_code: str,
    reason: str,
    observed_conditions: tuple[str, ...] = (),
    partial_evidence: bool = False,
) -> CheckExplanation:
    return CheckExplanation(
        check_id=definition.check_id,
        category=definition.category,
        scoring=definition.is_score_bearing,
        check_version=definition.check_version,
        status=finding.status if finding is not None else None,
        severity=finding.severity if finding is not None else None,
        state=state,
        weight_points=definition.points,
        applicable_points=applicable_points,
        resolved_points=resolved_points,
        deduction_points=deduction,
        reason_code=reason_code,
        reason=reason,
        observed_conditions=observed_conditions,
        evidence_reference=definition.check_id if finding is not None else None,
        partial_evidence=partial_evidence,
    )


def _category_breakdown(
    category: FindingCategory,
    budget: int,
    checks: Sequence[CheckExplanation],
) -> CategoryBreakdown:
    category_checks = tuple(check for check in checks if check.category == category)
    available = sum(check.applicable_points for check in category_checks)
    resolved = sum(check.resolved_points for check in category_checks)
    deductions = sum(check.deduction_points for check in category_checks)
    partial_evidence = any(check.partial_evidence for check in category_checks)
    if available == 0:
        state = CategoryState.NOT_APPLICABLE
    elif resolved < available or partial_evidence:
        state = CategoryState.PARTIAL
    else:
        state = CategoryState.COMPLETE
    return CategoryBreakdown(
        category=category,
        budget_points=budget,
        available_points=available,
        resolved_points=resolved,
        unassessed_points=available - resolved,
        deductions=deductions,
        resulting_points=resolved - deductions,
        state=state,
    )


def _weakest_categories(categories: Sequence[CategoryBreakdown]) -> tuple[FindingCategory, ...]:
    reduced = [category for category in categories if category.resolved_points > 0 and category.deductions > 0]
    reduced.sort(
        key=lambda category: (
            -Fraction(category.deductions, category.resolved_points),
            tuple(CATEGORY_BUDGETS).index(category.category),
        )
    )
    return tuple(category.category for category in reduced)


def _check_explanation_order(check: CheckExplanation) -> tuple[int, int, str]:
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }
    return (-check.deduction_points, severity_order.get(check.severity, 5), check.check_id)


def _unavailability_reasons(
    *,
    applicable_points: int,
    resolved_points: int,
    applicable_checks: int,
    resolved_checks: int,
    has_unresolved: bool,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if applicable_points < MIN_APPLICABLE_POINTS:
        reasons.append("insufficient_applicable_points")
    if not _coverage_at_least(resolved_points, applicable_points, MIN_COVERAGE_PERCENT):
        reasons.append("insufficient_point_coverage")
    if not _coverage_at_least(resolved_checks, applicable_checks, MIN_COVERAGE_PERCENT):
        reasons.append("insufficient_check_coverage")
    coverage_is_incomplete = (
        resolved_points < applicable_points or resolved_checks < applicable_checks
    )
    if has_unresolved and coverage_is_incomplete and reasons:
        reasons.append("incomplete_scan")
    return tuple(reasons)


def _coverage_at_least(resolved: int, applicable: int, minimum_percent: int) -> bool:
    return applicable > 0 and resolved * 100 >= applicable * minimum_percent


def _coverage_percent(resolved: int, applicable: int) -> float | None:
    if applicable == 0:
        return None
    # Report two decimal places using integer half-up rounding.
    hundredths = _round_half_up(resolved * 10_000, applicable)
    return hundredths / 100


def _round_half_up(numerator: int, denominator: int) -> int:
    if denominator <= 0 or numerator < 0:
        raise ValueError("Half-up rounding expects a non-negative numerator and positive denominator.")
    quotient, remainder = divmod(numerator, denominator)
    return quotient + int(remainder * 2 >= denominator)


def _resource_type_counts(value: object) -> dict[str, int] | None:
    if not isinstance(value, (tuple, list)):
        return None
    counts: dict[str, int] = {}
    for pair in value:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            return None
        resource_type, count = pair
        if not isinstance(resource_type, str) or not resource_type or not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return None
        counts[resource_type] = counts.get(resource_type, 0) + count
    return counts


def _bool(evidence: Mapping[str, object], key: str) -> bool | None:
    value = evidence.get(key)
    return value if isinstance(value, bool) else None


def _integer(evidence: Mapping[str, object], key: str) -> int | None:
    value = evidence.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _string(evidence: Mapping[str, object], key: str) -> str | None:
    value = evidence.get(key)
    return value if isinstance(value, str) else None


def _sequence(evidence: Mapping[str, object], key: str) -> tuple[object, ...] | None:
    value = evidence.get(key)
    if isinstance(value, (tuple, list)):
        return tuple(value)
    return None


def _passed(reason_code: str, reason: str) -> _Evaluation:
    return _Evaluation("passed", reason_code=reason_code, reason=reason)


def _failed(
    deduction: int,
    reason_code: str,
    reason: str,
    observed_conditions: tuple[str, ...] = (),
    *,
    partial_evidence: bool = False,
) -> _Evaluation:
    return _Evaluation(
        "failed",
        deduction,
        reason_code,
        reason,
        observed_conditions,
        partial_evidence,
    )


def _unresolved(
    reason_code: str,
    reason: str,
    *,
    state: str = "unresolved",
    partial_evidence: bool = False,
) -> _Evaluation:
    return _Evaluation(state, reason_code=reason_code, reason=reason, partial_evidence=partial_evidence)
