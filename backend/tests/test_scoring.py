from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity
from app.scanner.checks import run_security_checks
from app.scanner.cookie_metadata import parse_set_cookie_headers
from app.scanner.models import ScanContext, ScanStatus
from app.scanner.scoring import (
    CATEGORY_BUDGETS,
    CHECK_CATALOG,
    CHECKS_BY_ID,
    LEGACY_CATALOG_RECONCILIATION,
    MIN_APPLICABLE_POINTS,
    SCORING_CHECKS,
    SCORING_VERSION,
    CategoryState,
    ScoreConfidence,
    _round_half_up,
    _unavailability_reasons,
    score_findings,
)


def make_finding(
    check_id: str,
    status: FindingStatus,
    *,
    evidence: dict[str, object] | None = None,
    severity: Severity = Severity.INFORMATIONAL,
    metadata: dict[str, object] | None = None,
) -> Finding:
    definition = CHECKS_BY_ID[check_id]
    return Finding(
        check_id=check_id,
        title=definition.name,
        severity=severity,
        category=definition.category,
        status=status,
        summary="Deterministic test observation.",
        why_it_matters="Test fixture.",
        evidence=evidence or {},
        remediation="Test fixture.",
        affected_url="https://site.example/",
        metadata=metadata or {},
    )


def passing_findings(*, diagnostics: bool = False) -> list[Finding]:
    findings = [
        make_finding("transport.https", FindingStatus.PASS, evidence={"final_scheme": "https"}),
        make_finding(
            "headers.hsts",
            FindingStatus.PASS,
            evidence={"final_scheme": "https", "header_present": True, "header_count": 1, "max_age": 31_536_000, "parse_errors": ()},
        ),
        make_finding(
            "headers.csp",
            FindingStatus.PASS,
            evidence={
                "header_present": True,
                "header_count": 1,
                "unsafe_inline_observed": False,
                "unsafe_eval_observed": False,
                "broad_source_kinds": (),
                "malformed_policy_count": 0,
                "duplicate_directives": (),
            },
        ),
        make_finding(
            "headers.x_content_type_options",
            FindingStatus.PASS,
            evidence={"header_present": True, "header_count": 1, "nosniff_values": 1, "unexpected_value_count": 0},
        ),
        make_finding(
            "headers.referrer_policy",
            FindingStatus.PASS,
            evidence={
                "header_present": True,
                "recognized_policies": ("strict-origin-when-cross-origin",),
                "effective_policy_candidate": "strict-origin-when-cross-origin",
                "weaker_policy_candidate": False,
                "unrecognized_token_count": 0,
            },
        ),
        make_finding(
            "headers.permissions_policy",
            FindingStatus.PASS,
            evidence={"header_present": True, "header_count": 1, "directive_names": (), "parse_errors": ()},
        ),
        make_finding(
            "headers.frame_protection",
            FindingStatus.PASS,
            evidence={
                "x_frame_options_present": False,
                "x_frame_options_count": 0,
                "x_frame_options_recognized": None,
                "x_frame_options_allow_from_observed": False,
                "csp_frame_ancestors_present": True,
                "csp_frame_ancestors_restrictive_observed": True,
                "protection_observed_via": ("csp-frame-ancestors",),
            },
        ),
        make_finding(
            "cookies.security_attributes",
            FindingStatus.PASS,
            evidence={
                "set_cookie_header_count": 1,
                "cookie_count": 1,
                "malformed_set_cookie_header_count": 0,
                "secure_missing_cookie_names": (),
                "same_site_none_without_secure_cookie_names": (),
                "domain_scope_outside_target_cookie_names": (),
                "prefix_requirement_violation_cookie_names": (),
                "same_site_missing_cookie_names": (),
                "same_site_invalid_cookie_names": (),
                "http_only_missing_sensitive_name_candidates": (),
                "invalid_attribute_cookie_names": (),
            },
        ),
        make_finding(
            "content.mixed_http_resources",
            FindingStatus.PASS,
            evidence={
                "final_scheme": "https",
                "body_inspected": True,
                "body_analysis_truncated": False,
                "reference_scan_truncated": False,
                "detected_reference_count": 0,
                "resource_type_counts": (),
            },
        ),
    ]
    if diagnostics:
        findings.extend(
            [
                make_finding("transport.http_to_https_redirect", FindingStatus.FAIL),
                make_finding("transport.final_scheme", FindingStatus.WARN),
                make_finding("exposure.server_headers", FindingStatus.WARN),
                make_finding("technology.passive_indicators", FindingStatus.PASS),
            ]
        )
    return findings


def find_check(result, check_id: str):
    return next(check for check in result.checks if check.check_id == check_id)


class ScoringCatalogTests(unittest.TestCase):
    def test_catalog_has_all_13_canonical_ids_and_only_nine_score_checks(self) -> None:
        self.assertEqual(len(CHECK_CATALOG), 13)
        self.assertEqual(len(SCORING_CHECKS), 9)
        self.assertEqual(
            sum(definition.points for definition in SCORING_CHECKS if definition.category == FindingCategory.TRANSPORT),
            CATEGORY_BUDGETS[FindingCategory.TRANSPORT],
        )
        for category, budget in CATEGORY_BUDGETS.items():
            self.assertEqual(sum(check.points for check in SCORING_CHECKS if check.category == category), budget)
        self.assertEqual(sum(CATEGORY_BUDGETS.values()), 100)

    def test_legacy_reconciliation_is_explicit_and_only_two_ids_are_new(self) -> None:
        self.assertEqual(
            dict(LEGACY_CATALOG_RECONCILIATION),
            {
                "https": "transport.https",
                "http_to_https": "transport.http_to_https_redirect",
                "hsts": "headers.hsts",
                "csp": "headers.csp",
                "x_content_type_options": "headers.x_content_type_options",
                "referrer_policy": "headers.referrer_policy",
                "permissions_policy": "headers.permissions_policy",
                "frame_protection": "headers.frame_protection",
                "server_header": "exposure.server_headers",
                "secure_cookies": "cookies.security_attributes",
                "mixed_content": "content.mixed_http_resources",
            },
        )
        self.assertEqual(
            {item.check_id for item in CHECK_CATALOG if item.legacy_catalog_id is None},
            {"transport.final_scheme", "technology.passive_indicators"},
        )

    def test_legacy_catalog_ids_are_not_silently_accepted_as_scoring_aliases(self) -> None:
        legacy_finding = Finding(
            check_id="https",
            title="Legacy HTTPS",
            severity=Severity.HIGH,
            category=FindingCategory.TRANSPORT,
            status=FindingStatus.FAIL,
            summary="Legacy ID.",
            why_it_matters="Test.",
            evidence={},
            remediation="Test.",
            affected_url="https://site.example/",
        )
        with self.assertRaisesRegex(ValueError, "not score aliases"):
            score_findings([legacy_finding])


class ScoringMethodologyTests(unittest.TestCase):
    def test_actual_phase_4b_4c_findings_score_without_changing_scanner_behavior(self) -> None:
        url = "https://site.example/"
        cookies, malformed = parse_set_cookie_headers(
            ("sessionid=discard-me; Secure; HttpOnly; SameSite=Lax; Path=/",),
            target_url=url,
        )
        body = b"<html><head></head><body>ok</body></html>"
        context = ScanContext(
            requested_url=url,
            status=ScanStatus.COMPLETED,
            normalized_url=url,
            current_url=url,
            hostname="site.example",
            scheme="https",
            port=443,
            http_status=200,
            response_headers=(
                ("content-type", "text/html; charset=utf-8"),
                ("strict-transport-security", "max-age=31536000"),
                ("content-security-policy", "default-src 'self'; frame-ancestors 'self'"),
                ("x-content-type-options", "nosniff"),
                ("referrer-policy", "strict-origin-when-cross-origin"),
                ("permissions-policy", "camera=()"),
                ("x-frame-options", "SAMEORIGIN"),
            ),
            response_cookies=cookies,
            malformed_cookie_header_count=malformed,
            set_cookie_header_count=1,
            response_body=body,
            response_body_bytes=len(body),
            response_body_complete=True,
        )
        findings = run_security_checks(context)
        self.assertEqual({finding.check_id for finding in findings}, set(CHECKS_BY_ID))
        result = score_findings(findings)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.confidence, ScoreConfidence.COMPLETE)

    def test_perfect_applicable_configuration_is_100_complete(self) -> None:
        result = score_findings(passing_findings(diagnostics=True))
        self.assertEqual(result.score, 100)
        self.assertTrue(result.available)
        self.assertEqual(result.scoring_version, "1.0")
        self.assertEqual(result.scoring_version, SCORING_VERSION)
        self.assertEqual(result.confidence, ScoreConfidence.COMPLETE)
        self.assertEqual(result.applicable_points, 100)
        self.assertEqual(result.resolved_points, 100)
        self.assertEqual(result.deductions, 0)
        self.assertEqual(result.applicable_checks, 9)
        self.assertEqual(result.resolved_checks, 9)

    def test_exact_mixed_configuration_example_from_scoring_design(self) -> None:
        findings = [
            make_finding("transport.https", FindingStatus.FAIL, evidence={"final_scheme": "http"}),
            make_finding("headers.hsts", FindingStatus.NOT_APPLICABLE, evidence={"final_scheme": "http"}),
            make_finding("headers.csp", FindingStatus.FAIL, evidence={"header_present": False}),
            make_finding("headers.x_content_type_options", FindingStatus.FAIL, evidence={"header_present": False}),
            make_finding(
                "headers.referrer_policy",
                FindingStatus.WARN,
                evidence={"header_present": True, "effective_policy_candidate": "unsafe-url"},
            ),
            make_finding("headers.permissions_policy", FindingStatus.FAIL, evidence={"header_present": False}),
            make_finding(
                "headers.frame_protection",
                FindingStatus.FAIL,
                evidence={
                    "x_frame_options_present": False,
                    "csp_frame_ancestors_restrictive_observed": False,
                    "protection_observed_via": (),
                },
            ),
            make_finding(
                "cookies.security_attributes",
                FindingStatus.WARN,
                evidence={
                    "set_cookie_header_count": 1,
                    "cookie_count": 1,
                    "malformed_set_cookie_header_count": 0,
                    "secure_missing_cookie_names": (),
                    "same_site_none_without_secure_cookie_names": ("session",),
                    "domain_scope_outside_target_cookie_names": (),
                    "prefix_requirement_violation_cookie_names": (),
                    "same_site_missing_cookie_names": (),
                    "same_site_invalid_cookie_names": (),
                    "http_only_missing_sensitive_name_candidates": (),
                    "invalid_attribute_cookie_names": (),
                },
            ),
            make_finding(
                "content.mixed_http_resources",
                FindingStatus.NOT_APPLICABLE,
                evidence={"final_scheme": "http", "body_inspected": False},
            ),
            # The redirect failure is diagnostic-only and is deliberately not scored.
            make_finding("transport.http_to_https_redirect", FindingStatus.FAIL),
        ]
        result = score_findings(findings)
        self.assertEqual(result.score, 6)
        self.assertEqual(result.confidence, ScoreConfidence.COMPLETE)
        self.assertEqual((result.applicable_points, result.resolved_points, result.deductions), (78, 78, 73))
        self.assertEqual((result.applicable_checks, result.resolved_checks), (7, 7))
        self.assertEqual(find_check(result, "transport.http_to_https_redirect").deduction_points, 0)
        self.assertEqual(
            result.weakest_categories[:2],
            (FindingCategory.TRANSPORT, FindingCategory.HEADERS),
        )
        self.assertEqual(result.checks[0].check_id, "transport.https")

    def test_exact_limited_incomplete_example_from_scoring_design(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id not in {"headers.csp", "cookies.security_attributes", "content.mixed_http_resources"}]
        findings.extend(
            [
                make_finding("headers.csp", FindingStatus.ERROR, evidence={"error_code": "scanner_failure"}),
                make_finding("cookies.security_attributes", FindingStatus.ERROR, evidence={}),
                make_finding(
                    "content.mixed_http_resources",
                    FindingStatus.NOT_APPLICABLE,
                    evidence={"final_scheme": "https", "body_available": True, "body_complete": False, "body_inspected": False},
                ),
            ]
        )
        result = score_findings(findings)
        self.assertIsNone(result.score)
        self.assertFalse(result.available)
        self.assertEqual(result.confidence, ScoreConfidence.LIMITED)
        self.assertEqual((result.applicable_points, result.resolved_points), (100, 61))
        self.assertEqual((result.applicable_checks, result.resolved_checks), (9, 6))
        self.assertIn("incomplete_scan", result.unavailability_reasons)
        self.assertEqual(find_check(result, "content.mixed_http_resources").state, "unresolved")

    def test_exact_partial_confidence_contrast_from_scoring_design(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id not in {"cookies.security_attributes", "content.mixed_http_resources"}]
        findings.extend(
            [
                make_finding(
                    "cookies.security_attributes",
                    FindingStatus.NOT_APPLICABLE,
                    evidence={"set_cookie_header_count": 0, "cookie_count": 0},
                ),
                make_finding(
                    "content.mixed_http_resources",
                    FindingStatus.WARN,
                    evidence={
                        "final_scheme": "https",
                        "body_inspected": True,
                        "body_analysis_truncated": True,
                        "reference_scan_truncated": False,
                        "detected_reference_count": 0,
                        "resource_type_counts": (),
                    },
                ),
            ]
        )
        result = score_findings(findings)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.confidence, ScoreConfidence.PARTIAL)
        self.assertEqual((result.applicable_points, result.resolved_points), (85, 75))
        self.assertEqual((result.applicable_checks, result.resolved_checks), (8, 7))
        self.assertAlmostEqual(result.point_coverage_percent, 88.24)
        self.assertEqual(result.check_coverage_percent, 87.5)

    def test_all_nine_check_ceilings_sum_to_zero_score_when_each_fails(self) -> None:
        findings = [
            make_finding("transport.https", FindingStatus.FAIL, evidence={"final_scheme": "http"}),
            make_finding("headers.hsts", FindingStatus.FAIL, evidence={"final_scheme": "https", "header_present": False}),
            make_finding("headers.csp", FindingStatus.FAIL, evidence={"header_present": False}),
            make_finding("headers.x_content_type_options", FindingStatus.FAIL, evidence={"header_present": False}),
            make_finding("headers.referrer_policy", FindingStatus.FAIL, evidence={"header_present": False}),
            make_finding("headers.permissions_policy", FindingStatus.FAIL, evidence={"header_present": False}),
            make_finding(
                "headers.frame_protection",
                FindingStatus.FAIL,
                evidence={"x_frame_options_present": False, "csp_frame_ancestors_restrictive_observed": False, "protection_observed_via": ()},
            ),
            make_finding(
                "cookies.security_attributes",
                FindingStatus.WARN,
                evidence={
                    "set_cookie_header_count": 1,
                    "cookie_count": 1,
                    "malformed_set_cookie_header_count": 1,
                    "secure_missing_cookie_names": ("session",),
                    "same_site_none_without_secure_cookie_names": (),
                    "domain_scope_outside_target_cookie_names": ("session",),
                    "prefix_requirement_violation_cookie_names": (),
                    "same_site_missing_cookie_names": ("session",),
                    "same_site_invalid_cookie_names": (),
                    "http_only_missing_sensitive_name_candidates": (),
                    "invalid_attribute_cookie_names": (),
                },
            ),
            make_finding(
                "content.mixed_http_resources",
                FindingStatus.WARN,
                evidence={
                    "detected_reference_count": 50,
                    "resource_type_counts": (("script", 50),),
                    "body_inspected": True,
                    "body_analysis_truncated": False,
                    "reference_scan_truncated": False,
                },
            ),
        ]
        result = score_findings(findings)
        self.assertEqual(result.score, 0)
        self.assertEqual((result.resolved_points, result.deductions), (100, 100))

    def test_each_category_breakdown_matches_documented_deductions(self) -> None:
        result = score_findings(
            [
                make_finding("transport.https", FindingStatus.FAIL, evidence={"final_scheme": "http"}),
                make_finding("headers.hsts", FindingStatus.WARN, evidence={"final_scheme": "https", "header_present": True, "header_count": 1, "max_age": 1, "parse_errors": ("duplicate_header",)}),
                make_finding("headers.csp", FindingStatus.WARN, evidence={"header_present": True, "unsafe_inline_observed": True, "malformed_policy_count": 1, "duplicate_directives": ("script-src",)}),
                make_finding("headers.x_content_type_options", FindingStatus.FAIL, evidence={"header_present": True, "unexpected_value_count": 1}),
                make_finding("headers.referrer_policy", FindingStatus.WARN, evidence={"header_present": True, "effective_policy_candidate": "origin-when-cross-origin", "recognized_policies": ("origin-when-cross-origin",), "unrecognized_token_count": 1}),
                make_finding("headers.permissions_policy", FindingStatus.WARN, evidence={"header_present": True, "header_count": 1, "parse_errors": ("invalid",)}),
                make_finding("headers.frame_protection", FindingStatus.WARN, evidence={"x_frame_options_present": True, "x_frame_options_count": 1, "x_frame_options_recognized": None, "x_frame_options_allow_from_observed": True, "csp_frame_ancestors_restrictive_observed": False, "protection_observed_via": ()}),
                make_finding(
                    "cookies.security_attributes",
                    FindingStatus.WARN,
                    evidence={
                        "set_cookie_header_count": 1,
                        "malformed_set_cookie_header_count": 0,
                        "secure_missing_cookie_names": ("session",),
                        "same_site_none_without_secure_cookie_names": (),
                        "domain_scope_outside_target_cookie_names": (),
                        "prefix_requirement_violation_cookie_names": (),
                        "same_site_missing_cookie_names": (),
                        "same_site_invalid_cookie_names": (),
                        "http_only_missing_sensitive_name_candidates": (),
                        "invalid_attribute_cookie_names": (),
                    },
                ),
                make_finding("content.mixed_http_resources", FindingStatus.WARN, evidence={"detected_reference_count": 1, "resource_type_counts": (("image", 1),), "body_inspected": True, "body_analysis_truncated": False, "reference_scan_truncated": False}),
            ]
        )
        categories = {category.category: category for category in result.categories}
        self.assertEqual(categories[FindingCategory.TRANSPORT].deductions, 30)
        self.assertEqual(categories[FindingCategory.HEADERS].deductions, 6 + 9 + 4 + 1 + 2 + 5)
        self.assertEqual(categories[FindingCategory.COOKIES].deductions, 10)
        self.assertEqual(categories[FindingCategory.CONTENT].deductions, 5)
        for category, budget in CATEGORY_BUDGETS.items():
            self.assertLessEqual(categories[category].resulting_points, budget)
            self.assertGreaterEqual(categories[category].resulting_points, 0)

    def test_csp_uses_strongest_warning_not_sum_of_weaknesses(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id != "headers.csp"]
        findings.append(
            make_finding(
                "headers.csp",
                FindingStatus.WARN,
                evidence={"header_present": True, "unsafe_inline_observed": True, "unsafe_eval_observed": True, "broad_source_kinds": ("star",), "malformed_policy_count": 4, "duplicate_directives": ("script-src",)},
            )
        )
        result = score_findings(findings)
        self.assertEqual(find_check(result, "headers.csp").deduction_points, 9)

    def test_cookie_issue_classes_and_many_cookies_are_aggregated_and_capped(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id != "cookies.security_attributes"]
        findings.append(
            make_finding(
                "cookies.security_attributes",
                FindingStatus.WARN,
                evidence={
                    "set_cookie_header_count": 50,
                    "cookie_count": 50,
                    "malformed_set_cookie_header_count": 20,
                    "secure_missing_cookie_names": tuple(f"session-{i}" for i in range(50)),
                    "same_site_none_without_secure_cookie_names": tuple(f"none-{i}" for i in range(50)),
                    "domain_scope_outside_target_cookie_names": tuple(f"domain-{i}" for i in range(50)),
                    "prefix_requirement_violation_cookie_names": tuple(f"prefix-{i}" for i in range(50)),
                    "same_site_missing_cookie_names": tuple(f"same-site-{i}" for i in range(50)),
                    "same_site_invalid_cookie_names": (),
                    "http_only_missing_sensitive_name_candidates": (),
                    "invalid_attribute_cookie_names": (),
                },
            )
        )
        result = score_findings(findings)
        self.assertEqual(find_check(result, "cookies.security_attributes").deduction_points, 15)

    def test_multiple_active_content_references_are_one_check_deduction(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id != "content.mixed_http_resources"]
        findings.append(
            make_finding(
                "content.mixed_http_resources",
                FindingStatus.WARN,
                evidence={"detected_reference_count": 512, "resource_type_counts": (("script", 511), ("iframe", 1)), "body_inspected": True, "body_analysis_truncated": True, "reference_scan_truncated": True},
            )
        )
        result = score_findings(findings)
        check = find_check(result, "content.mixed_http_resources")
        self.assertEqual(check.deduction_points, 10)
        self.assertEqual(result.confidence, ScoreConfidence.PARTIAL)
        self.assertTrue(check.partial_evidence)

    def test_legitimate_not_applicable_excludes_weight_but_incomplete_does_not(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id not in {"headers.hsts", "cookies.security_attributes", "content.mixed_http_resources"}]
        findings.extend(
            [
                make_finding("headers.hsts", FindingStatus.NOT_APPLICABLE, evidence={"final_scheme": "http"}),
                make_finding("cookies.security_attributes", FindingStatus.NOT_APPLICABLE, evidence={"set_cookie_header_count": 0, "cookie_count": 0}),
                make_finding("content.mixed_http_resources", FindingStatus.NOT_APPLICABLE, evidence={"final_scheme": "https", "body_available": True, "body_complete": False, "body_inspected": False}),
            ]
        )
        result = score_findings(findings)
        self.assertEqual(result.applicable_points, 73)
        self.assertEqual(find_check(result, "headers.hsts").state, "not_applicable")
        self.assertEqual(find_check(result, "cookies.security_attributes").state, "not_applicable")
        self.assertEqual(find_check(result, "content.mixed_http_resources").state, "unresolved")
        self.assertEqual(find_check(result, "content.mixed_http_resources").applicable_points, 10)

    def test_scanner_errors_do_not_deduct_and_reduce_coverage(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id != "headers.csp"]
        findings.append(make_finding("headers.csp", FindingStatus.ERROR, evidence={"error_code": "scanner_failure"}))
        result = score_findings(findings)
        self.assertEqual(find_check(result, "headers.csp").deduction_points, 0)
        self.assertEqual(find_check(result, "headers.csp").resolved_points, 0)
        self.assertEqual((result.applicable_points, result.resolved_points), (100, 86))
        self.assertEqual(result.score, 100)
        self.assertEqual(result.confidence, ScoreConfidence.PARTIAL)

    def test_missing_results_are_not_passes_and_report_incomplete_scan(self) -> None:
        result = score_findings([])
        self.assertIsNone(result.score)
        self.assertEqual(result.confidence, ScoreConfidence.LIMITED)
        self.assertEqual(result.resolved_points, 0)
        self.assertIn("incomplete_scan", result.unavailability_reasons)
        self.assertEqual(find_check(result, "transport.https").reason_code, "missing_result")

    def test_insufficient_applicable_points_availability_guard(self) -> None:
        # Current legitimate NA combinations leave at least 63 points. Exercise
        # the documented forward-compatible <60 guard directly at its boundary.
        self.assertEqual(MIN_APPLICABLE_POINTS, 60)
        reasons = _unavailability_reasons(
            applicable_points=59,
            resolved_points=59,
            applicable_checks=1,
            resolved_checks=1,
            has_unresolved=False,
        )
        self.assertEqual(reasons, ("insufficient_applicable_points",))

    def test_exact_eighty_percent_coverage_is_sufficient(self) -> None:
        reasons = _unavailability_reasons(
            applicable_points=100,
            resolved_points=80,
            applicable_checks=5,
            resolved_checks=4,
            has_unresolved=True,
        )
        self.assertEqual(reasons, ())

    def test_check_count_coverage_gate_can_fail_while_point_coverage_passes(self) -> None:
        findings = passing_findings()
        findings = [
            finding
            for finding in findings
            if finding.check_id not in {"headers.referrer_policy", "headers.permissions_policy"}
        ]
        findings.extend(
            [
                make_finding("headers.referrer_policy", FindingStatus.ERROR),
                make_finding("headers.permissions_policy", FindingStatus.ERROR),
            ]
        )
        result = score_findings(findings)
        self.assertIsNone(result.score)
        self.assertEqual(result.point_coverage_percent, 94.0)
        self.assertAlmostEqual(result.check_coverage_percent, 77.78)
        self.assertEqual(
            result.unavailability_reasons,
            ("insufficient_check_coverage", "incomplete_scan"),
        )

    def test_point_coverage_gate_can_fail_while_check_count_passes(self) -> None:
        findings = passing_findings()
        findings = [finding for finding in findings if finding.check_id != "transport.https"]
        findings.append(make_finding("transport.https", FindingStatus.ERROR))
        result = score_findings(findings)
        self.assertIsNone(result.score)
        self.assertEqual(result.point_coverage_percent, 70.0)
        self.assertEqual(result.check_coverage_percent, 88.89)
        self.assertEqual(
            result.unavailability_reasons,
            ("insufficient_point_coverage", "incomplete_scan"),
        )

    def test_exact_half_points_round_up(self) -> None:
        self.assertEqual(_round_half_up(13, 2), 7)

    def test_incomplete_scan_reason_is_added_when_coverage_withholds_score(self) -> None:
        reasons = _unavailability_reasons(
            applicable_points=100,
            resolved_points=60,
            applicable_checks=9,
            resolved_checks=5,
            has_unresolved=True,
        )
        self.assertEqual(
            reasons,
            ("insufficient_point_coverage", "insufficient_check_coverage", "incomplete_scan"),
        )

    def test_duplicate_identical_findings_do_not_multiply_deductions(self) -> None:
        findings = passing_findings()
        csp = next(finding for finding in findings if finding.check_id == "headers.csp")
        baseline = score_findings(findings)
        duplicate_result = score_findings([*findings, csp, csp])
        self.assertEqual(duplicate_result, baseline)

    def test_conflicting_duplicate_findings_become_unresolved_not_double_penalty(self) -> None:
        findings = passing_findings()
        csp = next(finding for finding in findings if finding.check_id == "headers.csp")
        conflicting = make_finding("headers.csp", FindingStatus.FAIL, evidence={"header_present": False})
        result = score_findings([*findings, conflicting])
        self.assertEqual(find_check(result, "headers.csp").reason_code, "conflicting_duplicate_results")
        self.assertEqual(find_check(result, "headers.csp").deduction_points, 0)
        self.assertEqual(result.deductions, 0)
        self.assertEqual(result.confidence, ScoreConfidence.PARTIAL)
        self.assertEqual(result.score, 100)

    def test_severity_does_not_change_score_or_turn_duplicates_into_conflicts(self) -> None:
        findings = passing_findings()
        csp = next(finding for finding in findings if finding.check_id == "headers.csp")
        severity_variant = make_finding(
            csp.check_id,
            csp.status,
            evidence=dict(csp.evidence),
            severity=Severity.HIGH,
        )
        baseline = score_findings(findings)
        changed = score_findings([*findings, severity_variant])
        self.assertEqual((changed.score, changed.deductions), (baseline.score, baseline.deductions))
        self.assertEqual(find_check(changed, "headers.csp").reason_code, "csp_parseable_observed")

    def test_unsupported_check_version_is_unresolved(self) -> None:
        findings = passing_findings()
        hsts = next(finding for finding in findings if finding.check_id == "headers.hsts")
        findings = [finding for finding in findings if finding.check_id != "headers.hsts"]
        findings.append(
            make_finding(
                hsts.check_id,
                hsts.status,
                evidence=dict(hsts.evidence),
                metadata={"check_version": "2"},
            )
        )
        result = score_findings(findings)
        check = find_check(result, "headers.hsts")
        self.assertEqual(check.reason_code, "unsupported_check_version")
        self.assertEqual(check.resolved_points, 0)
        self.assertEqual(result.confidence, ScoreConfidence.PARTIAL)

    def test_informational_and_diagnostic_checks_do_not_change_score(self) -> None:
        baseline = score_findings(passing_findings())
        with_informational = score_findings(passing_findings(diagnostics=True))
        self.assertEqual(
            (with_informational.score, with_informational.available, with_informational.deductions),
            (baseline.score, baseline.available, baseline.deductions),
        )
        self.assertEqual(find_check(with_informational, "transport.http_to_https_redirect").reason_code, "diagnostic_only")
        self.assertEqual(find_check(with_informational, "transport.final_scheme").reason_code, "diagnostic_only")
        self.assertEqual(find_check(with_informational, "exposure.server_headers").reason_code, "informational_only")
        self.assertEqual(find_check(with_informational, "technology.passive_indicators").reason_code, "informational_only")

    def test_deterministic_output_and_no_network_access(self) -> None:
        findings = passing_findings(diagnostics=True)
        expected = score_findings(findings).to_dict()
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS was accessed")), patch.object(
            socket, "socket", side_effect=AssertionError("socket was opened")
        ):
            first = score_findings(findings).to_dict()
            second = score_findings(findings).to_dict()
        self.assertEqual(first, expected)
        self.assertEqual(second, expected)

    def test_status_and_reason_explanation_is_structured(self) -> None:
        result = score_findings(passing_findings(diagnostics=True))
        serialized = result.to_dict()
        self.assertIn("categories", serialized)
        self.assertIn("checks", serialized)
        self.assertEqual(len(serialized["categories"]), 4)
        self.assertEqual(
            {category["state"] for category in serialized["categories"]},
            {CategoryState.COMPLETE.value},
        )
        self.assertTrue(all("reason_code" in check and "evidence_reference" in check for check in serialized["checks"]))

    def test_score_and_category_invariants_across_representative_results(self) -> None:
        result_set = [score_findings(passing_findings())]
        result_set.append(score_findings([]))
        result_set.append(
            score_findings(
                [make_finding("transport.https", FindingStatus.FAIL, evidence={"final_scheme": "http"})]
            )
        )
        for result in result_set:
            if result.score is not None:
                self.assertGreaterEqual(result.score, 0)
                self.assertLessEqual(result.score, 100)
            for category in result.categories:
                self.assertLessEqual(category.available_points, category.budget_points)
                self.assertLessEqual(category.resulting_points, category.budget_points)
                self.assertGreaterEqual(category.resulting_points, 0)


if __name__ == "__main__":
    unittest.main()
