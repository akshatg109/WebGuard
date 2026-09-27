import unittest
from urllib.parse import urlsplit

from app.scanner.checks.base import BaseCheck
from app.scanner.checks.header_checks import (
    ContentSecurityPolicyCheck,
    FrameProtectionCheck,
    HstsCheck,
    PermissionsPolicyCheck,
    ReferrerPolicyCheck,
    ServerInformationExposureCheck,
    XContentTypeOptionsCheck,
)
from app.scanner.checks.registry import (
    DEFAULT_CHECKS,
    DEFAULT_ENGINE,
    CheckEngine,
    CheckRegistry,
    run_security_checks,
)
from app.scanner.checks.transport import FinalUrlSchemeCheck, HttpsAvailabilityCheck, HttpToHttpsRedirectCheck
from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity
from app.scanner.models import RedirectHop, ScanContext, ScanStatus


def scan_context(
    requested_url: str = "https://site.example.com/?access_token=private",
    *,
    final_url: str | None = None,
    headers: tuple[tuple[str, str], ...] = (),
    redirects: tuple[RedirectHop, ...] = (),
    status: ScanStatus = ScanStatus.COMPLETED,
    http_status: int | None = 200,
) -> ScanContext:
    final = final_url or requested_url
    final_parts = urlsplit(final)
    requested_parts = urlsplit(requested_url)
    return ScanContext(
        requested_url=requested_url,
        status=status,
        normalized_url=requested_url,
        current_url=final,
        hostname=final_parts.hostname,
        scheme=final_parts.scheme,
        port=final_parts.port or (443 if final_parts.scheme == "https" else 80),
        redirect_chain=list(redirects),
        http_status=http_status,
        response_headers=headers,
        response_body=b"<html></html>",
        response_body_bytes=13,
        response_body_complete=True,
    )


def run_one(check: BaseCheck, context: ScanContext) -> Finding:
    findings = check.run(context)
    if len(findings) != 1:
        raise AssertionError(f"Expected exactly one finding from {check.check_id}, received {len(findings)}")
    return findings[0]


class TransportCheckTests(unittest.TestCase):
    def test_https_final_destination_passes_without_claiming_site_is_secure(self) -> None:
        finding = run_one(HttpsAvailabilityCheck(), scan_context())
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.severity, Severity.INFORMATIONAL)
        self.assertIn("does not establish", finding.summary)

    def test_http_final_destination_fails_https_availability(self) -> None:
        context = scan_context(
            "http://site.example.com/",
            final_url="http://site.example.com/",
        )
        finding = run_one(HttpsAvailabilityCheck(), context)
        self.assertEqual(finding.status, FindingStatus.FAIL)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.evidence["final_scheme"], "http")

    def test_http_to_https_redirect_is_detected(self) -> None:
        context = scan_context(
            "http://site.example.com/",
            final_url="https://site.example.com/",
            redirects=(RedirectHop("http://site.example.com/", 301, "https://site.example.com/", "https://site.example.com/"),),
        )
        finding = run_one(HttpToHttpsRedirectCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertTrue(finding.evidence["https_upgrade_observed"])

    def test_http_to_http_final_destination_fails_redirect_check(self) -> None:
        context = scan_context("http://site.example.com/", final_url="http://site.example.com/home")
        finding = run_one(HttpToHttpsRedirectCheck(), context)
        self.assertEqual(finding.status, FindingStatus.FAIL)
        self.assertEqual(finding.evidence["redirect_count"], 0)

    def test_https_request_makes_http_upgrade_check_not_applicable(self) -> None:
        finding = run_one(HttpToHttpsRedirectCheck(), scan_context())
        self.assertEqual(finding.status, FindingStatus.NOT_APPLICABLE)

    def test_final_scheme_is_an_observation(self) -> None:
        finding = run_one(FinalUrlSchemeCheck(), scan_context())
        self.assertEqual(finding.check_id, "transport.final_scheme")
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["final_scheme"], "https")

    def test_final_http_scheme_is_warned_without_numeric_score(self) -> None:
        context = scan_context("http://site.example.com/", final_url="http://site.example.com/")
        finding = run_one(FinalUrlSchemeCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.severity, Severity.INFORMATIONAL)
        self.assertEqual(finding.evidence["final_scheme"], "http")


class HstsCheckTests(unittest.TestCase):
    def test_missing_hsts_on_https_fails(self) -> None:
        finding = run_one(HstsCheck(), scan_context())
        self.assertEqual(finding.status, FindingStatus.FAIL)
        self.assertFalse(finding.evidence["header_present"])

    def test_missing_hsts_on_http_is_not_applicable(self) -> None:
        context = scan_context("http://site.example.com/", final_url="http://site.example.com/")
        finding = run_one(HstsCheck(), context)
        self.assertEqual(finding.status, FindingStatus.NOT_APPLICABLE)

    def test_hsts_directives_are_parsed_without_preload_claim(self) -> None:
        context = scan_context(headers=(("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),))
        finding = run_one(HstsCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["max_age"], 31_536_000)
        self.assertTrue(finding.evidence["include_subdomains"])
        self.assertTrue(finding.evidence["preload_token_present"])
        self.assertFalse(finding.evidence["preload_eligibility_checked"])

    def test_hsts_malformed_max_age_warns(self) -> None:
        context = scan_context(headers=(("strict-transport-security", "max-age=forever"),))
        finding = run_one(HstsCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertIn("invalid_max_age", finding.evidence["parse_errors"])

    def test_hsts_duplicate_case_insensitive_headers_warn(self) -> None:
        context = scan_context(
            headers=(
                ("Strict-Transport-Security", "max-age=100"),
                ("strict-transport-security", "max-age=200"),
            )
        )
        finding = run_one(HstsCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.evidence["header_count"], 2)


class ContentSecurityPolicyCheckTests(unittest.TestCase):
    def test_missing_csp_fails(self) -> None:
        finding = run_one(ContentSecurityPolicyCheck(), scan_context())
        self.assertEqual(finding.status, FindingStatus.FAIL)
        self.assertFalse(finding.evidence["header_present"])

    def test_basic_parseable_csp_passes_without_overclaim(self) -> None:
        context = scan_context(headers=(("Content-Security-Policy", "default-src 'self'; object-src 'none'"),))
        finding = run_one(ContentSecurityPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertTrue(finding.evidence["default_src_present"])
        self.assertIn("does not prove", finding.summary)

    def test_unsafe_inline_and_eval_are_distinguished(self) -> None:
        context = scan_context(headers=(("content-security-policy", "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"),))
        finding = run_one(ContentSecurityPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertTrue(finding.evidence["unsafe_inline_observed"])
        self.assertTrue(finding.evidence["unsafe_eval_observed"])

    def test_wildcard_and_scheme_wide_sources_are_distinguished(self) -> None:
        context = scan_context(headers=(("Content-Security-Policy", "default-src * https:"),))
        finding = run_one(ContentSecurityPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.evidence["broad_source_kinds"], ("*", "https:"))

    def test_malformed_csp_is_reported(self) -> None:
        context = scan_context(headers=(("Content-Security-Policy", "default-src 'self"),))
        finding = run_one(ContentSecurityPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.evidence["malformed_policy_count"], 1)

    def test_empty_csp_policy_is_malformed(self) -> None:
        context = scan_context(headers=(("Content-Security-Policy", "; ;"),))
        finding = run_one(ContentSecurityPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.evidence["malformed_policy_count"], 1)

    def test_duplicate_case_insensitive_csp_headers_are_preserved(self) -> None:
        context = scan_context(
            headers=(
                ("Content-Security-Policy", "default-src 'self'"),
                ("content-security-policy", "object-src 'none'"),
            )
        )
        finding = run_one(ContentSecurityPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["header_count"], 2)
        self.assertEqual(finding.evidence["directive_names"], ("default-src", "object-src"))


class XContentTypeOptionsCheckTests(unittest.TestCase):
    def test_missing_header_fails(self) -> None:
        finding = run_one(XContentTypeOptionsCheck(), scan_context())
        self.assertEqual(finding.status, FindingStatus.FAIL)

    def test_nosniff_is_case_insensitive(self) -> None:
        context = scan_context(headers=(("X-Content-Type-Options", "NOSNIFF"),))
        finding = run_one(XContentTypeOptionsCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)

    def test_duplicate_case_insensitive_values_are_all_checked(self) -> None:
        context = scan_context(
            headers=(("X-Content-Type-Options", "nosniff"), ("x-content-type-options", "other"))
        )
        finding = run_one(XContentTypeOptionsCheck(), context)
        self.assertEqual(finding.status, FindingStatus.FAIL)
        self.assertEqual(finding.evidence["unexpected_value_count"], 1)


class ReferrerPolicyCheckTests(unittest.TestCase):
    def test_missing_header_fails(self) -> None:
        self.assertEqual(run_one(ReferrerPolicyCheck(), scan_context()).status, FindingStatus.FAIL)

    def test_standard_policies_are_recognized(self) -> None:
        policies = (
            "no-referrer",
            "same-origin",
            "origin",
            "strict-origin",
            "origin-when-cross-origin",
            "strict-origin-when-cross-origin",
        )
        for policy in policies:
            with self.subTest(policy=policy):
                context = scan_context(headers=(("Referrer-Policy", policy),))
                finding = run_one(ReferrerPolicyCheck(), context)
                self.assertEqual(finding.status, FindingStatus.PASS)
                self.assertEqual(finding.evidence["effective_policy_candidate"], policy)

    def test_weak_policies_warn(self) -> None:
        for policy in ("unsafe-url", "no-referrer-when-downgrade"):
            with self.subTest(policy=policy):
                context = scan_context(headers=(("Referrer-Policy", policy),))
                self.assertEqual(run_one(ReferrerPolicyCheck(), context).status, FindingStatus.WARN)

    def test_fallback_list_uses_last_recognized_policy(self) -> None:
        context = scan_context(headers=(("Referrer-Policy", "unsafe-url, no-referrer"),))
        finding = run_one(ReferrerPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["effective_policy_candidate"], "no-referrer")

    def test_malformed_policy_warns_without_echoing_unknown_value(self) -> None:
        context = scan_context(headers=(("Referrer-Policy", "private-token-value"),))
        finding = run_one(ReferrerPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertNotIn("private-token-value", str(finding.to_dict()))


class PermissionsPolicyCheckTests(unittest.TestCase):
    def test_missing_policy_fails(self) -> None:
        self.assertEqual(run_one(PermissionsPolicyCheck(), scan_context()).status, FindingStatus.FAIL)

    def test_present_policy_is_reported_without_claiming_correctness(self) -> None:
        context = scan_context(
            headers=(("Permissions-Policy", "camera=(), geolocation=(self), microphone=(self \"https://media.example.com\")"),)
        )
        finding = run_one(PermissionsPolicyCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["directive_names"], ("camera", "geolocation", "microphone"))
        self.assertIn("not assessed", finding.summary)

    def test_malformed_allowlist_warns(self) -> None:
        for header in ("camera=self", "geolocation=(https://site.example.com", "camera=(not-a-valid-source!)"):
            with self.subTest(header=header):
                context = scan_context(headers=(("Permissions-Policy", header),))
                finding = run_one(PermissionsPolicyCheck(), context)
                self.assertEqual(finding.status, FindingStatus.WARN)


class FrameProtectionCheckTests(unittest.TestCase):
    def test_missing_frame_protection_fails(self) -> None:
        finding = run_one(FrameProtectionCheck(), scan_context())
        self.assertEqual(finding.status, FindingStatus.FAIL)

    def test_x_frame_options_deny_and_sameorigin_pass(self) -> None:
        for value in ("DENY", "SAMEORIGIN"):
            with self.subTest(value=value):
                context = scan_context(headers=(("X-Frame-Options", value),))
                finding = run_one(FrameProtectionCheck(), context)
                self.assertEqual(finding.status, FindingStatus.PASS)
                self.assertEqual(finding.evidence["x_frame_options_recognized"], value)

    def test_invalid_and_allow_from_values_warn(self) -> None:
        for value in ("ALLOW-FROM https://trusted.example.com", "INVALID"):
            with self.subTest(value=value):
                context = scan_context(headers=(("X-Frame-Options", value),))
                finding = run_one(FrameProtectionCheck(), context)
                self.assertEqual(finding.status, FindingStatus.WARN)
                self.assertFalse(finding.evidence["x_frame_options_recognized"])

    def test_csp_frame_ancestors_provides_equivalent_observable_protection(self) -> None:
        context = scan_context(headers=(("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),))
        finding = run_one(FrameProtectionCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertTrue(finding.evidence["csp_frame_ancestors_restrictive_observed"])

    def test_csp_wildcard_frame_ancestors_is_not_counted_as_protection(self) -> None:
        context = scan_context(headers=(("Content-Security-Policy", "frame-ancestors *"),))
        finding = run_one(FrameProtectionCheck(), context)
        self.assertEqual(finding.status, FindingStatus.FAIL)

    def test_both_mechanisms_are_reported_once_as_protected(self) -> None:
        context = scan_context(
            headers=(
                ("X-Frame-Options", "SAMEORIGIN"),
                ("Content-Security-Policy", "frame-ancestors 'self'"),
            )
        )
        finding = run_one(FrameProtectionCheck(), context)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["protection_observed_via"], ("x-frame-options", "csp-frame-ancestors"))


class ServerInformationExposureCheckTests(unittest.TestCase):
    def test_server_and_x_powered_by_versions_are_reported(self) -> None:
        context = scan_context(
            headers=(("Server", "nginx/1.24.0"), ("X-Powered-By", "Express/4.18.2"))
        )
        finding = run_one(ServerInformationExposureCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertTrue(finding.evidence["version_disclosed"])
        self.assertEqual(finding.evidence["server_header_count"], 1)
        self.assertEqual(finding.evidence["x_powered_by_header_count"], 1)

    def test_identifier_without_version_is_informational_not_a_vulnerability_claim(self) -> None:
        context = scan_context(headers=(("Server", "nginx"),))
        finding = run_one(ServerInformationExposureCheck(), context)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.severity, Severity.INFORMATIONAL)
        self.assertIn("not itself a vulnerability", finding.summary)

    def test_no_disclosure_is_pass(self) -> None:
        finding = run_one(ServerInformationExposureCheck(), scan_context())
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertFalse(finding.evidence["version_disclosed"])

    def test_duplicate_headers_are_case_insensitive(self) -> None:
        context = scan_context(headers=(("SERVER", "nginx"), ("server", "Apache/2.4.0")))
        finding = run_one(ServerInformationExposureCheck(), context)
        self.assertEqual(finding.evidence["server_header_count"], 2)


class CheckRegistryTests(unittest.TestCase):
    def test_default_registry_ids_are_stable_unique_and_findings_repeat_deterministically(self) -> None:
        ids = tuple(check.check_id for check in DEFAULT_CHECKS)
        self.assertEqual(len(ids), len(set(ids)))
        first = DEFAULT_ENGINE.evaluate(scan_context())
        second = DEFAULT_ENGINE.evaluate(scan_context())
        self.assertEqual(tuple(finding.to_dict() for finding in first), tuple(finding.to_dict() for finding in second))
        self.assertEqual(tuple(finding.check_id for finding in first), ids)
        self.assertTrue(all(isinstance(finding.severity, Severity) for finding in first))
        self.assertTrue(all(isinstance(finding.status, FindingStatus) for finding in first))
        self.assertTrue(all(finding.why_it_matters and finding.remediation for finding in first))
        self.assertTrue(all("score" not in finding.to_dict() for finding in first))

    def test_finding_affected_url_omits_query_parameters(self) -> None:
        finding = run_one(HttpsAvailabilityCheck(), scan_context())
        self.assertEqual(finding.affected_url, "https://site.example.com/")
        self.assertNotIn("access_token", finding.affected_url)

    def test_error_context_produces_safe_error_findings(self) -> None:
        context = scan_context(status=ScanStatus.FAILED, http_status=None)
        context.error = None
        findings = run_security_checks(context)
        self.assertTrue(findings)
        self.assertTrue(all(finding.status is FindingStatus.ERROR for finding in findings))
        self.assertNotIn("access_token", str([finding.to_dict() for finding in findings]))

    def test_registry_rejects_duplicate_check_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "unique"):
            CheckRegistry((HttpsAvailabilityCheck(), HttpsAvailabilityCheck()))

    def test_finding_rejects_uncontrolled_severity_and_status_strings(self) -> None:
        values = {
            "check_id": "test.controlled",
            "title": "Controlled finding",
            "severity": Severity.LOW,
            "category": FindingCategory.HEADERS,
            "status": FindingStatus.WARN,
            "summary": "A controlled test finding.",
            "why_it_matters": "Tests must not introduce free-form severity labels.",
            "evidence": {},
            "remediation": "Use the enum values.",
            "affected_url": "https://site.example.com/",
        }
        self.assertEqual(Finding(**values).severity, Severity.LOW)
        with self.assertRaisesRegex(TypeError, "controlled Severity"):
            Finding(**{**values, "severity": "critical"})

    def test_check_failure_is_isolated_and_does_not_leak_exception_text(self) -> None:
        class BrokenCheck(BaseCheck):
            check_id = "test.broken"
            name = "Broken check"
            description = "Test-only failure."
            category = FindingCategory.HEADERS
            default_severity = Severity.LOW
            default_why_it_matters = "A failed check cannot make a security conclusion."
            default_remediation = "Retry later."

            def run(self, _context: ScanContext) -> tuple[Finding, ...]:
                raise RuntimeError("secret response data")

        finding = CheckEngine(CheckRegistry((BrokenCheck(),))).evaluate(scan_context())[0]
        self.assertEqual(finding.status, FindingStatus.ERROR)
        self.assertNotIn("secret response data", str(finding.to_dict()))


if __name__ == "__main__":
    unittest.main()
