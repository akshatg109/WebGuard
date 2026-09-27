import unittest
from unittest.mock import patch

from app.scanner.checks import run_security_checks
from app.scanner.checks.content import MixedContentCheck, MAX_HTML_INSPECTION_BYTES
from app.scanner.checks.cookies import CookieSecurityCheck
from app.scanner.checks.header_checks import header_values
from app.scanner.checks.technology import MAX_TECH_HTML_BYTES, TechnologyDetectionCheck, TechnologyDetector
from app.scanner.cookie_metadata import parse_set_cookie_headers
from app.scanner.cookie_metadata import parse_set_cookie_headers
from app.scanner.findings import FindingStatus, Severity
from app.scanner.models import ObservedCookie, ScanContext, ScanStatus


def context(
    *,
    url: str = "https://site.example.com/",
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes | None = b"",
    body_complete: bool = True,
    status: ScanStatus = ScanStatus.COMPLETED,
    http_status: int | None = 200,
) -> ScanContext:
    return ScanContext(
        requested_url=url,
        status=status,
        normalized_url=url,
        current_url=url,
        hostname="site.example.com",
        scheme="https" if url.startswith("https:") else "http",
        port=443 if url.startswith("https:") else 80,
        http_status=http_status,
        response_headers=headers,
        response_body=body,
        response_body_bytes=len(body or b""),
        response_body_complete=body_complete,
    )


def context_with_cookies(
    set_cookie_values: tuple[str, ...],
    *,
    url: str = "https://site.example.com/",
) -> ScanContext:
    cookies, malformed_count = parse_set_cookie_headers(set_cookie_values, target_url=url)
    result = context(url=url)
    result.response_cookies = cookies
    result.set_cookie_header_count = len(set_cookie_values)
    result.malformed_cookie_header_count = malformed_count
    return result


def only_finding(check, scan: ScanContext):
    findings = check.run(scan)
    if len(findings) != 1:
        raise AssertionError(f"Expected one aggregated finding; got {len(findings)}")
    return findings[0]


class CookieMetadataNormalizationTests(unittest.TestCase):
    def test_multiple_set_cookie_fields_are_parsed_independently_without_values(self) -> None:
        headers = (
            "sessionid=secret-session-value; Secure; HttpOnly; SameSite=Strict; Path=/",
            "theme=private-preference; SameSite=Lax; Domain=example.com; Path=/assets; Max-Age=3600; Expires=Wed, 21 Oct 2030 07:28:00 GMT",
        )
        cookies, malformed = parse_set_cookie_headers(headers, target_url="https://site.example.com/")
        self.assertEqual(malformed, 0)
        self.assertEqual([cookie.name for cookie in cookies], ["sessionid", "theme"])
        self.assertTrue(cookies[0].secure)
        self.assertTrue(cookies[0].http_only)
        self.assertEqual(cookies[0].same_site, "strict")
        self.assertEqual(cookies[1].domain_scope, "parent_domain")
        self.assertEqual(cookies[1].path_scope, "scoped_path")
        self.assertTrue(cookies[1].max_age_valid)
        self.assertTrue(cookies[1].expires_valid)
        self.assertNotIn("secret-session-value", repr(cookies))
        self.assertNotIn("private-preference", repr(cookies))

    def test_malformed_and_ambiguous_cookie_headers_are_counted_and_discarded(self) -> None:
        cookies, malformed = parse_set_cookie_headers(
            ("not a cookie", "a=secret-a, b=secret-b"),
            target_url="https://site.example.com/",
        )
        self.assertEqual(cookies, ())
        self.assertEqual(malformed, 2)
        self.assertNotIn("secret-a", repr(cookies))
        self.assertNotIn("secret-b", repr(cookies))

    def test_prefix_constraints_and_domain_scope_are_normalized(self) -> None:
        cookies, malformed = parse_set_cookie_headers(
            (
                "__Host-session=not-returned; Secure; HttpOnly; Path=/; SameSite=Lax",
                "__Secure-token=not-returned; HttpOnly; Path=/",
                "global=not-returned; Domain=elsewhere.example.net; Path=/",
            ),
            target_url="https://site.example.com/",
        )
        self.assertEqual(malformed, 0)
        self.assertTrue(cookies[0].prefix_requirements_satisfied)
        self.assertFalse(cookies[1].prefix_requirements_satisfied)
        self.assertEqual(cookies[2].domain_scope, "outside_target")


class CookieSecurityCheckTests(unittest.TestCase):
    def test_secure_and_httponly_present_and_same_site_values_are_observed(self) -> None:
        scan = context_with_cookies((
            "sessionid=session-secret; Secure; HttpOnly; SameSite=Strict; Path=/",
            "preference=preference-secret; Secure; HttpOnly; SameSite=Lax; Path=/settings",
        ))
        finding = only_finding(CookieSecurityCheck(), scan)
        self.assertEqual(finding.status, FindingStatus.PASS)
        observations = finding.evidence["cookie_observations"]
        self.assertEqual([item["same_site"] for item in observations], ["strict", "lax"])
        serialized = str(finding.to_dict())
        self.assertNotIn("session-secret", serialized)
        self.assertNotIn("preference-secret", serialized)
        self.assertFalse(finding.evidence["cookie_values_stored"])

    def test_missing_secure_on_https_is_reported(self) -> None:
        finding = only_finding(
            CookieSecurityCheck(),
            context_with_cookies(("preference=secret-value; HttpOnly; SameSite=Lax",)),
        )
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.evidence["secure_missing_cookie_names"], ("preference",))
        self.assertNotIn("secret-value", str(finding.to_dict()))

    def test_missing_secure_on_http_is_not_reported_as_an_https_requirement(self) -> None:
        scan = context_with_cookies(
            ("preference=secret-value; HttpOnly; SameSite=Lax",),
            url="http://site.example.com/",
        )
        finding = only_finding(CookieSecurityCheck(), scan)
        self.assertFalse(finding.evidence["secure_check_applicable"])
        self.assertEqual(finding.evidence["secure_missing_cookie_names"], ())
        self.assertFalse(finding.evidence["cookie_observations"][0]["secure"])

    def test_missing_httponly_is_only_flagged_for_sensitive_name_candidates(self) -> None:
        scan = context_with_cookies(
            (
                "sessionid=secret-session; Secure; SameSite=Lax",
                "theme=secret-theme; Secure; SameSite=Lax",
            )
        )
        finding = only_finding(CookieSecurityCheck(), scan)
        self.assertEqual(finding.evidence["http_only_missing_count"], 2)
        self.assertEqual(finding.evidence["http_only_missing_sensitive_name_candidates"], ("sessionid",))
        self.assertNotIn("secret-session", str(finding.to_dict()))
        self.assertNotIn("secret-theme", str(finding.to_dict()))

    def test_samesite_none_with_secure_is_observed_as_a_valid_combination(self) -> None:
        finding = only_finding(
            CookieSecurityCheck(),
            context_with_cookies(("cross-site=secret; Secure; SameSite=None",)),
        )
        self.assertEqual(finding.evidence["same_site_none_without_secure_cookie_names"], ())
        self.assertEqual(finding.evidence["cookie_observations"][0]["same_site"], "none")

    def test_samesite_none_without_secure_is_reported(self) -> None:
        finding = only_finding(
            CookieSecurityCheck(),
            context_with_cookies(("cross-site=secret; SameSite=None",)),
        )
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.evidence["same_site_none_without_secure_cookie_names"], ("cross-site",))
        self.assertNotIn("secret", str(finding.to_dict()))

    def test_multiple_cookie_findings_are_aggregated_into_one_finding(self) -> None:
        scan = context_with_cookies((
            "a=one; Secure; SameSite=Lax",
            "b=two; Secure; SameSite=Lax",
            "c=three; Secure; SameSite=Lax",
        ))
        finding = only_finding(CookieSecurityCheck(), scan)
        self.assertEqual(finding.evidence["cookie_count"], 3)
        self.assertEqual(finding.evidence["set_cookie_header_count"], 3)
        self.assertEqual(tuple(item["name"] for item in finding.evidence["cookie_observations"]), ("a", "b", "c"))

    def test_malformed_cookie_is_a_safe_warning(self) -> None:
        scan = context_with_cookies(("not a valid cookie",))
        finding = only_finding(CookieSecurityCheck(), scan)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.evidence["malformed_set_cookie_header_count"], 1)
        self.assertNotIn("not a valid cookie", str(finding.to_dict()))

    def test_no_set_cookie_is_not_applicable(self) -> None:
        finding = only_finding(CookieSecurityCheck(), context())
        self.assertEqual(finding.status, FindingStatus.NOT_APPLICABLE)
        self.assertEqual(finding.evidence["cookie_count"], 0)


class MixedContentCheckTests(unittest.TestCase):
    def test_https_html_without_http_resource_attributes_passes(self) -> None:
        body = b"""
        <html><body>
          <!-- <script src='http://comments.example.com/a.js'></script> -->
          <a href='http://docs.example.com'>HTTP link</a>
          <script>const example = 'http://plain-text.example.com';</script>
          <p>http://visible-text.example.com/image.png</p>
        </body></html>
        """
        finding = only_finding(MixedContentCheck(), context(headers=(("Content-Type", "text/html"),), body=body))
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["detected_reference_count"], 0)
        self.assertFalse(finding.evidence["subresources_fetched"])

    def test_https_page_http_script_is_active_mixed_content(self) -> None:
        body = b"<html><script src='http://assets.example.net/js/app.js?token=private'></script></html>"
        finding = only_finding(MixedContentCheck(), context(headers=(("Content-Type", "text/html"),), body=body))
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.evidence["resource_type_counts"], (("script", 1),))
        self.assertEqual(finding.evidence["sanitized_reference_origins"], ("http://assets.example.net",))
        serialized = str(finding.to_dict())
        self.assertNotIn("/js/app.js", serialized)
        self.assertNotIn("private", serialized)
        self.assertFalse(finding.evidence["subresources_fetched"])

    def test_stylesheet_image_iframe_and_media_references_are_categorized(self) -> None:
        body = b"""
        <link rel='stylesheet' href='http://cdn.example.net/site.css'>
        <img src='http://img.example.net/logo.png'>
        <iframe src='http://frame.example.net/embed'></iframe>
        <video poster='http://media.example.net/poster.png'><source src='http://media.example.net/video.mp4'></video>
        """
        finding = only_finding(MixedContentCheck(), context(headers=(("Content-Type", "text/html; charset=utf-8"),), body=body))
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(
            finding.evidence["resource_type_counts"],
            (("iframe", 1), ("image", 2), ("media", 1), ("stylesheet", 1)),
        )
        self.assertEqual(finding.evidence["detected_reference_count"], 5)

    def test_multiple_http_references_are_aggregated(self) -> None:
        body = b"<img src='http://a.example.net/1'><img src='http://a.example.net/2'><img src='http://b.example.net/3'>"
        finding = only_finding(MixedContentCheck(), context(headers=(("Content-Type", "text/html"),), body=body))
        self.assertEqual(finding.evidence["detected_reference_count"], 3)
        self.assertEqual(finding.evidence["sanitized_reference_origins"], ("http://a.example.net", "http://b.example.net"))

    def test_http_document_is_not_misreported_as_mixed_content(self) -> None:
        body = b"<script src='http://cdn.example.net/app.js'></script>"
        scan = context(url="http://site.example.com/", headers=(("Content-Type", "text/html"),), body=body)
        finding = only_finding(MixedContentCheck(), scan)
        self.assertEqual(finding.status, FindingStatus.NOT_APPLICABLE)
        self.assertFalse(finding.evidence["body_inspected"])

    def test_non_html_or_unavailable_body_is_not_applicable(self) -> None:
        json_scan = context(headers=(("Content-Type", "application/json"),), body=b"http://not-html.example.net")
        self.assertEqual(only_finding(MixedContentCheck(), json_scan).status, FindingStatus.NOT_APPLICABLE)
        incomplete = context(headers=(("Content-Type", "text/html"),), body=b"<html>", body_complete=False)
        self.assertEqual(only_finding(MixedContentCheck(), incomplete).status, FindingStatus.NOT_APPLICABLE)

    def test_large_body_is_bounded_and_absence_is_not_overclaimed(self) -> None:
        body = b"<html>" + (b"text" * (MAX_HTML_INSPECTION_BYTES // 4)) + b"<img src='http://late.example.net/image'>"
        finding = only_finding(MixedContentCheck(), context(headers=(("Content-Type", "text/html"),), body=body))
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertTrue(finding.evidence["body_analysis_truncated"])
        self.assertEqual(finding.evidence["detected_reference_count"], 0)


class PassiveTechnologyDetectionTests(unittest.TestCase):
    def test_server_and_x_powered_by_signals_produce_separate_technologies(self) -> None:
        scan = context(headers=(("Server", "nginx/1.24.0"), ("X-Powered-By", "PHP/8.2.1")), body=None)
        technologies = TechnologyDetector().detect(scan)
        by_name = {item.name: item for item in technologies}
        self.assertEqual(by_name["nginx"].category.value, "web_server")
        self.assertEqual(by_name["PHP"].category.value, "runtime")
        self.assertEqual(by_name["nginx"].confidence.value, "medium")
        self.assertIn("server_header:nginx", by_name["nginx"].evidence)
        self.assertNotIn("1.24.0", str([item.to_dict() for item in technologies]))

    def test_generator_metadata_produces_cms_indicator(self) -> None:
        body = b"<html><head><meta name='generator' content='WordPress 6.4.2'></head></html>"
        scan = context(headers=(("Content-Type", "text/html"),), body=body)
        tech = TechnologyDetector().detect(scan)
        self.assertEqual([(item.name, item.category.value) for item in tech], [("WordPress", "cms")])
        self.assertEqual(tech[0].confidence.value, "medium")
        self.assertNotIn("6.4.2", str([item.to_dict() for item in tech]))

    def test_recognizable_framework_markers_and_corroboration_confidence(self) -> None:
        body = b"<html><script id='__NEXT_DATA__'></script><script src='/_next/static/chunks/app.js'></script></html>"
        scan = context(headers=(("Content-Type", "text/html"), ("X-Powered-By", "Next.js")), body=body)
        tech = TechnologyDetector().detect(scan)
        nextjs = next(item for item in tech if item.name == "Next.js")
        self.assertEqual(nextjs.category.value, "framework")
        self.assertEqual(nextjs.confidence.value, "high")
        self.assertGreaterEqual(len(nextjs.evidence), 2)
        self.assertNotIn("app.js", str(nextjs.to_dict()))

    def test_single_weak_react_marker_is_low_confidence(self) -> None:
        body = b"<div id='root' data-reactroot=''></div>"
        scan = context(headers=(("Content-Type", "text/html"),), body=body)
        tech = TechnologyDetector().detect(scan)
        react = next(item for item in tech if item.name == "React")
        self.assertEqual(react.confidence.value, "low")

    def test_ambiguous_signals_are_not_fingerprinted(self) -> None:
        body = b"<html><div id='app'></div><script src='/static/js/app.js'>const marker='__NEXT_DATA__';</script><a href='/wp-content/page'>CMS docs</a><p>built with React?</p></html>"
        scan = context(headers=(("Content-Type", "text/html"),), body=body)
        self.assertEqual(TechnologyDetector().detect(scan), ())

    def test_non_html_body_is_not_inspected(self) -> None:
        scan = context(headers=(("Content-Type", "application/json"),), body=b"WordPress http://host")
        self.assertEqual(TechnologyDetector().detect(scan), ())

    def test_large_html_inspection_is_bounded(self) -> None:
        body = b"<html>" + b"x" * (MAX_TECH_HTML_BYTES + 20_000) + b"<meta name='generator' content='WordPress'>"
        scan = context(headers=(("Content-Type", "text/html"),), body=body)
        self.assertEqual(TechnologyDetector().detect(scan), ())

    def test_check_exposes_technology_model_as_structured_metadata(self) -> None:
        scan = context(headers=(("Server", "nginx"),), body=None)
        finding = only_finding(TechnologyDetectionCheck(), scan)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.evidence["technology_count"], 1)
        technology = finding.to_dict()["metadata"]["technologies"][0]
        self.assertEqual(technology["name"], "nginx")
        self.assertEqual(technology["confidence"], "medium")


class Phase4CNoNetworkTests(unittest.TestCase):
    def test_registry_does_not_make_network_requests_for_cookie_content_or_technology(self) -> None:
        scan = context(
            headers=(("Content-Type", "text/html"),),
            body=b"<script src='http://assets.example.net/app.js'></script><meta name='generator' content='WordPress'>",
        )
        scan.response_cookies, scan.malformed_cookie_header_count = parse_set_cookie_headers(
            ("sessionid=do-not-return; Secure; HttpOnly; SameSite=Lax",),
            target_url=scan.current_url,
        )
        with patch("app.scanner.network.AiohttpTransport.request", side_effect=AssertionError("network request")) as request:
            findings = run_security_checks(scan)
        request.assert_not_called()
        self.assertTrue(findings)
        self.assertNotIn("do-not-return", str([finding.to_dict() for finding in findings]))


if __name__ == "__main__":
    unittest.main()
