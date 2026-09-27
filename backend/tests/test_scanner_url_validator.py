import unittest

from app.scanner.config import ScannerSettings
from app.scanner.errors import (
    BlockedDestinationError,
    InvalidTargetError,
    ScannerErrorCode,
    UnsupportedPortError,
    UnsupportedSchemeError,
)
from app.scanner.models import ObservedCookie, ResponseHead
from app.scanner.errors import ResponseTooLargeError
from app.scanner.url_validator import validate_target_url


class TargetUrlValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = ScannerSettings()

    def test_valid_http_url_is_normalized(self) -> None:
        target = validate_target_url("http://ExAmPle.com", self.settings)
        self.assertEqual(target.normalized_url, "http://example.com/")
        self.assertEqual(target.request_target, "/")
        self.assertEqual(target.port, 80)

    def test_valid_https_url_keeps_path_and_query_and_removes_fragment(self) -> None:
        target = validate_target_url(
            "https://example.com:443/a%20b?q=value#section", self.settings
        )
        self.assertEqual(target.normalized_url, "https://example.com/a%20b?q=value")
        self.assertEqual(target.request_target, "/a%20b?q=value")
        self.assertEqual(target.port, 443)

    def test_missing_scheme_is_rejected(self) -> None:
        with self.assertRaises(InvalidTargetError):
            validate_target_url("example.com", self.settings)

    def test_unsupported_schemes_are_rejected(self) -> None:
        for scheme in ("file", "ftp", "ssh", "javascript", "data"):
            with self.subTest(scheme=scheme), self.assertRaises(UnsupportedSchemeError):
                validate_target_url(f"{scheme}://example.com/path", self.settings)

    def test_malformed_urls_are_rejected(self) -> None:
        for url in (
            "http:///missing-host",
            "http://[2001:db8::1",
            "http://example.com:",
            "http://intranet/",
            "http://example.com/%xy",
            "http://example.com\\@127.0.0.1/",
            " http://example.com",
            "http://example.com\n.evil.test",
        ):
            with self.subTest(url=url), self.assertRaises(InvalidTargetError):
                validate_target_url(url, self.settings)

    def test_credentials_in_authority_are_rejected(self) -> None:
        for url in (
            "http://user:password@example.com/",
            "http://@example.com/",
        ):
            with self.subTest(url=url), self.assertRaises(InvalidTargetError):
                validate_target_url(url, self.settings)

    def test_localhost_names_are_rejected(self) -> None:
        for host in (
            "localhost",
            "localhost.",
            "api.localhost",
            "service.local",
            "db.internal",
            "host.example.test",
            "host.invalid",
            "host.example",
            "home.arpa",
            "metadata.google.internal",
            "metadata.goog",
            "instance-data.ec2.internal",
        ):
            with self.subTest(host=host), self.assertRaises(BlockedDestinationError):
                validate_target_url(f"http://{host}/", self.settings)

    def test_loopback_private_link_local_multicast_and_reserved_ipv4_are_rejected(self) -> None:
        for address in (
            "127.0.0.1",
            "10.0.0.8",
            "172.16.4.1",
            "192.168.1.10",
            "169.254.1.1",
            "100.64.0.10",
            "224.0.0.1",
            "240.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.5",
            "198.18.0.1",
            "168.63.129.16",
        ):
            with self.subTest(address=address), self.assertRaises(BlockedDestinationError):
                validate_target_url(f"http://{address}/", self.settings)

    def test_loopback_private_link_local_multicast_and_reserved_ipv6_are_rejected(self) -> None:
        for address in (
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "64:ff9b::7f00:1",
            "fd00:ec2::254",
        ):
            with self.subTest(address=address), self.assertRaises(BlockedDestinationError):
                validate_target_url(f"http://[{address}]/", self.settings)

    def test_public_ipv4_and_ipv6_literals_are_accepted(self) -> None:
        ipv4 = validate_target_url("https://93.184.216.34/", self.settings)
        ipv6 = validate_target_url("https://[2606:4700:4700::1111]/", self.settings)
        self.assertTrue(ipv4.is_ip_literal)
        self.assertEqual(ipv4.hostname, "93.184.216.34")
        self.assertEqual(ipv6.hostname, "2606:4700:4700::1111")
        self.assertEqual(ipv6.normalized_url, "https://[2606:4700:4700::1111]/")

    def test_idn_is_normalized_to_idna_ascii(self) -> None:
        target = validate_target_url("https://bücher.example.com/", self.settings)
        self.assertEqual(target.hostname, "xn--bcher-kva.example.com")
        self.assertEqual(target.normalized_url, "https://xn--bcher-kva.example.com/")

    def test_one_trailing_root_dot_is_normalized(self) -> None:
        target = validate_target_url("https://example.com./", self.settings)
        self.assertEqual(target.normalized_url, "https://example.com/")

    def test_ambiguous_ipv4_spellings_are_rejected(self) -> None:
        for host in ("2130706433", "127.1", "0177.0.0.1", "0x7f000001"):
            with self.subTest(host=host), self.assertRaises(InvalidTargetError):
                validate_target_url(f"http://{host}/", self.settings)

    def test_ipv6_zone_identifiers_and_percent_encoded_hosts_are_rejected(self) -> None:
        for url in ("http://[fe80::1%25eth0]/", "http://%65xample.com/"):
            with self.subTest(url=url), self.assertRaises(InvalidTargetError):
                validate_target_url(url, self.settings)

    def test_unusual_ports_are_rejected_but_configured_web_ports_are_allowed(self) -> None:
        with self.assertRaises(UnsupportedPortError):
            validate_target_url("http://example.com:22/", self.settings)
        alternate = validate_target_url("https://example.com:8443/", self.settings)
        self.assertEqual(alternate.port, 8443)

    def test_url_length_is_bounded(self) -> None:
        settings = ScannerSettings(max_url_length=100)
        with self.assertRaises(InvalidTargetError):
            validate_target_url(f"https://example.com/{'a' * 100}", settings)

    def test_scanner_errors_serialize_only_safe_fields(self) -> None:
        head = ResponseHead(
            url="https://example.com/?token=secret",
            status_code=200,
            headers=(),
            content_length=999,
            content_type="text/html",
            content_encoding=None,
            cookies=(
                ObservedCookie(
                    name="session",
                    secure=True,
                    http_only=True,
                    same_site="lax",
                    domain_scope="host_only",
                    path_scope="root",
                    max_age_present=False,
                    max_age_valid=False,
                    max_age_nonpositive=False,
                    expires_present=False,
                    expires_valid=False,
                    prefix_kind=None,
                    prefix_requirements_satisfied=None,
                ),
            ),
        )
        error = ResponseTooLargeError(response_head=head, bytes_read=0)
        data = error.to_dict()
        self.assertEqual(data["code"], ScannerErrorCode.RESPONSE_TOO_LARGE.value)
        self.assertNotIn("url", data)
        self.assertNotIn("headers", data)
        self.assertNotIn("secret", str(data))
        self.assertNotIn("session", str(data))


if __name__ == "__main__":
    unittest.main()
