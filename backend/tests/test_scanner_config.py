import unittest

from app.scanner.config import ScannerSettings


class ScannerSettingsTests(unittest.TestCase):
    def test_sensible_defaults(self) -> None:
        settings = ScannerSettings.from_environment({})
        self.assertEqual(settings.allowed_schemes, frozenset({"http", "https"}))
        self.assertEqual(settings.allowed_ports, frozenset({80, 443, 8080, 8443}))
        self.assertEqual(settings.max_redirects, 5)
        self.assertEqual(settings.max_response_bytes, 1_000_000)
        self.assertEqual(settings.user_agent, "WebGuard-Security-Scanner/0.1")

    def test_environment_overrides_limits(self) -> None:
        settings = ScannerSettings.from_environment(
            {
                "SCANNER_ALLOWED_SCHEMES": "https",
                "SCANNER_ALLOWED_PORTS": "443,8443",
                "SCANNER_MAX_REDIRECTS": "2",
                "SCANNER_MAX_RESPONSE_BYTES": "4096",
                "SCANNER_CONNECT_TIMEOUT_SECONDS": "1.25",
                "SCANNER_READ_CHUNK_BYTES": "2048",
            }
        )
        self.assertEqual(settings.allowed_schemes, frozenset({"https"}))
        self.assertEqual(settings.allowed_ports, frozenset({443, 8443}))
        self.assertEqual(settings.max_redirects, 2)
        self.assertEqual(settings.max_response_bytes, 4096)
        self.assertEqual(settings.connect_timeout_seconds, 1.25)
        self.assertEqual(settings.read_chunk_bytes, 2048)

    def test_unsafe_scheme_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "only http and https"):
            ScannerSettings.from_environment({"SCANNER_ALLOWED_SCHEMES": "http,ftp"})

    def test_unusual_operational_values_are_bounded(self) -> None:
        for environment in (
            {"SCANNER_MAX_REDIRECTS": "100"},
            {"SCANNER_MAX_RESPONSE_BYTES": "1000000000"},
            {"SCANNER_ALLOWED_PORTS": "70000"},
            {"SCANNER_READ_TIMEOUT_SECONDS": "500"},
            {"SCANNER_OVERALL_TIMEOUT_SECONDS": "1"},
        ):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                ScannerSettings.from_environment(environment)


if __name__ == "__main__":
    unittest.main()
