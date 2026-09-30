import unittest
from os import environ
from unittest.mock import patch

from app.config import (
    AiProviderSettings,
    AiRateLimitSettings,
    ScanRateLimitSettings,
    SupabaseSettings,
    allowed_origins_from_environment,
    scanner_api_token_from_environment,
    validate_allowed_origins,
)


class SupabaseSettingsTests(unittest.TestCase):
    def test_local_supabase_url_is_accepted(self) -> None:
        with patch.dict(environ, {"SUPABASE_URL": "http://127.0.0.1:54321"}):
            settings = SupabaseSettings.from_environment()
        self.assertEqual(settings.url, "http://127.0.0.1:54321")

    def test_remote_supabase_url_requires_https(self) -> None:
        with patch.dict(environ, {"SUPABASE_URL": "http://db.example.test"}):
            with self.assertRaisesRegex(ValueError, "must use HTTPS"):
                SupabaseSettings.from_environment()

    def test_supabase_url_rejects_embedded_credentials(self) -> None:
        with patch.dict(environ, {"SUPABASE_URL": "https://user:pass@db.example.test"}):
            with self.assertRaisesRegex(ValueError, "without credentials"):
                SupabaseSettings.from_environment()

    def test_privileged_client_requires_all_server_credentials(self) -> None:
        with patch.dict(environ, {}, clear=True):
            settings = SupabaseSettings.from_environment()
        with self.assertRaisesRegex(RuntimeError, "SUPABASE_SECRET_KEY"):
            settings.require_configured()


class ScanApiConfigTests(unittest.TestCase):
    def test_rate_limit_defaults_and_environment_overrides(self) -> None:
        with patch.dict(environ, {}, clear=True):
            self.assertEqual(ScanRateLimitSettings.from_environment(), ScanRateLimitSettings())
        with patch.dict(
            environ,
            {"SCAN_RATE_LIMIT_MAX_REQUESTS": "12", "SCAN_RATE_LIMIT_WINDOW_SECONDS": "90"},
            clear=True,
        ):
            self.assertEqual(
                ScanRateLimitSettings.from_environment(),
                ScanRateLimitSettings(max_requests=12, window_seconds=90),
            )

    def test_rate_limit_rejects_unbounded_values(self) -> None:
        for values in ((0, 60), (5, 0), (10_001, 60), (5, 86_401)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                ScanRateLimitSettings(*values)

    def test_allowed_origins_are_exact_and_canonicalized(self) -> None:
        self.assertEqual(
            validate_allowed_origins(
                ["HTTPS://Frontend.Example:443/", "http://[::1]:80", "http://[::1]"]
            ),
            ("https://frontend.example", "http://[::1]"),
        )

    def test_allowed_origins_reject_wildcards_credentials_paths_and_bad_ports(self) -> None:
        for origin in (
            "*",
            "https://user:pass@example.com",
            "https://example.com/app",
            "https://example.com:0",
            "https://example.com:",
            "https://example.com:invalid",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                validate_allowed_origins([origin])

    def test_environment_origins_are_split_trimmed_and_empty_values_ignored(self) -> None:
        with patch.dict(
            environ,
            {"ALLOWED_ORIGINS": " https://one.example/ , , https://two.example:443 "},
            clear=True,
        ):
            self.assertEqual(allowed_origins_from_environment(), ("https://one.example", "https://two.example"))

    def test_non_local_http_origins_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            validate_allowed_origins(["http://frontend.example"])

    def test_ai_configuration_is_optional_server_side_and_openai_compatible(self) -> None:
        with patch.dict(environ, {}, clear=True):
            self.assertIsNone(AiProviderSettings.from_environment())
        with patch.dict(
            environ,
            {
                "AI_PROVIDER": "openai",
                "AI_API_KEY": "server-secret-key",
                "AI_MODEL": "gpt-test",
            },
            clear=True,
        ):
            settings = AiProviderSettings.from_environment()
        self.assertIsNotNone(settings)
        assert settings is not None
        self.assertEqual(settings.base_url, "https://api.openai.com/v1")
        self.assertEqual(settings.api_key, "server-secret-key")

    def test_custom_ai_provider_requires_a_safe_base_url(self) -> None:
        base = {
            "AI_PROVIDER": "openai-compatible",
            "AI_API_KEY": "server-secret-key",
            "AI_MODEL": "local-model",
        }
        with patch.dict(environ, base, clear=True):
            self.assertIsNone(AiProviderSettings.from_environment())
        with patch.dict(environ, {**base, "AI_BASE_URL": "http://provider.example/v1"}, clear=True):
            self.assertIsNone(AiProviderSettings.from_environment())
        with patch.dict(environ, {**base, "AI_BASE_URL": "https://10.0.0.8/v1"}, clear=True):
            self.assertIsNone(AiProviderSettings.from_environment())
        with patch.dict(environ, {**base, "AI_BASE_URL": "https://metadata.google.internal/v1"}, clear=True):
            self.assertIsNone(AiProviderSettings.from_environment())
        with patch.dict(environ, {**base, "AI_BASE_URL": "http://127.0.0.1:8000/v1"}, clear=True):
            settings = AiProviderSettings.from_environment()
        self.assertIsNotNone(settings)

    def test_ai_generation_limits_are_bounded_and_configurable(self) -> None:
        with patch.dict(environ, {}, clear=True):
            self.assertEqual(AiRateLimitSettings.from_environment(), AiRateLimitSettings())
        with patch.dict(
            environ,
            {"AI_RATE_LIMIT_MAX_REQUESTS": "8", "AI_RATE_LIMIT_WINDOW_SECONDS": "7200"},
            clear=True,
        ):
            self.assertEqual(
                AiRateLimitSettings.from_environment(),
                AiRateLimitSettings(max_requests=8, window_seconds=7200),
            )
        with self.assertRaises(ValueError):
            AiRateLimitSettings(max_requests=0)

    def test_server_to_server_token_requires_sufficient_length_and_no_padding(self) -> None:
        with patch.dict(environ, {"SCANNER_API_TOKEN": "a" * 32}, clear=True):
            self.assertEqual(scanner_api_token_from_environment(), "a" * 32)
        for token in ("", "short", "a" * 31, f"{'a' * 32} "):
            with self.subTest(token=token), patch.dict(
                environ, {"SCANNER_API_TOKEN": token}, clear=True
            ):
                self.assertIsNone(scanner_api_token_from_environment())


if __name__ == "__main__":
    unittest.main()
