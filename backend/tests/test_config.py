import unittest
from os import environ
from unittest.mock import patch

from app.config import SupabaseSettings


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


if __name__ == "__main__":
    unittest.main()
