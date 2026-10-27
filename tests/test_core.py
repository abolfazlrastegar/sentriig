import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sentriig import core

class CoreTests(unittest.TestCase):
    def test_redaction(self):
        self.assertNotIn("secretvalue", core.redact("password=secretvalue"))
        self.assertNotIn("verysecret", core.redact("Authorization: Bearer verysecret"))
        self.assertIn("[REDACTED]", core.redact("token=abc123"))
    def test_authorization(self):
        c = {"chat_id":123,"user_id":456}
        self.assertTrue(core.authorized(c, {"chat":{"id":123},"from":{"id":456}}))
        self.assertFalse(core.authorized(c, {"chat":{"id":123},"from":{"id":999}}))
    def test_private_config_and_events(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            with patch.object(core,"HOME",d), patch.object(core,"CONFIG",d/"config.json"), patch.object(core,"DB",d/"state.db"):
                core.save({"token":"example"})
                self.assertEqual(core.load()["token"],"example")
                self.assertEqual(core.CONFIG.stat().st_mode & 0o777, 0o600)
                conn = core.store()
                core.record(conn,{"server_name":"test","notifications":{}},"ERROR","","nginx","token=supersecret")
                self.assertNotIn("supersecret", conn.execute("SELECT message FROM events").fetchone()[0])

if __name__ == "__main__":
    unittest.main()
