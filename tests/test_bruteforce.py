"""
Unit tests for brute-force detection logic.
Validates time-window analysis, alert generation,
and false-positive avoidance.
"""
import unittest
from datetime import datetime, timedelta

from analyzer.detector import detect_bruteforce
from analyzer.thresholds import (
    BRUTE_FORCE_FAILURE_THRESHOLD,
    BRUTE_FORCE_TIME_WINDOW_MINUTES,
    SEVERITY_HIGH,
)


class TestBruteForceDetection(unittest.TestCase):
    """
    Tests for brute-force detection logic.
    """

    def _generate_failures(self, ip, start_time, count, interval_seconds):
        """
        Helper to generate failed login attempts.
        """
        return [
            {
                "timestamp": start_time + timedelta(seconds=i * interval_seconds),
                "ip": ip,
                "user": "admin",
                "status": "FAIL",
            }
            for i in range(count)
        ]

    def test_bruteforce_is_detected(self):
        """
        A brute-force attack within the time window should trigger an alert.
        """
        start_time = datetime(2026, 1, 18, 10, 0, 0)
        logs = self._generate_failures(
            ip="192.168.1.10",
            start_time=start_time,
            count=BRUTE_FORCE_FAILURE_THRESHOLD,
            interval_seconds=10,
        )

        alerts = detect_bruteforce(logs)

        self.assertEqual(len(alerts), 1)

        alert = alerts[0]
        self.assertEqual(alert["ip"], "192.168.1.10")
        self.assertEqual(alert["type"], "Brute Force")
        self.assertEqual(alert["severity"], SEVERITY_HIGH)
        self.assertEqual(alert["attempts"], BRUTE_FORCE_FAILURE_THRESHOLD)

    def test_no_alert_for_normal_behavior(self):
        """
        Failed attempts spread outside the time window should not trigger an alert.
        """
        start_time = datetime(2026, 1, 18, 10, 0, 0)

        logs = self._generate_failures(
            ip="10.0.0.5",
            start_time=start_time,
            count=BRUTE_FORCE_FAILURE_THRESHOLD,
            interval_seconds=(BRUTE_FORCE_TIME_WINDOW_MINUTES * 60) + 10,
        )

        alerts = detect_bruteforce(logs)

        self.assertEqual(len(alerts), 0)

    def test_only_one_alert_per_ip(self):
        """
        Multiple brute-force windows from the same IP should produce only one alert.
        """
        start_time = datetime(2026, 1, 18, 10, 0, 0)

        logs = (
            self._generate_failures("203.0.113.5", start_time, 5, 5)
            + self._generate_failures("203.0.113.5", start_time + timedelta(minutes=10), 5, 5)
        )

        alerts = detect_bruteforce(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "203.0.113.5")

    def test_success_events_are_ignored(self):
        """
        SUCCESS events should not affect brute-force detection.
        """
        start_time = datetime(2026, 1, 18, 10, 0, 0)

        logs = self._generate_failures(
            ip="192.168.1.20",
            start_time=start_time,
            count=BRUTE_FORCE_FAILURE_THRESHOLD - 1,
            interval_seconds=10,
        )

        logs.append(
            {
                "timestamp": start_time + timedelta(seconds=5),
                "ip": "192.168.1.20",
                "user": "admin",
                "status": "SUCCESS",
            }
        )

        alerts = detect_bruteforce(logs)

        self.assertEqual(len(alerts), 0)

    def test_alert_time_window_fields_exist(self):
        """
        Alerts must include start_time and end_time fields.
        """
        start_time = datetime(2026, 1, 18, 10, 0, 0)

        logs = self._generate_failures(
            ip="198.51.100.7",
            start_time=start_time,
            count=BRUTE_FORCE_FAILURE_THRESHOLD,
            interval_seconds=10,
        )

        alerts = detect_bruteforce(logs)

        alert = alerts[0]

        self.assertIn("start_time", alert)
        self.assertIn("end_time", alert)
        self.assertIsInstance(alert["start_time"], datetime)
        self.assertIsInstance(alert["end_time"], datetime)


if __name__ == "__main__":
    unittest.main()
