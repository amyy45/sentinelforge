"""
test_parser.py

Unit tests for the authentication log parser.
These tests validate correctness, fault tolerance,
and data normalization.
"""

import unittest
from datetime import datetime
import tempfile
import os

from analyzer.parser import parse_log_file


class TestLogParser(unittest.TestCase):
    """
    Tests for parse_log_file function.
    """

    def _create_temp_log_file(self, lines):
        """
        Helper method to create a temporary log file.
        """
        temp_file = tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8"
        )
        for line in lines:
            temp_file.write(line + "\n")
        temp_file.close()
        return temp_file.name

    def test_valid_log_lines_are_parsed(self):
        """
        Valid log lines should be parsed correctly.
        """
        lines = [
            "2026-01-18 10:32:11 | IP=192.168.1.10 | user=admin | status=FAIL",
            "2026-01-18 10:33:05 | IP=10.0.0.1 | user=alice | status=SUCCESS",
        ]

        file_path = self._create_temp_log_file(lines)
        result = parse_log_file(file_path)

        os.remove(file_path)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["ip"], "192.168.1.10")
        self.assertEqual(result[0]["user"], "admin")
        self.assertEqual(result[0]["status"], "FAIL")

    def test_timestamp_is_datetime_object(self):
        """
        Parsed timestamp must be a datetime object.
        """
        lines = [
            "2026-01-18 10:32:11 | IP=192.168.1.10 | user=admin | status=FAIL"
        ]

        file_path = self._create_temp_log_file(lines)
        result = parse_log_file(file_path)

        os.remove(file_path)

        self.assertIsInstance(result[0]["timestamp"], datetime)

    def test_malformed_lines_are_skipped(self):
        """
        Malformed log lines should be skipped without crashing.
        """
        lines = [
            "INVALID LOG ENTRY",
            "2026-01-18 10:32:11 | IP=192.168.1.10 | user=admin | status=FAIL",
            "2026-01-18 | IP=bad | status=FAIL",
        ]

        file_path = self._create_temp_log_file(lines)
        result = parse_log_file(file_path)

        os.remove(file_path)

        # Only one valid line should be parsed
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user"], "admin")

    def test_empty_file_returns_empty_list(self):
        """
        Empty log files should return an empty list.
        """
        file_path = self._create_temp_log_file([])
        result = parse_log_file(file_path)

        os.remove(file_path)

        self.assertEqual(result, [])

    def test_empty_lines_are_ignored(self):
        """
        Empty lines should be ignored safely.
        """
        lines = [
            "",
            "   ",
            "2026-01-18 10:32:11 | IP=192.168.1.10 | user=admin | status=FAIL",
        ]

        file_path = self._create_temp_log_file(lines)
        result = parse_log_file(file_path)

        os.remove(file_path)

        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
