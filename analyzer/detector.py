"""
Contains detection logic for identifying suspicious authentication behavior.

This module is responsible ONLY for detection.
It must not perform parsing, printing, or file I/O.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict

from analyzer.thresholds import (
    BRUTE_FORCE_FAILURE_THRESHOLD,
    BRUTE_FORCE_TIME_WINDOW_MINUTES,
    SEVERITY_HIGH,
)


def detect_bruteforce(logs: List[Dict]) -> List[Dict]:
    """
    Detects brute-force authentication attempts using a sliding time window.

    Rule:
        IF failed_logins >= threshold
        WITHIN time_window minutes
        FROM same IP
        → FLAG (HIGH)

    Parameters
    ----------
    logs : List[Dict]
        Parsed authentication log entries.

    Returns
    -------
    List[Dict]
        List of brute-force alert dictionaries.
    """

    alerts: List[Dict] = []

    # Group failed authentication attempts by IP
    failures_by_ip = defaultdict(list)

    for entry in logs:
        if entry.get("status") == "FAIL":
            failures_by_ip[entry["ip"]].append(entry["timestamp"])

    # Time window definition
    time_window = timedelta(minutes=BRUTE_FORCE_TIME_WINDOW_MINUTES)

    # Analyze each IP independently
    for ip, timestamps in failures_by_ip.items():
        if len(timestamps) < BRUTE_FORCE_FAILURE_THRESHOLD:
            continue

        # Ensure timestamps are sorted
        timestamps.sort()

        # Sliding window analysis
        for start_index in range(len(timestamps)):
            window_start = timestamps[start_index]
            window_end = window_start + time_window

            count = 0
            for ts in timestamps[start_index:]:
                if ts <= window_end:
                    count += 1
                else:
                    break

            if count >= BRUTE_FORCE_FAILURE_THRESHOLD:
                alert = {
                    "ip": ip,
                    "type": "Brute Force",
                    "severity": SEVERITY_HIGH,
                    "attempts": count,
                    "window_minutes": BRUTE_FORCE_TIME_WINDOW_MINUTES,
                    "start_time": window_start,
                    "end_time": timestamps[start_index + count - 1],
                }

                alerts.append(alert)
                break  # One alert per IP (SOC-style)

    return alerts
