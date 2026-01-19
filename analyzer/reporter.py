"""
Handles reporting of detected security alerts.

Responsibilities:
- Convert alert objects into JSON-safe structures
- Persist alerts to disk in a deterministic format

This module does NOT perform detection or parsing.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict


def serialize_alerts(alerts: List[Dict]) -> List[Dict]:
    """
    Convert alert dictionaries into JSON-serializable form.

    Datetime objects are converted to ISO 8601 strings so the
    output can be consumed by dashboards, databases, or APIs.
    """

    serialized = []

    for alert in alerts:
        serialized.append({
            "ip": alert["ip"],
            "type": alert["type"],
            "severity": alert["severity"],
            "attempts": alert["attempts"],
            "window_minutes": alert["window_minutes"],
            "start_time": _to_iso(alert["start_time"]),
            "end_time": _to_iso(alert["end_time"]),
        })

    return serialized


def write_json_report(alerts: List[Dict], output_path: str) -> None:
    """
    Write alerts to a JSON file.

    The output file is overwritten on each run to ensure
    deterministic results.
    """

    output_file = Path(output_path)

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    serialized_alerts = serialize_alerts(alerts)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(serialized_alerts, f, indent=2)


def _to_iso(value) -> str:
    """
    Convert datetime objects to ISO 8601 strings.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
