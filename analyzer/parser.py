"""
Responsible for parsing authentication log files into structured,
validated Python objects suitable for security detection logic.

This module performs:
- Line-by-line log ingestion
- Regex-based field extraction
- Timestamp normalization
- Basic validation
- Fault-tolerant parsing (malformed lines are skipped)

Detection logic MUST NOT live here.
"""

import re
from datetime import datetime
from typing import List, Dict


# -------------------------------------------------------------------
# Regex pattern for authentication log lines
# -------------------------------------------------------------------
LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} '
    r'\d{2}:\d{2}:\d{2}) '
    r'\| IP=(?P<ip>[\d\.]+) '
    r'\| user=(?P<user>[A-Za-z0-9_\-]+) '
    r'\| status=(?P<status>SUCCESS|FAIL)$'
)


# -------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------
def parse_log_file(file_path: str) -> List[Dict]:
    """
    Parses an authentication log file and returns a list of structured
    log entries.

    Parameters
    ----------
    file_path : str
        Path to the authentication log file.

    Returns
    -------
    List[Dict]
        A list of parsed log entries. Each entry is a dictionary with:
        - timestamp (datetime.datetime)
        - ip (str)
        - user (str)
        - status (str)

    Notes
    -----
    - Malformed or invalid log lines are skipped.
    - The function is fault-tolerant and will not raise exceptions
      due to bad input data.
    """

    parsed_entries: List[Dict] = []

    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                line = raw_line.strip()

                # Skip empty lines
                if not line:
                    continue

                match = LOG_PATTERN.match(line)
                if not match:
                    # Malformed line — skip silently (SOC pipelines do this)
                    continue

                try:
                    entry = _build_log_entry(match.groupdict())
                except ValueError:
                    # Validation or timestamp conversion failed
                    continue

                parsed_entries.append(entry)

    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {file_path}")

    return parsed_entries


# -------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------
def _build_log_entry(fields: Dict[str, str]) -> Dict:
    """
    Converts regex-extracted fields into a validated log entry.

    Parameters
    ----------
    fields : Dict[str, str]
        Dictionary containing raw string fields from regex match.

    Returns
    -------
    Dict
        Validated log entry with normalized data types.

    Raises
    ------
    ValueError
        If any field is invalid or timestamp conversion fails.
    """

    timestamp_str = fields.get("timestamp")
    ip = fields.get("ip")
    user = fields.get("user")
    status = fields.get("status")

    # Convert timestamp string to datetime object
    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except Exception as exc:
        raise ValueError("Invalid timestamp format") from exc

    # Basic field validation
    if not ip or not isinstance(ip, str):
        raise ValueError("Invalid IP address")

    if not user or not isinstance(user, str):
        raise ValueError("Invalid username")

    if status not in {"SUCCESS", "FAIL"}:
        raise ValueError("Invalid status value")

    return {
        "timestamp": timestamp,
        "ip": ip,
        "user": user,
        "status": status,
    }
