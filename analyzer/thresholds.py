"""
Centralized configuration for detection thresholds used by SentinelForge.

All tunable detection parameters must live in this file to ensure:
- Clear visibility into detection logic
- Easy threshold tuning
- Reduced false-positive risk
"""

# -------------------------------------------------------------------
# Brute-force detection thresholds
# -------------------------------------------------------------------

# Number of failed authentication attempts required to trigger
# a brute-force alert from a single IP.
BRUTE_FORCE_FAILURE_THRESHOLD = 5

# Time window (in minutes) within which failed attempts are counted.
BRUTE_FORCE_TIME_WINDOW_MINUTES = 2


# -------------------------------------------------------------------
# Severity levels (reserved for future use)
# -------------------------------------------------------------------

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
