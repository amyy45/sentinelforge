# SentinelForge

**SentinelForge** is a blue-team–focused security log analysis project that demonstrates how defenders detect suspicious authentication behavior using structured logs and rule-based detection logic.

This project is intentionally designed to reflect **real SOC (Security Operations Center) workflows**: normalize raw logs, extract signals, apply detection rules, and generate actionable alerts.

---

## Project Objective

The goal of SentinelForge is to build a **detection engine**, not just a log parser.

Specifically, this project aims to show that the author can:

- Understand real-world authentication attack patterns
- Translate security theory into detection logic
- Work with production-style log data
- Think like a defender rather than an attacker

---

## What This Project Detects (MVP)

The initial version focuses on **authentication-based threats**, including:

- **Brute-force login attempts**
- **High-frequency failed authentications**
- **Suspicious IP behavior across short time windows**

Additional detections (credential stuffing, IP anomalies, dashboards) are planned as extensions.

---

## Project Structure

```yaml
sentinelforge/
│
├── logs/
│ ├── sample_auth.log       # Curated authentication logs
│ └── README.md             # Log format and assumptions
│
├── analyzer/
│ ├── __init__.py
│ ├── parser.py             # Log parsing and normalization
│ ├── detectors.py          # Detection logic (next stage)
│ ├── thresholds.py         # Tunable detection thresholds
│
├── tests/
│ ├── test_parser.py        # Unit tests for parser
│
├── output/
│ └── alerts.json           # Generated alerts (future)
│
├── main.py                 # Pipeline entry point
└── README.md               # Project documentation
```

---

## Log Format

Each authentication event follows a normalized, human-readable format:

```txt
YYYY-MM-DD HH:MM:SS | IP=<ip_address> | user=<username> | status=<SUCCESS|FAIL>
```

Example:

```txt
2026-01-18 10:32:11 | IP=192.168.1.10 | user=admin | status=FAIL
```

This format was chosen to:
- Be easy to parse with regex
- Support time-window–based detection
- Avoid vendor-specific noise

---

## Design Philosophy

### 1. Separation of Concerns
- **Parsing** is isolated from **detection**
- **Detection logic** will be isolated from **reporting**

This mirrors real-world SOC pipelines and makes the system easier to reason about and extend.

---

### 2. Small, Explainable Data
The dataset is intentionally small and curated.

This allows:
- Manual verification of detections
- Clear justification of alerts
- Easier discussion of false positives and trade-offs

The focus is on **signal quality**, not data volume.

---

### 3. Defensive First
SentinelForge is built from a **blue-team perspective**:
- What patterns matter to defenders?
- What can realistically be detected from logs alone?
- How do we avoid noisy or misleading alerts?

---

## Current Status

### Implemented
- Fault-tolerant authentication log parser
- Regex-based field extraction
- Datetime normalization
- Unit tests for parsing logic

### In Progress
- Brute-force detection engine
- Alert severity classification
- JSON-based reporting

---

## How to Run (Current Stage)

From the project root:

```bash
python3 main.py
```

This will:

- Parse the sample authentication logs
- Print a structured summary of parsed events

---

## Testing

Parser unit tests can be run with:
```bash
python3 -m unittest tests/test_parser.py
```
All tests must pass before detection logic is added.

---

## Assumptions and Limitations

- Logs are time-ordered
- IP addresses are not spoofed
- No MFA or geo-context is available
- Shared or NATed IPs may cause false positives

These limitations are intentional and discussed as part of detection trade-offs.

---

## Why This Project Exists

This project was built to demonstrate practical defensive security skills, not theoretical knowledge.

It is meant to answer questions such as:

- *How do you detect brute-force attacks from logs?*
- *Why choose these thresholds?*
- *How would this scale in production?*

---

## Author Notes

SentinelForge is a learning and demonstration project aligned with SOC analyst and junior security engineering roles.

All design decisions are intentional and structured to be explainable during technical reviews and interviews.

---

## Next Steps

- Implement brute-force detection logic
- Add configurable thresholds
- Generate structured alert reports
- Extend to credential stuffing and IP anomaly detection