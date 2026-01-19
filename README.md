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
│ └── reporter.py           # Reporting and JSON serialization
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

## Detection Logic (Brute-Force)

SentinelForge detects brute-force attacks by identifying **multiple failed authentication attempts originating from the same IP address within a short time window.**

Rather than relying on total failure counts, the detection logic focuses on **rate-based behavior**, which is more indicative of automated attacks than normal user mistakes.

Detection steps at a high level:

- Group failed authentication attempts by source IP
- Sort attempts by timestamp
- Apply a sliding time window
- Trigger a high-severity alert when the threshold is exceeded

This approach mirrors how early-stage SIEM and SOC rules are commonly implemented.

---

## Threshold Selection

The default brute-force rule uses:

- 5 failed attempts
- Within 2 minutes
- From the same IP

These values are intentionally conservative:

- Lower thresholds increase false positives (e.g., users mistyping passwords)
- Higher thresholds risk missing fast, automated attacks

All thresholds are centralized in thresholds.py and are designed to be **tuned based on environment and risk tolerance.**

---

## Reporting and Output

Detected alerts are:

- Displayed in a human-readable format on the console
- Serialized to a machine-readable JSON file at:

```bash
output/alerts.json
```
Timestamps in JSON output are stored using **ISO 8601** format to support downstream systems such as dashboards, databases, or APIs.

---

## How to Run 

From the project root:

```bash
python3 main.py
```

This will:

- Parse the sample authentication logs
- Run brute-force detection
- Print detected alerts
- Write alerts to output/alerts.json

---

## Testing

All core logic is covered by unit tests.

Run tests with:
```bash
python3 -m unittest discover
```
Tests validate:
- Correct parsing
- Time-window brute-force detection
- False-positive avoidance
- Deterministic alert behavior

---

## Assumptions and Limitations

- Logs are time-ordered
- IP addresses are not spoofed
- No MFA or geo-context is available
- Shared or NATed IPs may cause false positives

These limitations are intentional and reflect the constraints of log-only detection.

---

## Scaling Considerations

In a production environment, this approach would evolve by:
- Processing streaming logs instead of static files
- Maintaining sliding windows in memory or state stores
- Offloading alerting to SIEM platforms or message queues
- Combining rule-based detection with contextual signals

Rule-based detection remains valuable due to its **explainability and low operational cost.**

---

## Why This Project Exists

This project was built to demonstrate practical defensive security skills, not theoretical knowledge.

It is meant to answer questions such as:

- *How do you detect brute-force attacks from logs?*
- *Why choose these thresholds?*
- *How detection logic can scale and evolve?*

---

## Next Steps

- Implement brute-force detection logic
- Add configurable thresholds
- Generate structured alert reports
- Extend to credential stuffing and IP anomaly detection