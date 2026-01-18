# Authentication Log Dataset

## Overview

This directory contains a **curated and normalized authentication log dataset** used by the **SentinelForge** project to model and detect common authentication-based attacks from a blue-team (defensive) perspective.

The dataset is intentionally small and controlled to make detection logic explainable, testable, and defensible during analysis and interviews.

---

## Log Format

Each log entry follows a consistent, human-readable format:

YYYY-MM-DD HH:MM:SS | IP=<ip_address> | user=<username> | status=<SUCCESS|FAIL>


### Field Description

| Field | Description | Security Relevance |
|------|------------|--------------------|
| Timestamp | Date and time of the authentication attempt | Enables time-window and rate-based detection |
| IP | Source IP address of the request | Used for attacker attribution and anomaly detection |
| user | Username used in the authentication attempt | Helps identify credential stuffing and account targeting |
| status | Result of the authentication attempt (`SUCCESS` or `FAIL`) | Differentiates normal behavior from attack activity |

---

## Simulated Behavior in the Dataset

The dataset intentionally includes multiple behavior patterns to support rule-based detection.

### Normal User Activity
- Successful and failed logins
- Reasonable time gaps between attempts
- Different IPs and users

This establishes a **baseline** for comparison.

---

### Brute-Force Authentication Attempts
- Multiple failed login attempts
- Same IP address
- Short time window (seconds apart)

This pattern represents a classic **brute-force attack**, where an attacker rapidly attempts to guess credentials for a single account.

---

### Credential Stuffing Signals
- Same IP attempting multiple usernames
- All attempts fail
- Short time interval

While not fully detected in the MVP, this behavior is included to support future detection rules.

---

## Data Source

The log entries are **manually curated and normalized** based on common patterns observed in publicly available SSH authentication logs.  
They are adapted into a simplified format to focus on detection logic rather than vendor-specific log noise.

---

## Assumptions

- Logs are time-ordered
- IP addresses are not spoofed
- No multi-factor authentication events are present
- All authentication attempts are captured in the logs

---

## Limitations

- Shared or NATed IPs may cause false positives
- No geographic or reputation-based IP context
- Does not differentiate between internal and external IP ranges

These limitations are intentional and addressed in later project stages.

---

## Purpose

This dataset exists to:
- Validate detection logic
- Enable deterministic testing
- Support defender-focused reasoning

It is **not** intended to represent full production-scale log volume.

