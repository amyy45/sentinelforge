"""
Entry point for the SentinelForge log analysis pipeline.

Responsibilities (Day 3):
- Load authentication logs
- Parse logs into structured events
- Run brute-force detection
- Display detected security alerts
"""

from analyzer.parser import parse_log_file
from analyzer.detector import detect_bruteforce


def main() -> None:
    """
    Main execution function.
    """

    log_file_path = "logs/sample_auth.log"

    #1: Parse logs
    parsed_logs = parse_log_file(log_file_path)

    print("=" * 60)
    print("SentinelForge — Log Parsing Summary")
    print("=" * 60)
    print(f"Total parsed log entries: {len(parsed_logs)}")
    print()

    #2: Run brute-force detection
    alerts = detect_bruteforce(parsed_logs)

    print("=" * 60)
    print("SentinelForge — Security Alerts")
    print("=" * 60)

    if not alerts:
        print("No brute-force activity detected.")
    else:
        for alert in alerts:
            print(f"[{alert['severity']}] {alert['type']} detected")
            print(f"IP Address   : {alert['ip']}")
            print(f"Attempts     : {alert['attempts']} "
                  f"in {alert['window_minutes']} minutes")
            print(f"Time Window  : {alert['start_time']} → {alert['end_time']}")
            print("-" * 60)


if __name__ == "__main__":
    main()
