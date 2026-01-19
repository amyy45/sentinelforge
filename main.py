from analyzer.parser import parse_log_file
from analyzer.detector import detect_bruteforce
from analyzer.reporter import write_json_report


def main() -> None:
    """
    Main execution function.
    """

    log_file_path = "logs/sample_auth.log"
    output_path = "output/alerts.json"

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
            print(
                f"Attempts     : {alert['attempts']} "
                f"in {alert['window_minutes']} minutes"
            )
            print(
                f"Time Window  : "
                f"{alert['start_time']} → {alert['end_time']}"
            )
            print("-" * 60)

        #3: Write alerts to JSON
        write_json_report(alerts, output_path)
        print(f"Alerts written to: {output_path}")


if __name__ == "__main__":
    main()
