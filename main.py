"""
main.py

Entry point for the SentinelForge log analysis pipeline.

Current responsibilities:
- Load authentication logs
- Parse logs into structured events
- Display basic parsing summary

Detection and reporting will be integrated in later stages.
"""

from analyzer.parser import parse_log_file


def main() -> None:
    """
    Main execution function.
    """

    log_file_path = "logs/sample_auth.log"

    parsed_logs = parse_log_file(log_file_path)

    print("=" * 60)
    print("SentinelForge — Log Parsing Summary")
    print("=" * 60)
    print(f"Total parsed log entries: {len(parsed_logs)}")
    print()

    for entry in parsed_logs:
        print(entry)


if __name__ == "__main__":
    main()
