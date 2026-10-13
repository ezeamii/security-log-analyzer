"""
Security Log Analyzer
---------------------
Analyzes synthetic authentication logs for repeated failed logins and
potential password-spraying patterns. This is a defensive learning project.

Usage (from the project root):
    python python/analyzer.py
    python python/analyzer.py --threshold 5
    python python/analyzer.py --input data/login_logs.csv --output reports
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "data" / "login_logs.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "reports"
EXPECTED_COLUMNS = {"timestamp", "source_ip", "username", "status", "service"}
VALID_STATUSES = {"SUCCESS", "FAILURE"}


def load_logs(path: Path) -> list[dict[str, str]]:
    """Load and validate CSV authentication events."""
    if not path.exists():
        raise FileNotFoundError(
            f"Could not find input file: {path}\n"
            "Make sure data/login_logs.csv exists or use --input PATH."
        )

    with path.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames:
            raise ValueError("The CSV file is empty or has no header row.")

        missing = EXPECTED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(
                "CSV is missing required column(s): " + ", ".join(sorted(missing))
            )

        events: list[dict[str, str]] = []
        for line_number, raw in enumerate(reader, start=2):
            event = {key: (raw.get(key) or "").strip() for key in EXPECTED_COLUMNS}
            if not all(event.values()):
                print(f"[WARNING] Skipping incomplete CSV row {line_number}.")
                continue

            try:
                datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                print(f"[WARNING] Skipping invalid timestamp on CSV row {line_number}.")
                continue

            event["status"] = event["status"].upper()
            if event["status"] not in VALID_STATUSES:
                print(f"[WARNING] Skipping unknown status on CSV row {line_number}.")
                continue

            events.append(event)

    if not events:
        raise ValueError("No valid log events were found in the CSV file.")
    return events



def analyze_logs(events: list[dict[str, str]], threshold: int) -> dict[str, Any]:
    """Summarize authentication events and detect suspicious login patterns."""
    failures_by_ip: Counter[str] = Counter()
    failures_by_user: Counter[str] = Counter()
    failures_by_ip_user: Counter[tuple[str, str]] = Counter()
    successes_by_ip: Counter[str] = Counter()

    # Track usernames that actually experienced failed logins.
    failed_users_by_ip: dict[str, set[str]] = defaultdict(set)

    # Group events by IP to check the order of failures and successes.
    events_by_ip: dict[str, list[dict[str, str]]] = defaultdict(list)

    for event in events:
        ip = event["source_ip"]
        user = event["username"]
        events_by_ip[ip].append(event)

        if event["status"] == "FAILURE":
            failures_by_ip[ip] += 1
            failures_by_user[user] += 1
            failures_by_ip_user[(ip, user)] += 1
            failed_users_by_ip[ip].add(user)
        else:
            successes_by_ip[ip] += 1

    # Check whether a successful login occurred after a failed login.
    success_after_failures: dict[str, bool] = {}

    for ip, ip_events in events_by_ip.items():
        ordered_events = sorted(
            ip_events,
            key=lambda event: datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            ),
        )

        failure_seen = False
        success_after_failures[ip] = False

        for event in ordered_events:
            if event["status"] == "FAILURE":
                failure_seen = True
            elif failure_seen:
                success_after_failures[ip] = True

    alerts: list[dict[str, Any]] = []

    for ip, count in failures_by_ip.most_common():
        failed_user_count = len(failed_users_by_ip[ip])
        followed_by_success = success_after_failures[ip]

        if count >= threshold:
            reasons = []

            if failed_user_count == 1:
                reasons.append("Repeated failed logins against one username")
            else:
                reasons.append("Repeated failures across multiple usernames")

            if followed_by_success:
                reasons.append("Successful login after failed attempts")

            severity = (
                "HIGH"
                if count >= threshold * 2 or followed_by_success
                else "MEDIUM"
            )

            alerts.append({
                "source_ip": ip,
                "failed_attempts": count,
                "distinct_usernames": len(
                    {event["username"] for event in events_by_ip[ip]}
                ),
                "successful_logins": successes_by_ip[ip],
                "severity": severity,
                "reason": "; ".join(reasons),
            })

    # Count distinct usernames with failures, not just usernames seen.
    password_spray_candidates = [
        {
            "source_ip": ip,
            "distinct_usernames": len(users),
            "failed_attempts": failures_by_ip[ip],
        }
        for ip, users in failed_users_by_ip.items()
        if len(users) >= 5 and failures_by_ip[ip] >= threshold
    ]

    return {
        "total_events": len(events),
        "successful_logins": sum(
            event["status"] == "SUCCESS" for event in events
        ),
        "failed_logins": sum(
            event["status"] == "FAILURE" for event in events
        ),
        "unique_source_ips": len(
            {event["source_ip"] for event in events}
        ),
        "unique_usernames": len(
            {event["username"] for event in events}
        ),
        "failures_by_ip": failures_by_ip,
        "failures_by_user": failures_by_user,
        "failures_by_ip_user": failures_by_ip_user,
        "alerts": alerts,
        "password_spray_candidates": password_spray_candidates,
    }



def write_report(results: dict[str, Any], output_dir: Path, threshold: int) -> Path:
    """Write a Markdown report with summary metrics and detection results."""
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "security_report.md"

    lines = [
        "# Security Log Analysis Report",
        "",
        f"- **Generated:** {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"- **Failed-login alert threshold:** {threshold} attempts per source IP",
        "- **Dataset:** Synthetic training data; not real user or production logs",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Total authentication events | {results['total_events']} |",
        f"| Successful logins | {results['successful_logins']} |",
        f"| Failed logins | {results['failed_logins']} |",
        f"| Unique source IPs | {results['unique_source_ips']} |",
        f"| Unique usernames | {results['unique_usernames']} |",
        "",
        "## Alerts",
        "",
    ]

    if results["alerts"]:
        lines.extend([
            "| Severity | Source IP | Failed attempts | Usernames seen | Successful logins | Reason |",
            "|---|---|---:|---:|---:|---|",
        ])
        for alert in results["alerts"]:
            lines.append(
                f"| {alert['severity']} | {alert['source_ip']} | "
                f"{alert['failed_attempts']} | {alert['distinct_usernames']} | "
                f"{alert['successful_logins']} | {alert['reason']} |"
            )
    else:
        lines.append("No source IP met the configured alert threshold.")

    
    lines.extend(["", "## Usernames with the most failed logins", ""])

    if results["failures_by_user"]:
        lines.extend([
            "| Username | Failed attempts |",
            "|---|---:|",
        ])

        for username, count in results["failures_by_user"].most_common(10):
            lines.append(f"| {username} | {count} |")
    else:
        lines.append("No failed login attempts were recorded.")


    lines.extend(["", "## Possible password-spraying patterns", ""])
    if results["password_spray_candidates"]:
        lines.extend([
            "| Source IP | Distinct usernames | Failed attempts |",
            "|---|---:|---:|",
        ])
        for candidate in results["password_spray_candidates"]:
            lines.append(
                f"| {candidate['source_ip']} | {candidate['distinct_usernames']} | "
                f"{candidate['failed_attempts']} |"
            )
    else:
        lines.append("No candidate met the current simple heuristic.")

    lines.extend([
        "",
        "## Recommended analyst follow-up",
        "",
        "1. Validate the alert against the organization's normal login patterns.",
        "2. Review authentication events immediately before and after the failures.",
        "3. Check whether any successful login from the same source was expected.",
        "4. Review account protection controls, including MFA and rate limiting.",
        "5. Escalate according to the organization's incident response process.",
        "",
        "## Limitations",
        "",
        "- Threshold-based alerts can produce false positives and false negatives.",
        "- The password-spraying check is a basic heuristic, not proof of an attack.",
        "- IP addresses in this sample use documentation-only ranges.",
        "- This tool analyzes provided CSV files; it does not monitor systems live.",
        "",
    ])

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def print_summary(results: dict[str, Any], report_path: Path) -> None:
    """Print a readable summary in the terminal."""
    print("\n" + "=" * 62)
    print("             SECURITY LOG ANALYZER")
    print("=" * 62)
    print(f"Total events:          {results['total_events']}")
    print(f"Successful logins:     {results['successful_logins']}")
    print(f"Failed logins:         {results['failed_logins']}")
    print(f"Unique source IPs:     {results['unique_source_ips']}")
    print(f"Unique usernames:      {results['unique_usernames']}")
    print("\nALERTS")
    print("-" * 62)

    if not results["alerts"]:
        print("No source IP met the alert threshold.")
    else:
        for alert in results["alerts"]:
            print(
                f"[{alert['severity']}] {alert['source_ip']}: "
                f"{alert['failed_attempts']} failures; "
                f"{alert['distinct_usernames']} username(s); "
                f"{alert['successful_logins']} successful login(s)."
            )
            print(f"        Reason: {alert['reason']}")

    print("\nPOSSIBLE PASSWORD-SPRAYING PATTERNS")
    print("-" * 62)
    if not results["password_spray_candidates"]:
        print("No candidate met the heuristic.")
    else:
        for candidate in results["password_spray_candidates"]:
            print(
                f"{candidate['source_ip']}: {candidate['failed_attempts']} failures "
                f"across {candidate['distinct_usernames']} usernames."
            )

    print(f"\nReport saved to: {report_path}")
    print("=" * 62 + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs and flag repeated failed logins."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT,
                        help="Path to the input CSV (default: data/login_logs.csv)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="Directory for the generated report (default: reports)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Minimum failures from one IP to alert (default: 5)")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    return args


def main() -> int:
    args = parse_args()
    try:
        events = load_logs(args.input)
        results = analyze_logs(events, args.threshold)
        report_path = write_report(results, args.output, args.threshold)
        print_summary(results, report_path)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
