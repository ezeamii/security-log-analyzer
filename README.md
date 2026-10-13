# Security Log Analyzer

A Python cybersecurity project that analyzes authentication logs, detects repeated failed login attempts, identifies possible password-spraying activity, and generates a Markdown security report.

## Features

- Loads and validates authentication events from CSV files.
- Counts successful and failed login attempts.
- Detects repeated failures from individual IP addresses.
- Flags suspicious login patterns, including successful logins after repeated failures.
- Identifies possible password-spraying activity across multiple usernames.
- Assigns alert severity levels.
- Generates a Markdown report with summary statistics, alerts, and analyst follow-up recommendations.
- Includes automated unit tests for key detection rules.

## Technologies

- Python
- CSV log processing
- `collections.Counter` and `defaultdict`
- `argparse` for command-line options
- `unittest` for automated testing
- Git and GitHub

## Project Structure

```text
security-log-analyzer/
├── data/
│   └── login_logs.csv
├── python/
│   └── analyzer.py
├── reports/
│   └── security_report.md
├── tests/
│   └── test_analyzer.py
└── README.md
```

## Requirements

- Python 3.10 or newer
- Git (optional, for version control)

No third-party Python packages are required.

## How to Run

Run these commands from the project root.

Analyze the default dataset:

```bash
python python/analyzer.py
```

Change the failed-login threshold:

```bash
python python/analyzer.py --threshold 3
```

Specify a different input file:

```bash
python python/analyzer.py --input data/login_logs.csv
```

Specify an output directory:

```bash
python python/analyzer.py --output reports
```

The generated report is saved as `security_report.md` in the selected output directory.

## Run the Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover repeated failures, successful logins after failures, password-spraying candidates, below-threshold activity, and empty event lists.

## Example Detection Scenarios

- Repeated failed logins from one source IP.
- Failed logins affecting multiple usernames.
- Successful authentication following failed attempts.
- Possible password spraying across several accounts.

## Security Considerations and Limitations

This project is designed for defensive cybersecurity education using synthetic training data.

- An alert indicates suspicious activity, not confirmed malicious behavior.
- A successful login following failures does not prove that an account was compromised.
- Threshold-based detection may produce false positives or miss attacks.
- The password-spraying detector uses a basic heuristic.
- The tool analyzes CSV files and does not monitor systems in real time.
- The sample IP addresses use documentation-only address ranges.

## Skills Demonstrated

Python programming, authentication log analysis, security event investigation, threat detection, report generation, command-line tools, and automated testing.