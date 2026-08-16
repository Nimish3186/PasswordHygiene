import argparse
import csv
import datetime
import io
import json
import os
import sys
from getpass import getpass

import complexity
import hibp
import strength

CSV_HEADERS = [
    "Timestamp",
    "Verdict",
    "Crack Time",
    "Length",
    "Complexity Score",
    "Complexity Verdict",
    "zxcvbn Score",
    "Breach Status",
    "Breach Count",
    "Breach Note",
    "Reasons",
]


def build_report(complexity_result, strength_result, hibp_result):
    """Combines raw results from all three security checks into a structured report."""
    reasons = []

    # 1. Complexity suggestions
    if complexity_result["length"] < 12:
        reasons.append(f"Length is only {complexity_result['length']} - aim for 12+.")
    score = sum([
        complexity_result["has_lower"],
        complexity_result["has_upper"],
        complexity_result["has_digit"],
        complexity_result["has_symbol"],
    ])
    if score <= 2:
        reasons.append("Uses too few character types - mix upper/lower/digits/symbols.")

    # 2. zxcvbn suggestions & warning
    warning = strength_result["feedback"]["warning"]
    if warning:
        reasons.append(warning)
    reasons.extend(strength_result["feedback"]["suggestions"])

    # 3. Breach feedback & final verdict logic
    if hibp_result is None:
        breach_status = "UNAVAILABLE"
        breach_note = "Breach check unavailable (no network / API error)."
        verdict = f"zxcvbn score {strength_result['score']}/4 (breach status unknown)"
    elif hibp_result > 0:
        breach_status = "COMPROMISED"
        breach_note = f"Found in {hibp_result:,} known data breaches."
        reasons.append(breach_note)
        verdict = "COMPROMISED"
    else:
        breach_status = "CLEAN"
        breach_note = "Not found in any known breach."
        verdict = f"zxcvbn score {strength_result['score']}/4"

    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verdict": verdict,
        "crack_time": strength_result["crack_time"],
        "breach_note": breach_note,
        "complexity": complexity_result,
        "strength": {
            "score": strength_result["score"],
            "crack_time": strength_result["crack_time"],
            "feedback": strength_result["feedback"],
        },
        "breach": {
            "status": breach_status,
            "count": hibp_result,
            "note": breach_note,
        },
        "reasons": reasons,
    }


def print_report(report):
    """Prints a human-readable summary report to the terminal."""
    print("\n--- Password Hygiene Report ---")
    print(f"Verdict     : {report['verdict']}")
    print(f"Breach check: {report['breach_note']}")
    print(f"Crack time  : {report['crack_time']}")
    if report["reasons"]:
        print("Why / how to improve:")
        for i in report["reasons"]:
            print(f"  - {i}")
    else:
        print("No issues found.")


def export_json(report, output_file=None):
    """Appends report to an existing JSON file (as a list) or creates a new one."""
    if output_file:
        existing_data = []
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, list):
                        existing_data = loaded
                    elif isinstance(loaded, dict):
                        existing_data = [loaded]
            except Exception:
                existing_data = []

        if isinstance(report, list):
            existing_data.extend(report)
        else:
            existing_data.append(report)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2)
        print(f"Report saved to {output_file}")
    else:
        json_data = json.dumps(report, indent=2)
        print(json_data)


def _report_to_csv_row(report):
    """Formats a report dictionary into a row matching CSV_HEADERS."""
    reasons_str = "; ".join(report.get("reasons", []))
    breach_count = report.get("breach", {}).get("count")
    return [
        report.get("timestamp", ""),
        report.get("verdict", ""),
        report.get("crack_time", ""),
        report.get("complexity", {}).get("length", ""),
        f"{report.get('complexity', {}).get('score', '')}/4",
        report.get("complexity", {}).get("verdict", ""),
        f"{report.get('strength', {}).get('score', '')}/4",
        report.get("breach", {}).get("status", ""),
        breach_count if breach_count is not None else "N/A",
        report.get("breach", {}).get("note", ""),
        reasons_str,
    ]


def export_csv(report, output_file=None):
    """Appends report to an existing CSV file or creates a new one with headers."""
    reports = report if isinstance(report, list) else [report]
    rows = [_report_to_csv_row(r) for r in reports]

    if output_file:
        file_exists = os.path.exists(output_file) and os.path.getsize(output_file) > 0
        with open(output_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(CSV_HEADERS)
            writer.writerows(rows)
        print(f"Report saved to {output_file}")
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(CSV_HEADERS)
        writer.writerows(rows)
        print(output.getvalue().strip())


def main():
    parser = argparse.ArgumentParser(
        description="Password Hygiene Checker — Evaluate password strength, patterns, and breach status."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured report in JSON format to stdout.",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Output structured report in CSV format to stdout.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save structured report to the specified file (.json or .csv). Appends if file exists.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        help="Explicitly choose export format (defaults to file extension or json).",
    )

    args = parser.parse_args()

    # Prompt user for password securely without echoing to terminal
    user_password = getpass("Please enter the password : ")

    complexity_result = complexity.check_complexity(user_password)
    strength_result = strength.analyze_strength(user_password)
    hibp_result = hibp.check_pwned_password(user_password)

    report = build_report(complexity_result, strength_result, hibp_result)

    if args.output:
        # Determine format: explicit --format flag or auto-detect from file extension
        fmt = args.format
        if not fmt:
            fmt = "csv" if args.output.lower().endswith(".csv") else "json"

        if fmt == "csv":
            export_csv(report, args.output)
        else:
            export_json(report, args.output)
    elif args.csv:
        export_csv(report)
    elif args.json:
        export_json(report)
    else:
        print_report(report)


if __name__ == "__main__":
    main()