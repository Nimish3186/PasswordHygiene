import argparse
import datetime
import json
import sys
from getpass import getpass

import complexity
import hibp
import strength


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
    """Serializes the report dictionary to JSON and prints to stdout or saves to a file."""
    json_data = json.dumps(report, indent=2)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(json_data)
        print(f"Report exported to {output_file}")
    else:
        print(json_data)


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
        "-o",
        "--output",
        metavar="FILE",
        help="Save structured report to the specified file (JSON format).",
    )

    args = parser.parse_args()

    # Prompt user for password securely without echoing to terminal
    user_password = getpass("Please enter the password : ")

    complexity_result = complexity.check_complexity(user_password)
    strength_result = strength.analyze_strength(user_password)
    hibp_result = hibp.check_pwned_password(user_password)

    report = build_report(complexity_result, strength_result, hibp_result)

    if args.output:
        export_json(report, args.output)
    elif args.json:
        export_json(report)
    else:
        print_report(report)


if __name__ == "__main__":
    main()