import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import sys

from getpass import getpass

import complexity
import hibp
import passphrase
import strength

DEFAULT_CSV_PATH = "report.csv"

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), "IST")

CSV_HEADERS = [
    "Timestamp",
    "Password Hash (SHA-1)",
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

def hash_password(password):
    return hashlib.sha1(password.encode("utf-8")).hexdigest()


def status(message):
    print(message, file=sys.stderr)


def build_report(complexity_result, strength_result, hibp_result, password_hash=None):
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

    # Suggest a replacement passphrase for anything weak enough to matter:
    # compromised outright, or a low zxcvbn score (0-2). Strong passwords
    # (score 3-4, not breached) don't get a suggestion - nothing to fix.
    is_weak = breach_status == "COMPROMISED" or strength_result["score"] < 3
    suggested_passphrase = passphrase.generate_passphrase() if is_weak else None

    return {
        "timestamp": datetime.datetime.now(IST).isoformat(),
        "password_hash": password_hash,
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
        "suggested_passphrase": suggested_passphrase,
    }


def print_report(report):
    """Print a human-readable summary report to stdout."""
    print("\n--- Password Hygiene Report ---")
    print(f"Verdict     : {report['verdict']}")
    print(f"Breach check: {report['breach_note']}")
    print(f"Crack time  : {report['crack_time']}")
    if report["reasons"]:
        print("Why / how to improve:")
        for reason in report["reasons"]:
            print(f"  - {reason}")
    else:
        print("No issues found.")

    if report.get("suggested_passphrase"):
        bits = passphrase.passphrase_entropy_bits()
        print(f"\nTry a passphrase instead: {report['suggested_passphrase']}")
        print(f"  (~{bits:.0f} bits of entropy, and far easier to remember)")


def _atomic_write(path, data, mode="w", encoding="utf-8"):
    """Write `data` to `path` via a temp file + rename.

    Rename is atomic on both POSIX and Windows (os.replace), so a crash or
    Ctrl-C mid-write leaves the original file intact rather than truncated.
    """
    tmp_path = f"{path}.tmp"
    kwargs = {"encoding": encoding, "newline": ""} if "b" not in mode else {}
    with open(tmp_path, mode, **kwargs) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def _load_existing_json(output_file):
    """Read an existing JSON report file into a list.

    Raises on unreadable/invalid content rather than silently starting from
    an empty list - doing that would overwrite (and destroy) a file we
    simply failed to parse.
    """
    if not (os.path.exists(output_file) and os.path.getsize(output_file) > 0):
        return []

    with open(output_file, "r", encoding="utf-8") as f:
        try:
            loaded = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"{output_file} exists but is not valid JSON ({e}). "
                "Refusing to overwrite it - move or delete it first."
            ) from e

    if isinstance(loaded, list):
        return loaded
    if isinstance(loaded, dict):
        return [loaded]
    raise ValueError(
        f"{output_file} contains JSON of type {type(loaded).__name__}, "
        "expected an object or a list. Refusing to overwrite it."
    )


def export_json(report, output_file=None):
    """Append report(s) to an existing JSON file (as a list) or create a new one."""
    reports = report if isinstance(report, list) else [report]

    if not output_file:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
        return

    existing_data = _load_existing_json(output_file)
    existing_data.extend(reports)
    _atomic_write(output_file, json.dumps(existing_data, indent=2))
    status(f"Report saved to {output_file}")


def _format_score(score):
    """Render a 0-4 score as 'N/4', or 'N/A' if the score is missing."""
    return f"{score}/4" if score is not None else "N/A"


def _report_to_csv_row(report):
    """Format a report dictionary into a row matching CSV_HEADERS."""
    breach_count = report.get("breach", {}).get("count")
    return [
        report.get("timestamp", ""),
        report.get("password_hash") or "",
        report.get("verdict", ""),
        report.get("crack_time", ""),
        report.get("complexity", {}).get("length", ""),
        _format_score(report.get("complexity", {}).get("score")),
        report.get("complexity", {}).get("verdict", ""),
        _format_score(report.get("strength", {}).get("score")),
        report.get("breach", {}).get("status", ""),
        breach_count if breach_count is not None else "N/A",
        report.get("breach", {}).get("note", ""),
        "; ".join(report.get("reasons", [])),
    ]


def _rows_to_csv_text(rows, include_header):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if include_header:
        writer.writerow(CSV_HEADERS)
    writer.writerows(rows)
    return buffer.getvalue()


def export_csv(report, output_file=None):

    reports = report if isinstance(report, list) else [report]
    rows = [_report_to_csv_row(r) for r in reports]

    if not output_file:
        print(_rows_to_csv_text(rows, include_header=True).strip())
        return

    has_content = os.path.exists(output_file) and os.path.getsize(output_file) > 0
    text = _rows_to_csv_text(rows, include_header=not has_content)

    with open(output_file, "a", newline="", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    status(f"Report saved to {output_file}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Password Hygiene Checker - evaluate password strength, patterns, and breach status."
    )
    stdout_format = parser.add_mutually_exclusive_group()
    stdout_format.add_argument(
        "--json",
        action="store_true",
        help="Print the structured report as JSON to stdout.",
    )
    stdout_format.add_argument(
        "--csv",
        action="store_true",
        help="Print the structured report as CSV to stdout.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Also save the report to FILE (.json or .csv). Appends if the file exists.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        help="Format for --output (defaults to the file extension, else json).",
    )

    args = parser.parse_args(argv)

    if args.format and not args.output:
        parser.error("--format only applies to --output; use --json or --csv for stdout.")

    return args


def resolve_output_format(args):

    if args.format:
        return args.format
    return "csv" if args.output.lower().endswith(".csv") else "json"


def main(argv=None):
    args = parse_args(argv)
    user_password = getpass("Please enter the password : ")
    if not user_password:
        status("No password entered - nothing to check.")
        return 1

    complexity_result = complexity.check_complexity(user_password)
    strength_result = strength.analyze_strength(user_password)
    hibp_result = hibp.check_pwned_password(user_password)
    password_hash = hash_password(user_password)

    report = build_report(
        complexity_result, strength_result, hibp_result, password_hash=password_hash
    )

    # Always archive to report.csv, unless --output already points there
    # (which would write the same run twice).
    already_archiving = args.output is not None and os.path.abspath(
        args.output
    ) == os.path.abspath(DEFAULT_CSV_PATH)
    if not already_archiving:
        export_csv(report, DEFAULT_CSV_PATH)

    if args.output:
        if resolve_output_format(args) == "csv":
            export_csv(report, args.output)
        else:
            export_json(report, args.output)

    if args.csv:
        export_csv(report)
    elif args.json:
        export_json(report)
    elif not args.output:
        print_report(report)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
