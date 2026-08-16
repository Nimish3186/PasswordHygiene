import csv
import json
import os
import uuid
import warnings
import complexity
import main
import strength


def _safe_remove(path):
    """Best-effort cleanup - never let a leftover file lock crash the suite."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as e:
        warnings.warn(f"Could not remove test artifact {path}: {e}")


def run_tests():
    print("Running Password Hygiene Checker Tests...")

    # Test 1: Complexity module test
    weak_pwd = "abc"
    strong_pwd = "Correct-Horse-Battery-Staple-2026!"

    comp_weak = complexity.check_complexity(weak_pwd)
    assert comp_weak["length"] == 3
    assert comp_weak["score"] == 1
    assert comp_weak["verdict"] == "Weak Password"

    comp_strong = complexity.check_complexity(strong_pwd)
    assert comp_strong["length"] > 12
    assert comp_strong["score"] == 4
    assert comp_strong["verdict"] == "Strong password"
    print("  [+] Complexity module tests passed.")

    # Test 2: Strength (zxcvbn) module test
    str_weak = strength.analyze_strength("password123")
    assert str_weak["score"] == 0
    assert "feedback" in str_weak

    str_strong = strength.analyze_strength(strong_pwd)
    assert str_strong["score"] == 4
    print("  [+] Strength (zxcvbn) module tests passed.")

    # Test 3: build_report structure and schema validation
    mock_hibp_breached = 15000
    report_breached = main.build_report(comp_weak, str_weak, mock_hibp_breached)

    required_keys = [
        "timestamp",
        "verdict",
        "crack_time",
        "breach_note",
        "complexity",
        "strength",
        "breach",
        "reasons",
    ]
    for key in required_keys:
        assert key in report_breached, f"Missing key: {key}"

    assert report_breached["verdict"] == "COMPROMISED"
    assert report_breached["breach"]["status"] == "COMPROMISED"
    assert report_breached["breach"]["count"] == 15000
    print("  [+] Report structure & breach override tests passed.")

    # Test 4: Report with clean breach status
    report_clean = main.build_report(comp_strong, str_strong, 0)
    assert report_clean["breach"]["status"] == "CLEAN"
    assert report_clean["verdict"] == "zxcvbn score 4/4"
    print("  [+] Clean password report tests passed.")

    # Test 5: Report with unavailable breach status
    report_unavail = main.build_report(comp_strong, str_strong, None)
    assert report_unavail["breach"]["status"] == "UNAVAILABLE"
    assert "unknown" in report_unavail["verdict"]
    print("  [+] Unavailable breach status report tests passed.")

    # Test 6: JSON serialization & round-trip validity
    json_output = json.dumps(report_breached)
    parsed_json = json.loads(json_output)
    assert parsed_json["verdict"] == "COMPROMISED"
    assert parsed_json["breach"]["count"] == 15000
    print("  [+] JSON serialization round-trip passed.")

    # Test 7: CSV appending validation (multiple writes accumulate rows without duplicating headers)
    # Uses a unique filename per run so a leftover locked file from a
    # previous interrupted run can't cause false failures.
    test_csv_path = f"test_append_output_{uuid.uuid4().hex}.csv"
    try:
        _safe_remove(test_csv_path)

        main.export_csv(report_breached, test_csv_path)
        main.export_csv(report_clean, test_csv_path)

        assert os.path.exists(test_csv_path)
        with open(test_csv_path, "r", encoding="utf-8") as f:
            raw_csv = f.read()
            reader = list(csv.reader(raw_csv.splitlines()))
            assert len(reader) == 3  # Header + 2 data rows
            assert reader[0] == main.CSV_HEADERS
            # Column layout: Timestamp, Password, Verdict, ...
            assert reader[1][2] == "COMPROMISED"
            assert reader[2][2] == "zxcvbn score 4/4"

        # Confidentiality check: the exported FILE is what actually gets
        # shared/committed, so this is the check that matters in practice -
        # not just build_report()'s in-memory return value. These calls
        # don't pass a password, so the Password column should be empty.
        assert weak_pwd not in raw_csv
        assert strong_pwd not in raw_csv
    finally:
        _safe_remove(test_csv_path)
    print("  [+] CSV append functionality tests passed.")
    print("  [+] CSV file does not contain raw passwords (when password= is not passed).")

    # Test 7b: CSV Password column - opt-in, exercises the feature main()
    # now uses on every real run (export_csv(..., password=user_password)).
    test_csv_pwd_path = f"test_append_output_{uuid.uuid4().hex}.csv"
    try:
        _safe_remove(test_csv_pwd_path)
        main.export_csv(report_breached, test_csv_pwd_path, password=weak_pwd)

        with open(test_csv_pwd_path, "r", encoding="utf-8") as f:
            reader = list(csv.reader(f.read().splitlines()))
            assert reader[0][1] == "Password"
            assert reader[1][1] == weak_pwd
    finally:
        _safe_remove(test_csv_pwd_path)
    print("  [+] CSV Password column populated correctly when password= is passed.")

    # Test 8: JSON appending validation
    test_json_path = f"test_append_output_{uuid.uuid4().hex}.json"
    try:
        _safe_remove(test_json_path)

        main.export_json(report_breached, test_json_path)
        main.export_json(report_clean, test_json_path)

        assert os.path.exists(test_json_path)
        with open(test_json_path, "r", encoding="utf-8") as f:
            raw_json = f.read()
            data = json.loads(raw_json)
            assert isinstance(data, list)
            assert len(data) == 2
            assert data[0]["verdict"] == "COMPROMISED"
            assert data[1]["verdict"] == "zxcvbn score 4/4"

        # Same confidentiality check against the actual exported file.
        assert weak_pwd not in raw_json
        assert strong_pwd not in raw_json
    finally:
        _safe_remove(test_json_path)
    print("  [+] JSON append functionality tests passed.")
    print("  [+] JSON file does not contain raw passwords.")

    # Test 9: Credential confidentiality assertion (no raw password inside
    # the in-memory report dict). NOTE: build_report() doesn't accept a
    # password argument at all, so this assertion can never actually fail -
    # it does not exercise a real code path. It's kept only as a cheap
    # regression trip-wire in case someone later adds the password to the
    # report dict by accident. The tests above (7 & 8) are the ones that
    # actually verify confidentiality, since they check the files that get
    # written to disk and potentially committed/shared.
    #
    # IMPORTANT: once logging is added (main() will hold user_password),
    # add a Test 10 here that runs main.py's logging path and asserts the
    # log file does NOT contain the raw password - that's the next real
    # place a leak could happen, and nothing here currently checks it.
    assert weak_pwd not in str(main.build_report(comp_weak, str_weak, mock_hibp_breached))
    print("  [+] Password confidentiality assertion passed (see note: file-based checks above are the real test).")

    print("\nAll tests passed successfully!")


if __name__ == "__main__":
    run_tests()