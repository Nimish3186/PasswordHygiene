import csv
import json
import os
import complexity
import main
import strength


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
    test_csv_path = "test_append_output.csv"
    try:
        if os.path.exists(test_csv_path):
            os.remove(test_csv_path)

        main.export_csv(report_breached, test_csv_path)
        main.export_csv(report_clean, test_csv_path)

        assert os.path.exists(test_csv_path)
        with open(test_csv_path, "r", encoding="utf-8") as f:
            reader = list(csv.reader(f))
            assert len(reader) == 3  # Header + 2 data rows
            assert reader[0] == main.CSV_HEADERS
            assert reader[1][1] == "COMPROMISED"
            assert reader[2][1] == "zxcvbn score 4/4"
    finally:
        if os.path.exists(test_csv_path):
            os.remove(test_csv_path)
    print("  [+] CSV append functionality tests passed.")

    # Test 8: JSON appending validation
    test_json_path = "test_append_output.json"
    try:
        if os.path.exists(test_json_path):
            os.remove(test_json_path)

        main.export_json(report_breached, test_json_path)
        main.export_json(report_clean, test_json_path)

        assert os.path.exists(test_json_path)
        with open(test_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert isinstance(data, list)
            assert len(data) == 2
            assert data[0]["verdict"] == "COMPROMISED"
            assert data[1]["verdict"] == "zxcvbn score 4/4"
    finally:
        if os.path.exists(test_json_path):
            os.remove(test_json_path)
    print("  [+] JSON append functionality tests passed.")

    # Test 9: Credential confidentiality assertion (no raw password inside report)
    assert weak_pwd not in str(main.build_report(comp_weak, str_weak, mock_hibp_breached))
    print("  [+] Password confidentiality assertion passed.")

    print("\nAll tests passed successfully!")


if __name__ == "__main__":
    run_tests()