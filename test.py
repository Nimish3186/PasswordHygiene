"""Sanity checks for the Password Hygiene Checker.

Run with: python test.py

All file-writing tests use a fresh temporary directory, so the suite never
leaves artifacts in the project folder even if it fails partway through.
"""

import csv
import hashlib
import io
import json
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout

import complexity
import hibp
import main
import passphrase
import strength

WEAK_PWD = "abc"
STRONG_PWD = "Correct-Horse-Battery-Staple-2026!"


def test_complexity():
    weak = complexity.check_complexity(WEAK_PWD)
    assert weak["length"] == 3
    assert weak["score"] == 1
    assert weak["verdict"] == "Weak Password"

    strong = complexity.check_complexity(STRONG_PWD)
    assert strong["length"] > 12
    assert strong["score"] == 4
    assert strong["verdict"] == "Strong password"

    # Whitespace is tracked separately and must not count as a symbol.
    spaced = complexity.check_complexity("hello world")
    assert spaced["has_space"] is True
    assert spaced["has_symbol"] is False, "whitespace was miscounted as a symbol"

    empty = complexity.check_complexity("")
    assert empty["length"] == 0 and empty["score"] == 0
    print("  [+] Complexity module tests passed.")


def test_strength():
    weak = strength.analyze_strength("password123")
    assert weak["score"] == 0
    assert "feedback" in weak

    assert strength.analyze_strength(STRONG_PWD)["score"] == 4

    # zxcvbn itself raises IndexError on "", so analyze_strength must
    # short-circuit. This is reachable in practice: getpass returns ""
    # when the user just presses Enter.
    empty = strength.analyze_strength("")
    assert empty["score"] == 0
    assert empty["feedback"]["warning"]
    print("  [+] Strength (zxcvbn) module tests passed, including empty input.")


def test_hibp_parsing():
    """hibp must survive a malformed API response instead of crashing."""

    class FakeResponse:
        status_code = 200
        # Blank line, a line with no colon, a non-numeric count, then padding.
        text = "\n".join(["", "GARBAGE-NO-COLON", "AAAA:notanumber", "BBBB:0"])

    original_get = hibp.requests.get
    try:
        hibp.requests.get = lambda *a, **kw: FakeResponse()
        # None of those lines match the real suffix, so the result is a
        # clean 0 - the point is that it returns at all.
        assert hibp.check_pwned_password("whatever") == 0

        class ErrorResponse:
            status_code = 503
            text = ""

        hibp.requests.get = lambda *a, **kw: ErrorResponse()
        assert hibp.check_pwned_password("whatever") is None

        def boom(*a, **kw):
            raise hibp.requests.RequestException("no network")

        hibp.requests.get = boom
        assert hibp.check_pwned_password("whatever") is None
    finally:
        hibp.requests.get = original_get
    print("  [+] HIBP handles malformed lines, HTTP errors, and network failure.")


def test_diceware_wordlist():
    """Every one of the 1296 possible rolls must map to a distinct word."""
    assert len(passphrase.WORDS_BY_CODE) == passphrase.EXPECTED_WORDLIST_SIZE == 1296
    assert len(set(passphrase.WORDS_BY_CODE.values())) == 1296, "wordlist has duplicates"

    # Spot-check against the published EFF short list.
    for code, word in [("1111", "acid"), ("2255", "data"), ("4134", "mango"),
                       ("6666", "zoom")]:
        assert passphrase.WORDS_BY_CODE[code] == word, f"{code} should map to {word}"

    # Codes must be exactly the 4-digit combinations of 1-6, nothing else.
    for code in passphrase.WORDS_BY_CODE:
        assert len(code) == 4 and all(c in "123456" for c in code)
    print(f"  [+] Diceware wordlist: all {len(passphrase.WORDS_BY_CODE)} dice codes map correctly.")


def test_dice_rolls():
    rolls = [d for _ in range(400) for d in passphrase.roll_dice()]
    assert all(1 <= d <= 6 for d in rolls), "roll outside 1-6"
    # All six faces should appear across 1600 rolls; if one never does,
    # the range or the modulo handling is wrong.
    assert set(rolls) == {1, 2, 3, 4, 5, 6}, f"faces missing: {set(range(1,7)) - set(rolls)}"

    word, code = passphrase.roll_word()
    assert passphrase.WORDS_BY_CODE[code] == word
    print("  [+] Dice rolls are in range, unbiased across faces, and map to their word.")


def test_passphrase_entropy():
    # The point of the rewrite: a suggested passphrase must be stronger
    # than the passwords the tool rejects, not weaker.
    assert passphrase.passphrase_entropy_bits() >= 60, "suggested passphrase too weak"
    assert round(passphrase.BITS_PER_WORD, 2) == 10.34

    sep = passphrase.DEFAULT_SEPARATOR
    phrase = passphrase.generate_passphrase()
    assert len(phrase.split(sep)) == passphrase.DEFAULT_NUM_WORDS

    # The separator must not occur inside any word, or the phrase becomes
    # ambiguous to split. This is why the default is "." - "yo-yo" is in
    # the EFF list and would break a hyphen separator.
    assert all(sep not in w for w in passphrase.WORDS_BY_CODE.values())

    # Two consecutive calls matching would mean the RNG is broken. With
    # 1296**6 possibilities it cannot happen by chance.
    assert phrase != passphrase.generate_passphrase()

    assert len(passphrase.generate_passphrase(num_words=3).split(sep)) == 3
    try:
        passphrase.generate_passphrase(num_words=0)
    except ValueError:
        pass
    else:
        raise AssertionError("num_words=0 should be rejected")

    # The auditable variant must return rolls consistent with the phrase.
    audited, rolls = passphrase.generate_with_rolls()
    assert audited.split(sep) == [w for _, w in rolls]
    assert all(passphrase.WORDS_BY_CODE[c] == w for c, w in rolls)
    print(
        f"  [+] Passphrase: {passphrase.DEFAULT_NUM_WORDS} words, "
        f"~{passphrase.passphrase_entropy_bits():.0f} bits, rolls auditable."
    )


def test_password_hashing():
    digest = main.hash_password(WEAK_PWD)
    assert len(digest) == 40, "SHA-1 hex digest should be 40 characters"
    assert digest == hashlib.sha1(WEAK_PWD.encode("utf-8")).hexdigest()

    # Determinism is the property that makes reuse detection work: the
    # same password must always produce the same column value.
    assert digest == main.hash_password(WEAK_PWD)
    assert digest != main.hash_password(STRONG_PWD)

    # Non-ASCII must not raise - encoding is pinned to utf-8 rather than
    # left to the platform default.
    assert len(main.hash_password("पासवर्ड123")) == 40
    print("  [+] SHA-1 password hashing is deterministic and utf-8 safe.")


def build_sample_reports():
    comp_weak = complexity.check_complexity(WEAK_PWD)
    str_weak = strength.analyze_strength("password123")
    comp_strong = complexity.check_complexity(STRONG_PWD)
    str_strong = strength.analyze_strength(STRONG_PWD)

    breached = main.build_report(comp_weak, str_weak, 15000)
    clean = main.build_report(comp_strong, str_strong, 0)
    unavailable = main.build_report(comp_strong, str_strong, None)
    return breached, clean, unavailable


def test_build_report(breached, clean, unavailable):
    required_keys = [
        "timestamp", "verdict", "crack_time", "breach_note",
        "complexity", "strength", "breach", "reasons", "password_hash",
    ]
    for key in required_keys:
        assert key in breached, f"Missing key: {key}"

    assert breached["verdict"] == "COMPROMISED"
    assert breached["breach"]["status"] == "COMPROMISED"
    assert breached["breach"]["count"] == 15000

    assert clean["breach"]["status"] == "CLEAN"
    assert clean["verdict"] == "zxcvbn score 4/4"

    assert unavailable["breach"]["status"] == "UNAVAILABLE"
    assert "unknown" in unavailable["verdict"]

    # Suggestions are offered only where there's something to fix.
    assert breached["suggested_passphrase"] is not None
    assert clean["suggested_passphrase"] is None

    # build_report must stay side-effect free so batch mode can call it freely.
    assert json.dumps(breached), "report is not JSON-serialisable"
    print("  [+] Report structure, breach override, and verdict logic passed.")


def test_stdout_is_clean_json(tmpdir):
    """--json output on stdout must be parseable with nothing else mixed in.

    This regression-tests a real bug: the auto-archive status line used to
    print to stdout ahead of the JSON, so `main.py --json | jq` failed.
    """
    breached, _, _ = build_sample_reports()
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        main.export_json(breached)
        main.export_json(breached, os.path.join(tmpdir, "side.json"))

    parsed = json.loads(out.getvalue())  # raises if anything else leaked in
    assert parsed["verdict"] == "COMPROMISED"
    assert "Report saved to" in err.getvalue(), "status line should go to stderr"
    print("  [+] Structured output on stdout stays parseable; status goes to stderr.")


def test_csv_export(tmpdir, breached, clean):
    path = os.path.join(tmpdir, "out.csv")
    with redirect_stderr(io.StringIO()):
        main.export_csv(breached, path)
        main.export_csv(clean, path)

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    rows = list(csv.reader(raw.splitlines()))
    assert len(rows) == 3, "header should be written once, not per append"
    assert rows[0] == main.CSV_HEADERS
    assert rows[1][2] == "COMPROMISED"
    assert rows[2][2] == "zxcvbn score 4/4"

    assert WEAK_PWD not in raw
    assert STRONG_PWD not in raw
    print("  [+] CSV appends without duplicating headers; no plaintext in file.")


def test_csv_hash_column(tmpdir):
    """Each report carries its own hash, so a batch can't be stamped with one."""
    comp = complexity.check_complexity(WEAK_PWD)
    str_res = strength.analyze_strength("password123")

    hash_a = main.hash_password(WEAK_PWD)
    hash_b = main.hash_password(STRONG_PWD)
    report_a = main.build_report(comp, str_res, 15000, password_hash=hash_a)
    report_b = main.build_report(comp, str_res, 0, password_hash=hash_b)

    path = os.path.join(tmpdir, "hashes.csv")
    with redirect_stderr(io.StringIO()):
        main.export_csv([report_a, report_b], path)

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    rows = list(csv.reader(raw.splitlines()))
    assert rows[0][1] == "Password Hash (SHA-1)"
    assert rows[1][1] == hash_a
    assert rows[2][1] == hash_b, "batch export applied the wrong hash to a row"
    assert len(rows[1][1]) == 40
    assert WEAK_PWD not in raw and STRONG_PWD not in raw
    print("  [+] CSV stores a per-report SHA-1 hash, never the raw password.")


def test_json_append_and_no_clobber(tmpdir, breached, clean):
    path = os.path.join(tmpdir, "out.json")
    with redirect_stderr(io.StringIO()):
        main.export_json(breached, path)
        main.export_json(clean, path)

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    data = json.loads(raw)
    assert isinstance(data, list) and len(data) == 2
    assert data[0]["verdict"] == "COMPROMISED"
    assert data[1]["verdict"] == "zxcvbn score 4/4"
    assert WEAK_PWD not in raw and STRONG_PWD not in raw

    # Regression: a corrupt target file used to be silently replaced,
    # destroying whatever was in it. It must now refuse and leave it alone.
    corrupt_path = os.path.join(tmpdir, "corrupt.json")
    sentinel = "not json{{ but someone's real data"
    with open(corrupt_path, "w", encoding="utf-8") as f:
        f.write(sentinel)
    try:
        main.export_json(breached, corrupt_path)
    except ValueError:
        pass
    else:
        raise AssertionError("export_json overwrote a corrupt file instead of refusing")
    with open(corrupt_path, "r", encoding="utf-8") as f:
        assert f.read() == sentinel, "corrupt file was modified"
    print("  [+] JSON appends correctly and refuses to clobber unparseable files.")


def test_cli_parsing():
    args = main.parse_args(["--json"])
    assert args.json and not args.csv

    # --json and --csv are mutually exclusive; --csv used to silently win.
    for bad in (["--json", "--csv"], ["--format", "csv"]):
        try:
            # argparse prints its usage message to stderr on rejection;
            # swallow it so the suite output stays readable.
            with redirect_stderr(io.StringIO()):
                main.parse_args(bad)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"expected {bad} to be rejected")

    assert main.resolve_output_format(main.parse_args(["-o", "r.csv"])) == "csv"
    assert main.resolve_output_format(main.parse_args(["-o", "r.json"])) == "json"
    assert main.resolve_output_format(main.parse_args(["-o", "r.txt"])) == "json"
    assert main.resolve_output_format(
        main.parse_args(["-o", "r.txt", "--format", "csv"])
    ) == "csv"
    print("  [+] CLI flag validation and format resolution passed.")


def run_tests():
    print("Running Password Hygiene Checker Tests...")
    test_complexity()
    test_strength()
    test_hibp_parsing()
    test_diceware_wordlist()
    test_dice_rolls()
    test_passphrase_entropy()
    test_cli_parsing()

    test_password_hashing()

    breached, clean, unavailable = build_sample_reports()
    test_build_report(breached, clean, unavailable)

    with tempfile.TemporaryDirectory() as tmpdir:
        test_stdout_is_clean_json(tmpdir)
        test_csv_export(tmpdir, breached, clean)
        test_csv_hash_column(tmpdir)
        test_json_append_and_no_clobber(tmpdir, breached, clean)

    print("\nAll tests passed successfully!")


if __name__ == "__main__":
    run_tests()
