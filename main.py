import complexity
import strength
import hibp
from getpass import getpass


def build_report(complexity_result, strength_result, hibp_result):

    reasons = []

    #  complexity
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

    #  zxcvbn
    warning = strength_result["feedback"]["warning"]
    if warning:
        reasons.append(warning)
    reasons.extend(strength_result["feedback"]["suggestions"])

    #  breach feedback + final result
    if hibp_result is None:
        breach_note = "Breach check unavailable (no network / API error)."
        verdict = f"zxcvbn score {strength_result['score']}/4 (breach status unknown)"
    elif hibp_result > 0:
        breach_note = f"Found in {hibp_result:,} known data breaches."
        reasons.append(breach_note)
        verdict = "COMPROMISED"
    else:
        breach_note = "Not found in any known breach."
        verdict = f"zxcvbn score {strength_result['score']}/4"

    return {
        "verdict": verdict,
        "breach_note": breach_note,
        "crack_time": strength_result["crack_time"],
        "reasons": reasons,
    }


def print_report(report):
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


if __name__ == "__main__":
    user_password = getpass("Please enter the password : ")
    print(user_password)
    print("===The Password is printed for demonstration purposes")

    complexity_result = complexity.check_complexity(user_password)
    strength_result = strength.analyze_strength(user_password)
    hibp_result = hibp.check_pwned_password(user_password)

    report = build_report(complexity_result, strength_result, hibp_result)

    print_report(report)