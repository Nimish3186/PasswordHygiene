"""Basic complexity scoring: length plus character-class variety.

This is the weakest of the three checks and is here for completeness, not
authority. `Password1!` scores full marks and is still terrible - that is
exactly what strength.py (zxcvbn) and hibp.py exist to catch. NIST SP
800-63B explicitly recommends against enforcing composition rules like
these; length and breach status matter far more.
"""


def check_complexity(password):
    """Return length, which character classes are present, a 0-4 score, and a verdict."""
    has_lower = has_upper = has_digit = has_symbol = has_space = False

    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        elif char.isspace():
            # Counted separately: whitespace was previously lumped in with
            # symbols, so "hello world" scored a symbol class it doesn't
            # really have. Spaces are welcome in passphrases, they just
            # aren't punctuation.
            has_space = True
        else:
            has_symbol = True

    length = len(password)
    score = has_lower + has_upper + has_digit + has_symbol

    if length < 8:
        verdict = "Weak Password"
    elif length < 12:
        verdict = "Weak Password" if score <= 1 else "Moderately strong password"
    elif score <= 1:
        verdict = "Weak Password"
    elif score <= 3:
        verdict = "Moderately strong password"
    else:
        verdict = "Strong password"

    return {
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "has_space": has_space,
        "score": score,
        "verdict": verdict,
    }


if __name__ == "__main__":
    for demo in ("Heloo123", "abc", "Correct-Horse-Battery-Staple-2026!"):
        print(f"{demo!r}: {check_complexity(demo)}")
