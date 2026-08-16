import zxcvbn

# Returned for an empty password instead of calling zxcvbn, which raises
# IndexError on "" rather than reporting a score of 0.
_EMPTY_RESULT = {
    "score": 0,
    "crack_time": "less than a second",
    "feedback": {
        "warning": "No password entered.",
        "suggestions": ["Enter a password to analyse."],
    },
}


def analyze_strength(password):
    """Run zxcvbn and return score (0-4), crack time estimate, and feedback.

    The crack time reported is the offline-slow-hashing estimate (1e4
    guesses/sec). That is the most realistic threat model here: it assumes
    an attacker who has stolen a password database that used a proper slow
    hash. Online-throttled estimates would flatter weak passwords.
    """
    if not password:
        # dict(...) so callers can't mutate the shared constant.
        return {**_EMPTY_RESULT, "feedback": dict(_EMPTY_RESULT["feedback"])}

    result = zxcvbn.zxcvbn(password)
    return {
        "score": result["score"],
        "crack_time": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "feedback": result["feedback"],
    }


if __name__ == "__main__":
    for demo in ("password123", "Correct-Horse-Battery-Staple-2026!"):
        r = analyze_strength(demo)
        print(f"{demo!r}: score {r['score']}/4, crack time {r['crack_time']}")
