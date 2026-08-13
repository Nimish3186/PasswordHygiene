import zxcvbn

def analyze_strength(password):
    result = zxcvbn.zxcvbn(password)
    feedback = result['feedback']
    score = result['score']
    crack_time = result["crack_times_display"]['offline_slow_hashing_1e4_per_second']

    return {
        "score": score,
        "crack_time": crack_time,
        "feedback": feedback
    }


