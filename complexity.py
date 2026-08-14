
def check_complexity(password):
    has_lower = False
    has_upper = False
    has_digit = False
    has_symbol= False
    length = len(password)

    # if length <=8:
    #     print("Weak")
    # elif length >=8 and length <=11 :
    #     print("Moderate")
    # else :
    #     print("strong")


    for i in password :
        if i.isupper():
            has_upper = True
        elif i.islower():
            has_lower = True
        elif i.isdigit():
            has_digit=True
        else :
            has_symbol = True

    score = has_symbol+has_digit+has_lower+has_upper
    if length < 8:
        verdict = "Weak Password"
    elif length < 12:
        if score <= 1:
            verdict = "Weak Password"
        else:
            verdict = "Moderately strong password"
    else:
        if score <= 1:
            verdict = "Weak Password"
        elif score in (2, 3):
            verdict = "Moderately strong password"
        else:
            verdict = "Strong password"

    return {
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "score": score,
        "verdict": verdict,
    }


if __name__ == '__main__':
    result = check_complexity("Heloo123")
    print(result)