from tkinter import Scrollbar
from unittest import result


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

    if score == 1 :
        result = ("Weak Password")
    elif score in [2,3] and length >= 8 :
        result = ("Moderately strong password")
    elif score == 4 and length >=11 :
        result = ("good enough strength")
    else:
        result = "cases to be added in process"

    return result

result = check_complexity("Heloo1233#")
print(result)