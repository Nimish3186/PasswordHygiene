import math
import os
import secrets

WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")

DICE_SIDES = 6
ROLLS_PER_WORD = 4  # 6^4 == 1296 == len(EFF short list)
EXPECTED_WORDLIST_SIZE = DICE_SIDES ** ROLLS_PER_WORD

DEFAULT_NUM_WORDS = 6
DEFAULT_SEPARATOR = "."  # not "-": the list contains "yo-yo"


class WordlistError(RuntimeError):
    """Raised when the wordlist is missing, malformed, or incomplete."""
def _load_wordlist(path=WORDLIST_PATH):

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = [line.strip() for line in f if line.strip()]
    except OSError as e:
        raise WordlistError(f"Could not read the Diceware wordlist at {path}: {e}") from e

    mapping = {}
    for lineno, line in enumerate(raw_lines, start=1):
        parts = line.split()
        if len(parts) != 2:
            raise WordlistError(f"{path}:{lineno}: expected 'code word', got {line!r}")
        code, word = parts
        if len(code) != ROLLS_PER_WORD or any(c not in "123456" for c in code):
            raise WordlistError(f"{path}:{lineno}: {code!r} is not a valid dice code")
        if code in mapping:
            raise WordlistError(f"{path}:{lineno}: duplicate dice code {code}")
        mapping[code] = word

    if len(mapping) != EXPECTED_WORDLIST_SIZE:
        raise WordlistError(
            f"{path} maps {len(mapping)} codes, expected {EXPECTED_WORDLIST_SIZE}. "
            "An incomplete list would produce weaker passphrases than reported."
        )
    return mapping


WORDS_BY_CODE = _load_wordlist()
WORDS = sorted(WORDS_BY_CODE.values())

BITS_PER_WORD = math.log2(len(WORDS_BY_CODE))


def roll_dice(count=ROLLS_PER_WORD):

    return [secrets.randbelow(DICE_SIDES) + 1 for _ in range(count)]


def roll_word():

    code = "".join(str(d) for d in roll_dice())
    return WORDS_BY_CODE[code], code


def passphrase_entropy_bits(num_words=DEFAULT_NUM_WORDS):

    return num_words * BITS_PER_WORD


def generate_passphrase(num_words=DEFAULT_NUM_WORDS, separator=DEFAULT_SEPARATOR):

    if num_words < 1:
        raise ValueError("num_words must be at least 1")
    return separator.join(roll_word()[0] for _ in range(num_words))


def generate_with_rolls(num_words=DEFAULT_NUM_WORDS, separator=DEFAULT_SEPARATOR):

    rolled = [roll_word() for _ in range(num_words)]
    phrase = separator.join(word for word, _ in rolled)
    return phrase, [(code, word) for word, code in rolled]


if __name__ == "__main__":
    phrase, rolls = generate_with_rolls()
    print("Diceware passphrase")
    print("-" * 40)
    for code, word in rolls:
        print(f"  {code}  ->  {word}")
    print("-" * 40)
    print(f"  {phrase}")
    print(
        f"\n  {len(WORDS_BY_CODE)}-word list, {DEFAULT_NUM_WORDS} words "
        f"= ~{passphrase_entropy_bits():.0f} bits of entropy"
    )
