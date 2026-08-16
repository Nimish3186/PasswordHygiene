# Password Hygiene Checker

A command-line tool that tells you whether a password is actually any
good — and if it isn't, gives you a better one to use instead.

You type a password in (it stays hidden as you type), and the tool
answers three questions about it:

1. **Is it long and varied enough?**
2. **Is it predictable?** — a common word, a keyboard pattern, a date
3. **Has it already been leaked?** — checked against real breach data

Then it prints a verdict, explains *why*, and suggests a replacement
passphrase if the password was weak.

---

## Why three checks and not one

This is the core idea of the project, so it's worth a moment.

Take `Password123!`. It has an uppercase letter, lowercase letters, a
number and a symbol. It passes the kind of "must contain..." rule most
websites use. It is also one of the first passwords any attacker tries.

Each of our three checks catches something the others miss:

| Check | File | What it catches | What it misses |
|---|---|---|---|
| Complexity | `complexity.py` | Too short, no variety | `Password123!` — looks fine to it |
| Patterns | `strength.py` | Dictionary words, `qwerty`, dates, `p@ssw0rd`-style swaps | A random-looking password that happens to be leaked |
| Breaches | `hibp.py` | Passwords that have appeared in real data leaks | Nothing, but it needs internet |

**A password found in a breach is marked COMPROMISED no matter how
clever it looks.** Once a password is public, complexity is irrelevant.

---

## Setup

You need **Python 3.8 or newer**. Check with:

```bash
python --version
```

**1. Get the code into a folder and open a terminal there.**

**2. Create a virtual environment** (a private space for this project's
libraries, so they don't clash with anything else on your machine):

```bash
python -m venv .venv
```

**3. Activate it** — you'll do this every time you come back to the project:

```bash
# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

You'll know it worked because your prompt now starts with `(.venv)`.

**4. Install the two libraries it needs:**

```bash
pip install -r requirements.txt
```

That's `zxcvbn` (the pattern checker) and `requests` (for the breach
lookup). Setup is done.

---

## Running it

```bash
python main.py
```

It asks for a password. **Nothing appears as you type** — that's
deliberate, not a bug. Press Enter when done.

```
Please enter the password :

--- Password Hygiene Report ---
Verdict     : COMPROMISED
Breach check: Found in 2,861,322 known data breaches.
Crack time  : less than a second
Why / how to improve:
  - Length is only 8 - aim for 12+.
  - This is similar to a commonly used password
  - Found in 2,861,322 known data breaches.

Try a passphrase instead: alias.nutty.scarf.grub.utter.aide
  (~62 bits of entropy, and far easier to remember)
```

### Options

| Command | What it does |
|---|---|
| `python main.py` | Normal readable report (shown above) |
| `python main.py --json` | Print the report as JSON |
| `python main.py --csv` | Print the report as CSV |
| `python main.py -o notes.csv` | Also save to `notes.csv` (adds to it if it exists) |
| `python main.py -o out.txt --format json` | Force a format instead of guessing from the extension |
| `python passphrase.py` | Just generate a passphrase, no checking |
| `python test.py` | Run the test suite |

Progress messages go to *stderr*, so `--json` output stays clean enough
to pipe into other tools:

```bash
python main.py --json | jq .verdict
```

---

## How the breach check keeps your password private

This surprises people, so here's the whole trick.

Your password is **never sent anywhere.** Not the password, not even its
full fingerprint.

1. Your password is converted locally into a 40-character SHA-1
   fingerprint, e.g. `21BD1...E4F49`
2. Only the **first 5 characters** — `21BD1` — are sent to the Have I
   Been Pwned service
3. HIBP sends back *every* leaked fingerprint starting with those 5
   characters, usually several hundred of them
4. Your computer checks the list **locally** for the rest of your
   fingerprint

So HIBP learns that someone, somewhere, has a password starting with
`21BD1` — shared with hundreds of other passwords. It never learns which
one is yours. This is called **k-anonymity**, and it's the method HIBP
itself recommends.

We also send an `Add-Padding` header, which asks HIBP to bulk out short
responses with decoys — otherwise the *size* of the reply could hint at
what you looked up.

---

## About `report.csv`

Every run is automatically saved to `report.csv` in the project folder,
whatever options you used. It's a running log of every check.

The password is **not** written there. Instead the file stores a SHA-1
hash — a one-way fingerprint. That way you can still spot the same
password being used twice (identical fingerprints), without the file
listing real passwords.

> ⚠️ **Still treat `report.csv` as confidential.**
> The fingerprint isn't salted, and HIBP publishes a free list of ~850
> million leaked SHA-1 fingerprints. So if a password in your log has
> ever been in a breach, someone could look it up in that list and
> recover it instantly — no cracking required.
>
> The column **obfuscates** passwords. It does not **protect** them.
> Don't email this file around, and don't commit it. (`.gitignore`
> already blocks it.)

---

## The passphrase suggestion

When a password is compromised or scores below 3 out of 4, the tool
offers a replacement like:

```
alias.nutty.scarf.grub.utter.aide
```

This is generated by **Diceware**: for each word, the computer rolls four
virtual six-sided dice and looks the result up in a 1296-word list
(`wordlist.txt`, the EFF short list). Four dice give exactly
6 × 6 × 6 × 6 = 1296 outcomes, so every word is equally likely.

Six words gives about **62 bits of entropy** — meaning roughly 4.6
billion billion equally likely possibilities, even for an attacker who
knows our exact method and wordlist.

**The size of the wordlist is what makes this safe.** An earlier version
used a hand-written list of 25 words, which produced only ~23 bits —
crackable in seconds. It was suggesting replacements *weaker* than the
passwords it was rejecting.

Run `python passphrase.py` to see the dice rolls alongside the words, so
you can verify any suggestion against the published EFF list yourself.

---

## Project files

```
main.py           Runs everything, builds and prints/saves the report
complexity.py     Length and character-variety scoring
strength.py       Wrapper around the zxcvbn pattern checker
hibp.py           Breach lookup (the k-anonymity part)
passphrase.py     Diceware passphrase generator
wordlist.txt      1296 words, each keyed to a dice roll
test.py           Test suite — run it after any change
requirements.txt  The two libraries needed
report.csv        Auto-generated log of every run (gitignored)
TODO.md           What's planned next
```

**How they fit together:** each checker module returns plain data (a
dictionary or a number) and never decides on wording. `main.py` collects
all three results and decides the verdict and phrasing. That separation
means the report format can change without touching the checks
themselves.

---

## Things worth knowing

- **`hibp.py` returning "unavailable" is not the same as "clean."** If
  there's no internet, the tool says the breach status is unknown rather
  than pretending the password passed.
- **SHA-1 appears twice, for unrelated reasons.** In `hibp.py` it exists
  only so a 5-character prefix can be sent to the API. In `main.py` it
  produces the fingerprint stored in the CSV. Changing one does not
  affect the other.
- **Design follows NIST SP 800-63B**, which recommends prioritising
  length and breach-checking over forced complexity rules. That's why
  `complexity.py` is the least important of the three checks.

---

## References

- [zxcvbn](https://github.com/dropbox/zxcvbn) — Dropbox's password strength estimator
- [Have I Been Pwned — Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [EFF Diceware wordlists](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases)