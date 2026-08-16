# Password Hygiene Checker

A command-line tool that evaluates password strength across three layers:
basic complexity, pattern/dictionary analysis, and real-world breach status.
Built for a college cyber cell project.

## Why three layers?

A password can look complex and still be worthless — `Password123!` passes
most regex rules but is one of the first guesses any cracking tool tries.
Real password hygiene needs all three checks together:

| Layer | Module | What it catches |
|---|---|---|
| Basic complexity | `complexity.py` | Length, character variety |
| Pattern & dictionary | `strength.py` (zxcvbn) | Common words, keyboard walks, dates, l33t substitutions |
| Breach status | `hibp.py` (HIBP API) | Whether this exact password has already been exposed |

A password found in a known breach is treated as **compromised regardless
of score** — complexity doesn't matter once a password is public.

## How the breach check stays private

`hibp.py` never sends your password, or even its full hash, anywhere:

1. The password is hashed locally with SHA-1.
2. Only the **first 5 characters** of that hash are sent to the
   [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords)
   Pwned Passwords API.
3. The API returns every breached hash suffix sharing that prefix
   (typically several hundred).
4. The real password is matched against that list **locally** — the full
   hash and the password itself never leave the machine.

This is the k-Anonymity model HIBP recommends for exactly this use case.

## Project structure

```
complexity.py   # length + character-class scoring
strength.py     # zxcvbn wrapper (pattern/dictionary analysis)
hibp.py         # HIBP k-Anonymity breach check
main.py         # orchestrates all three, builds and prints the report
test.py         # sanity checks
TODO.md         # remaining work / roadmap
```

## Setup

```bash
pip install zxcvbn requests
```

## Usage

```bash
python main.py
```

You'll be prompted for a password (input is hidden via `getpass`). The tool
prints a verdict, breach status, estimated crack time, and a list of
specific reasons if the password is weak.

**Every run is also archived to `report.csv`** in the project folder,
including the password in plaintext (a `Password` column). This happens
automatically regardless of which flags you use. `report.csv` is
gitignored so it never gets committed, but be aware it accumulates real
plaintext passwords over time - treat it as sensitive data, store it
somewhere access-controlled, and delete it when it's no longer needed.

Use `-o FILE` to additionally save to a different file, or `--csv`/`--json`
to print a structured report to stdout instead of the human-readable
summary.

Example output:

```
--- Password Hygiene Report ---
Verdict     : COMPROMISED
Breach check: Found in 2,861,322 known data breaches.
Crack time  : less than a second
Why / how to improve:
  - Length is only 8 - aim for 12+.
  - This is similar to a commonly used password
  - Found in 2,861,322 known data breaches.
```

## Design notes

- Each module returns structured data (dicts / ints), never a plain string
  verdict — `main.py` combines the raw results and decides the wording.
  This keeps decision logic and presentation separate, so the report format
  can change without touching the underlying checks.
- The password itself is never logged, written to disk, or included in any
  error message.
- If the breach check can't run (no network, API error), the tool reports
  breach status as "unavailable" rather than silently treating the
  password as clean.

## Status / roadmap

See [`TODO.md`](./TODO.md) for what's built and what's planned (batch mode,
PDF reports, audit logging, passphrase suggestions).

## References

- [zxcvbn](https://github.com/dropbox/zxcvbn) — Dropbox's password strength estimator
- [Have I Been Pwned — Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — digital identity guidelines (length over forced complexity, breach checking)
