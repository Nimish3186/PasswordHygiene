# Password Hygiene Checker — TODO

Status snapshot as of 2026-08-16.

## Done

- [x] `complexity.py` — length + character-class scoring, returns a dict (length, class booleans, score, verdict)
- [x] `strength.py` — zxcvbn wrapper (score, crack_time, feedback)
- [x] `hibp.py` — HIBP k-Anonymity breach check, returns int count / 0 / None
- [x] `main.py` — orchestrates all three, breach result overrides verdict, prints a combined report

## In Progress / Owned

### Ragnar
- [ ] **Logging with password redaction**
  - [ ] Use `logging` module (not raw `print`-to-file); INFO for normal checks, WARNING for compromised hits
  - [ ] Log only: timestamp, verdict, breach count, score, length bucket — never the raw password or full hash
  - [ ] Hook into `build_report()` in `main.py`, one log line per check
  - [ ] Verify: grep the log file after a test run, confirm zero plaintext passwords/exception leaks
- [ ] **Single-password PDF report**
  - [ ] Pick library (`fpdf2` recommended for simplicity)
  - [ ] Reuse `build_report()`'s dict as-is — no recomputation, just render it
  - [ ] Layout: header (title, timestamp, case/reference field), verdict block, reasons list, footer note that the password was never stored
  - [ ] Never include the real password in the PDF — mask if showing anything password-shaped
  - [ ] Timestamp-based filenames, not password-derived

### Teammates
- [ ] **Batch/audit mode** — read a file of credentials, loop `main.py`'s logic per line, output a CSV/report of hygiene status per entry
- [ ] **Passphrase generator** — suggest a diceware-style passphrase when a password fails, instead of just rejecting it
- [x] **Structured export (JSON)** — dump `build_report()`'s output as JSON, so batch mode / future dashboard can consume it directly

## Not Started / Backlog

- [ ] `test.py` — expand beyond the single zxcvbn sanity check; add cases for empty password, known-breached password, strong random password, and a simulated network failure (to test `hibp.py`'s `None` path)
- [ ] `README.md` — currently empty; write once behavior is locked (what it does, install steps, how to run, note on k-Anonymity privacy model)
- [ ] Decide: offline HIBP mode (local hash-dump lookup, no API call) — worth discussing as a stretch goal, valuable for air-gapped/forensic use
- [ ] NIST 800-63B alignment note — short explanation in README of why length-over-complexity and breach-checking were prioritized

## Open Design Questions

- [ ] Confirm final shape of `build_report()`'s output dict before batch mode / PDF / JSON export all start depending on it — changing it later means touching multiple files
- [ ] Decide how `hibp_result is None` (breach check unavailable) should surface in batch mode output — same "not checked" distinction as the CLI, or treated differently at scale
