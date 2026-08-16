# Password Hygiene Checker — TODO

Last updated: 2026-08-16

---

## Built and working

| Piece | File | Notes |
|---|---|---|
| Complexity scoring | `complexity.py` | Length + character classes; tracks whitespace separately |
| Pattern analysis | `strength.py` | zxcvbn wrapper; returns 0 for empty input instead of crashing |
| Breach lookup | `hibp.py` | k-anonymity, `Add-Padding` header, survives malformed replies |
| Diceware generator | `passphrase.py` | 1296-word EFF list, ~62 bits, dice rolls auditable |
| Report builder | `main.py` | Combines all three; breach result overrides the verdict |
| JSON / CSV export | `main.py` | `--json`, `--csv`, `-o FILE`; appends safely, never clobbers |
| Auto-archive | `main.py` | Every run appended to `report.csv` |
| Test suite | `test.py` | 13 groups; runs in a tempdir, leaves no artifacts |
| Docs | `README.md` | Setup, usage, and the privacy model explained |

---

## Next up — 4 small additions

These are deliberately small. Each is a single evening's work and doesn't
require changing anything that already exists.

### 1. `--passphrase` flag
**What:** Generate a passphrase without checking a password first.

```bash
python main.py --passphrase        # one 6-word passphrase
python main.py --passphrase 4      # four of them, pick your favourite
```

**Why:** Right now you can only get a suggestion by failing a check
first, which is backwards when someone just wants a new password.

**How:** Add the flag in `parse_args()`, and return early in `main()`
before the `getpass` prompt. `passphrase.generate_passphrase()` already
does the actual work.

---

### 2. Password reuse report
**What:** A command that reads `report.csv` and flags any hash appearing
more than once — i.e. the same password checked on different occasions.

```bash
python main.py --reuse
# Hash 49efef5f... appears 3 times (2026-08-14, 2026-08-15, 2026-08-16)
```

**Why:** Reuse is one of the biggest real-world password problems, and
we're *already* storing exactly the data needed to detect it. This is
close to free.

**How:** Read `report.csv` with `csv.DictReader`, count the
`Password Hash (SHA-1)` column with `collections.Counter`, print any
count above 1. Roughly 20 lines. Skip blank hashes.

---

### 3. Batch mode
**What:** Check a file of passwords, one per line, instead of typing one
at a time.

```bash
python main.py --batch passwords.txt -o results.csv
```

**Why:** Checking 200 passwords by hand isn't realistic.

**How:** `build_report()` and `export_csv()` already accept lists, so most
of the work is done. Loop over the lines, build a report for each, pass
the list to the exporter.

Two things to get right:
- **Rate limiting.** Add `time.sleep(0.2)` between HIBP calls — hammering
  the API from a loop will get you throttled.
- **Progress output.** Print `Checked 40/200` to *stderr*, not stdout, or
  it will corrupt `--json` output.

---

### 4. Audit log (`audit.log`)
**What:** A plain-text log of runs, separate from the CSV.

```
2026-08-16 20:05:22 INFO  Checked password (hash 49efef5f...) — score 1/4, CLEAN
2026-08-16 20:07:14 WARN  Checked password (hash a1b2c3d4...) — COMPROMISED, 2,861,322 breaches
```

**Why:** The CSV is for analysis; a log is for "what happened and when."
Useful if this is ever run by more than one person.

**How:** Use the `logging` module, not `print`-to-file. INFO for normal
checks, WARNING for compromised ones. Add a `log_report(report)` function
called from `main()` — **not** from inside `build_report()`, which must
stay free of side effects so batch mode can call it safely.

**Must verify:** after a test run, `grep` the log for the actual password
to confirm nothing leaked. Log the hash, never the password, and never
log a raw exception object (they sometimes carry input values).

---

## Backlog — bigger or undecided

- [ ] **PDF report** for a single check. Use `fpdf2`. Render
      `build_report()`'s existing dict — no recalculating. Header with a
      case/reference field, verdict block, reasons, and a footer noting
      the password was never stored. Filename from the timestamp, never
      from the password.
- [ ] **Offline HIBP mode** — match against a downloaded hash dump
      instead of the API. Valuable for air-gapped or forensic work where
      network calls aren't allowed. Needs a decision on storage: the full
      dump is ~35 GB.
- [ ] **Configurable passphrase length** — expose `num_words` and the
      separator as CLI flags. Trivial, just needs someone to decide the
      defaults.

---

## Open questions

- [ ] **Is the unsalted SHA-1 in `report.csv` acceptable for real cases?**
      Because HIBP publishes ~850 million leaked SHA-1 hashes as a free
      download, any breached password in our log can be reversed by a
      single lookup. Fine for coursework and test data. Needs a decision
      — salted hash, or encryption at rest — before the file ever holds
      genuine case material. *(See the warning in `README.md`.)*
- [ ] **How should "breach check unavailable" behave in batch mode?**
      If the network drops halfway through 200 passwords, do we keep
      going and mark them UNAVAILABLE, or stop and report the failure?
      Silently continuing risks a file full of rows that look checked but
      aren't.
- [ ] **Lock down `build_report()`'s output shape.** Batch mode, the PDF
      report and JSON export will all depend on it, so changing it later
      means touching several files. It gained a `password_hash` key during
      the last review; worth agreeing it's final before building on it.

---

## House rules

Worth keeping to, since a few of these were bugs we already fixed once:

1. **Status messages go to stderr.** stdout carries structured output; a
   stray print there breaks `--json | jq`.
2. **`build_report()` stays pure** — no printing, no file writes. Batch
   mode calls it in a loop.
3. **Never write the password anywhere** — not the CSV, not a log, not an
   error message. Hash it or omit it.
4. **Run `python test.py` before pushing.** It's fast and it has caught
   real regressions.
