# ALU Regex Data Extraction & Secure Validation

**Author:** mwayo-tech
**Language:** Python 3

## What this does

Reads a messy, realistic block of "support ticket export" text (`input/raw-text.txt`)
and pulls out four kinds of structured data using regex:

1. **Email addresses** — general, plus three ALU-specific categories:
   `@alueducation.com`, `@alumni.alueducation.com`, `@si.alueducation.com`
2. **Credit card numbers** — Visa, Mastercard, Amex, checked against the
   Luhn algorithm so obviously fake numbers are rejected, not just "16
   digits in a row"
3. **URLs** — `http://` / `https://` links
4. **Phone numbers** — loose international formats (`+250 788 123 456`,
   `(078) 234-5678`, `233-24-555-0199`, etc.)

Results are printed to the console (with sensitive fields masked) and
written as structured JSON to `output/sample-output.json`.

## How to run it

```bash
python3 src/main.py
```

No dependencies beyond the Python standard library (`re`, `json`, `os`).
Requires Python 3.10+ (uses the `str | None` type hint syntax).

The script always reads from `input/raw-text.txt` and always writes to
`output/sample-output.json`, so just running it from the project root is
enough — no arguments needed.

## Project structure

```
alu-regex-data-extraction_mwayo-tech/
├── input/
│   └── raw-text.txt        # realistic, messy sample input (fake data only)
├── src/
│   └── main.py              # all extraction + validation logic, heavily commented
├── output/
│   └── sample-output.json   # sample run output, safe to check in
└── README.md
```

## How the extraction works

Each line of the input is:

1. **Screened for hostile content** (`is_suspicious`). Lines containing
   `<script>` tags, inline event handlers (`onclick="..."`), SQL injection
   patterns (`DROP TABLE`, `UNION SELECT`), prompt-injection style phrases
   ("ignore all previous instructions"), or abnormally long/repetitive
   character runs are **skipped entirely** — they never reach the
   extraction regexes. This is the "not all input is trustworthy" behaviour
   the assignment asks for: the program actively looks for signs the text
   is trying to manipulate it, rather than assuming everything is safe to
   parse.
2. Run through each regex (**emails, URLs, credit cards, phones**), in that
   order. Credit card matches are found first and their character
   positions recorded, so the phone-number pass can skip over digit groups
   that already belong to a card number (a 16-digit card split into groups
   of 4 looks exactly like a phone number otherwise).
3. **Deduplicated and capped** per category (`MAX_MATCHES_PER_CATEGORY`) so
   a pathological input file can't blow up the output.

### Why these particular regex patterns

- **Emails**: the local part is bounded (`{0,63}`) and the domain requires
  a real-looking multi-label structure with a proper TLD, so junk like
  `a@@b,com`, `@missing.com`, or `john.doe@@@mail,com` (all present in the
  sample input on purpose) correctly fail to match.
- **ALU domain classification** checks `alumni.alueducation.com` and
  `si.alueducation.com` *before* the generic `alueducation.com` suffix.
  Both subdomains end in `alueducation.com`, so checking the generic
  suffix first would silently mis-classify every alumni/SI address as a
  plain official one.
- **Credit cards** use brand-specific prefixes (Visa `4`, Mastercard
  `51`–`55`, Amex `34`/`37`) with the standard human-typed grouping
  (spaces or dashes, or none). A regex match only tells you "this looks
  like a card number shape" — it says nothing about whether it's
  *well-formed*. That's what the Luhn checksum in `luhn_valid()` is for:
  it's run on every match, and only Luhn-valid numbers are reported as
  `"valid"` in the JSON output; the rest are reported separately under
  `"rejected_failed_luhn"` so you can see the validation step actually did
  something instead of trusting the regex alone.
- **URLs** only match `http://` / `https://`, deliberately excluding
  schemes like `javascript:` or `data:` that are common in real-world XSS
  payloads — we don't want the "URL extractor" to also be a way to smuggle
  a dangerous link into the report.
- **Phone numbers** are matched broadly by regex (regex alone is a bad tool
  for validating a phone number — country formats vary too much) and then
  filtered in plain Python (`validate_phone`): the total digit count must
  be 7–15 (matching the international E.164 range), and numbers made of a
  single repeated digit (`0000000000`) are rejected as obviously fake.

## Security considerations

- **Input size limit** (`MAX_FILE_SIZE_BYTES`) — refuses to process a file
  over 2 MB, so a huge/malicious file can't be used to exhaust memory.
- **Per-line length limit** (`MAX_LINE_LENGTH`) — lines over 2000 characters
  are treated as suspicious and skipped, since abnormally long lines are a
  classic way to try to trigger slow regex behaviour.
- **No catastrophic backtracking** — every regex in this file uses bounded
  quantifiers (`{0,63}`, `{1,5}`, etc.) with no nested unbounded groups
  (nothing shaped like `(\d+)+`), so none of them can be forced into
  exponential-time matching (ReDoS) by adversarial input.
- **Sensitive data is masked, not logged in full**:
  - Credit card numbers: only `luhn_valid()` ever sees the full digit
    string, purely to compute the checksum. Everywhere else — console
    output and the JSON report — only `mask_card()`'s last-4-digits form
    is used. The full number is never written to disk or printed.
  - Emails: the JSON report keeps the full address (that *is* the
    requested extracted data), but the console summary prints a masked
    version (`mask_email_for_log`) — a reminder that a real production
    system shouldn't casually dump PII into logs even when it's fine to
    return it in an API response.
- **Malicious content is screened out, not just "matched around"** — see
  `is_suspicious()` / `SUSPICIOUS_PATTERNS` above. The sample input file
  intentionally includes a `<script>` XSS attempt, a SQL injection
  attempt, and a prompt-injection-style line, all of which are correctly
  skipped (see `lines_skipped_as_suspicious` in the JSON output).

## Known limitations (honest notes, not bugs)

- Phone regex won't catch bare country-code prefixes without a leading
  `+` in every position (e.g. it grabs `24-555-0199` from
  `233-24-555-0199` rather than the full international number) — real
  phone validation really wants a library like `phonenumbers`, which is
  out of scope for a pure-regex assignment.
- URL regex requires an explicit `http(s)://` scheme, so bare
  `www.example.com` text is intentionally not extracted as a URL.
- The Luhn check confirms a card number is *well-formed*, not that it's
  real, active, or unauthorized to use — that would require talking to a
  card network, which is out of scope here.

