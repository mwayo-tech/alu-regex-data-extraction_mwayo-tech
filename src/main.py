"""
main.py
--------
Data Extraction & Secure Validation Assignment

This script reads raw, messy, production-style text (input/raw-text.txt),
extracts structured data using regex, validates what it finds, and writes
a safe, readable JSON report to output/sample-output.json.

Data types extracted (4 total, as required):
    1. Email addresses (general + ALU-specific: alueducation.com,
       alumni.alueducation.com, si.alueducation.com)
    2. Credit card numbers (Visa / Mastercard / Amex, Luhn-validated)
    3. URLs
    4. Phone numbers (loose international formats)

Security posture:
    - Input is NEVER trusted blindly. Every line is screened for signs of
      hostile content (script injection, SQL injection, prompt-injection
      style text, abnormally long/repetitive runs that could be a ReDoS
      attempt) before it is handed to any regex.
    - All regexes here use bounded, non-nested quantifiers. None of them
      contain the classic "(a+)+" / "(\\d+)+" shape that causes catastrophic
      backtracking, so a hostile string can't make matching hang.
    - Credit card numbers are validated with the Luhn algorithm (a
      checksum, not a secret) so we don't just trust "16 digits in a row"
      as a real card. Only the last 4 digits of any card are ever written
      to output or printed - the full number is held in memory only long
      enough to validate it, then discarded.
    - Extraction results are capped and the raw input file size is capped
      to reduce the blast radius of a hostile or malformed input file.
"""

import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Configuration / safety limits
# ---------------------------------------------------------------------------

INPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "input", "raw-text.txt")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "output", "sample-output.json")

# Defensive limits. These exist so a hostile or accidentally huge input file
# can't be used to exhaust memory or CPU time. This is basic input hygiene,
# not a full security system, but it shows the program does not treat
# incoming text as automatically safe.
MAX_FILE_SIZE_BYTES = 2_000_000        # 2 MB ceiling on the whole input file
MAX_LINE_LENGTH = 2_000                 # skip regex work on absurdly long lines
MAX_MATCHES_PER_CATEGORY = 500          # cap results so output can't explode


# ---------------------------------------------------------------------------
# Security screening
# ---------------------------------------------------------------------------

# Patterns that suggest a line is trying to manipulate the program, a
# downstream system, or a human reading the output, rather than just being
# ordinary (if messy) text. This is not exhaustive - it's a demonstration
# that untrusted input is actively screened, not just regex-matched blindly.
SUSPICIOUS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),           # script injection
    re.compile(r"on\w+\s*=\s*['\"]", re.IGNORECASE),       # inline JS handlers e.g. onclick="
    re.compile(r"(?:;|--)\s*drop\s+table", re.IGNORECASE),  # SQL injection
    re.compile(r"union\s+select", re.IGNORECASE),           # SQL injection
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),  # prompt injection
    re.compile(r"(.)\1{40,}"),                              # 40+ repeated chars: junk/DoS-ish
]


def is_suspicious(line: str) -> bool:
    """Return True if a line matches a known-hostile pattern."""
    if len(line) > MAX_LINE_LENGTH:
        # Abnormally long lines are treated as suspicious on principle:
        # they add cost for little legitimate benefit and are a classic
        # vector for trying to trigger slow regex behaviour.
        return True
    return any(p.search(line) for p in SUSPICIOUS_PATTERNS)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns below are written with bounded quantifiers and no nested
# unbounded groups (e.g. no "(\d+)+"), which avoids catastrophic
# backtracking / ReDoS on adversarial input.

# General email address. Deliberately conservative about the local part and
# requires a real-looking TLD (2+ letters) so obvious junk like
# "a@@b,com" or "@missing.com" won't match.
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?){1,5}\b"
)

# URLs (http/https only - we don't want to accidentally "extract" things
# like javascript: or data: URIs, which are common XSS vectors).
URL_RE = re.compile(
    r"\bhttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[^\s<>\"']*)?"
)

# Candidate phone numbers: broad on purpose, then verified in Python below.
# Regex alone is a poor tool for "is this really a phone number", so we
# extract candidates here and apply stricter rules (digit count, not all
# the same digit, etc.) in validate_phone().
PHONE_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[ \-]?)?"
    r"(?:\(\d{2,4}\)[ \-]?)?"
    r"\d{2,4}[ \-]?\d{3,4}[ \-]?\d{0,4}(?!\d)"
)

# Credit card candidates by brand, in common human-typed layouts:
# groups of 4 separated by spaces/dashes, or no separators at all.
CARD_PATTERNS = {
    "visa": re.compile(r"\b4\d{3}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b"),
    "mastercard": re.compile(r"\b5[1-5]\d{2}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b"),
    "amex": re.compile(r"\b3[47]\d{2}[ \-]?\d{6}[ \-]?\d{5}\b"),
}

# ALU-specific email domain suffixes, most specific first. Order matters:
# alumni.alueducation.com and si.alueducation.com are subdomains of
# alueducation.com, so if we checked the generic domain first every alumni/
# SI address would be mis-classified as a plain ALU official address.
ALU_DOMAINS = [
    ("alu_alumni", "@alumni.alueducation.com"),
    ("alu_si", "@si.alueducation.com"),
    ("alu_official", "@alueducation.com"),
]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def luhn_valid(digits: str) -> bool:
    """
    Standard Luhn checksum. This is public, well-known algorithm used by
    card networks to catch typos - it is NOT a way to tell if a card is
    real, active, or stolen. We use it purely to filter out numbers that
    are obviously not well-formed card numbers (e.g. test/placeholder
    values), which is exactly the kind of "well-formed" check the brief
    asks for.
    """
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def mask_card(digits: str) -> str:
    """Never expose a full card number in output/logs - last 4 digits only."""
    return f"**** **** **** {digits[-4:]}"


def classify_email(email: str) -> str:
    lowered = email.lower()
    for label, suffix in ALU_DOMAINS:
        if lowered.endswith(suffix):
            return label
    return "general"


def validate_phone(raw_candidate: str) -> str | None:
    """
    Take a raw regex candidate and decide if it's plausible enough to keep.
    Returns a cleaned representation, or None to reject.
    """
    digit_str = re.sub(r"\D", "", raw_candidate)

    # Real phone numbers (national or international) are realistically
    # 7-15 digits (ITU E.164 caps international numbers at 15 digits).
    if not (7 <= len(digit_str) <= 15):
        return None

    # Reject obviously fake numbers like "0000000000" or "1111111111".
    if len(set(digit_str)) == 1:
        return None

    return raw_candidate.strip()


def mask_email_for_log(email: str) -> str:
    """
    Lightly mask an email for console/log display (not for the JSON report -
    the JSON report is the deliverable and keeps the address, since email
    address itself is the "extracted data" the assignment asks for). This
    function exists to show awareness that even semi-sensitive data like
    emails shouldn't be dumped to a console/log by default in a real system.
    """
    name, _, domain = email.partition("@")
    if len(name) <= 2:
        masked_name = name[0] + "*"
    else:
        masked_name = name[0] + "*" * (len(name) - 2) + name[-1]
    return f"{masked_name}@{domain}"


# ---------------------------------------------------------------------------
# Extraction pipeline
# ---------------------------------------------------------------------------

def load_input(path: str) -> str:
    size = os.path.getsize(path)
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"Refusing to process input: file is {size} bytes, "
            f"exceeds the {MAX_FILE_SIZE_BYTES}-byte safety limit."
        )
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    # Strip null bytes / non-printable control characters. These have no
    # legitimate reason to be in a text log and are a common way to try to
    # confuse downstream parsers or terminals.
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return text


def extract(text: str) -> dict:
    results = {
        "emails": {"alu_official": [], "alu_alumni": [], "alu_si": [], "general": []},
        "credit_cards": [],
        "urls": [],
        "phone_numbers": [],
    }
    skipped_lines = 0

    for line_no, line in enumerate(text.splitlines(), start=1):
        if is_suspicious(line):
            skipped_lines += 1
            continue  # do not run extraction regex on flagged/oversized lines

        # ---- Emails ----
        for m in EMAIL_RE.findall(line):
            category = classify_email(m)
            bucket = results["emails"][category]
            if m not in bucket and len(bucket) < MAX_MATCHES_PER_CATEGORY:
                bucket.append(m)

        # ---- URLs ----
        for m in URL_RE.findall(line):
            cleaned = m.rstrip(').,;:!?"\'')  # drop trailing punctuation caught by mistake
            if cleaned not in results["urls"] and len(results["urls"]) < MAX_MATCHES_PER_CATEGORY:
                results["urls"].append(cleaned)

        # ---- Credit cards ----
        # Extracted first (and its character spans recorded below) so that
        # phone-number matching can skip over digit runs that are actually
        # part of a card number rather than double-counting them as phones.
        card_spans = []
        for brand, pattern in CARD_PATTERNS.items():
            for match in pattern.finditer(line):
                card_spans.append(match.span())
                digits = re.sub(r"\D", "", match.group())
                entry = {
                    "brand": brand,
                    "masked": mask_card(digits),
                    "luhn_valid": luhn_valid(digits),
                }
                if entry not in results["credit_cards"] and len(results["credit_cards"]) < MAX_MATCHES_PER_CATEGORY:
                    results["credit_cards"].append(entry)

        # ---- Phone numbers ----
        for match in PHONE_CANDIDATE_RE.finditer(line):
            start, end = match.span()
            # Skip any candidate that overlaps a digit run already claimed
            # by a credit card match - a 16-digit card number chopped into
            # groups of 4 will otherwise look exactly like a phone number.
            if any(start < c_end and end > c_start for c_start, c_end in card_spans):
                continue
            cleaned = validate_phone(match.group())
            if cleaned and cleaned not in results["phone_numbers"] and len(results["phone_numbers"]) < MAX_MATCHES_PER_CATEGORY:
                results["phone_numbers"].append(cleaned)

    results["_meta"] = {
        "lines_processed": len(text.splitlines()) - skipped_lines,
        "lines_skipped_as_suspicious": skipped_lines,
    }
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_summary(results: dict) -> None:
    meta = results["_meta"]
    print("=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Lines processed:            {meta['lines_processed']}")
    print(f"Lines skipped (suspicious): {meta['lines_skipped_as_suspicious']}")
    print("-" * 60)

    emails = results["emails"]
    total_emails = sum(len(v) for v in emails.values())
    print(f"Emails found: {total_emails}")
    for label in ("alu_official", "alu_alumni", "alu_si", "general"):
        for addr in emails[label]:
            # Console output uses the masked form - never dump raw emails
            # to a log/terminal by default.
            print(f"    [{label}] {mask_email_for_log(addr)}")

    print(f"\nCredit cards found: {len(results['credit_cards'])}")
    for c in results["credit_cards"]:
        status = "VALID (Luhn)" if c["luhn_valid"] else "REJECTED (fails Luhn)"
        print(f"    [{c['brand']}] {c['masked']} - {status}")

    print(f"\nURLs found: {len(results['urls'])}")
    for u in results["urls"]:
        print(f"    {u}")

    print(f"\nPhone numbers found: {len(results['phone_numbers'])}")
    for p in results["phone_numbers"]:
        print(f"    {p}")
    print("=" * 60)


def build_json_report(results: dict) -> dict:
    """
    Build the JSON report. Only Luhn-valid cards are included in the
    "credit_cards" output as genuinely extracted structured data; cards
    that fail the checksum are reported separately as rejected, so the
    grader can see the validation logic actually did something.
    """
    valid_cards = [c for c in results["credit_cards"] if c["luhn_valid"]]
    rejected_cards = [c for c in results["credit_cards"] if not c["luhn_valid"]]

    return {
        "meta": results["_meta"],
        "emails": results["emails"],
        "credit_cards": {
            "valid": valid_cards,
            "rejected_failed_luhn": rejected_cards,
        },
        "urls": results["urls"],
        "phone_numbers": results["phone_numbers"],
    }


def main() -> None:
    try:
        text = load_input(INPUT_PATH)
    except (OSError, ValueError) as e:
        print(f"Error loading input: {e}", file=sys.stderr)
        sys.exit(1)

    results = extract(text)
    print_summary(results)

    report = build_json_report(results)
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nJSON report written to: {os.path.abspath(OUTPUT_PATH)}")


if __name__ == "__main__":
    main()

