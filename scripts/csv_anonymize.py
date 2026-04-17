#!/usr/bin/env python3
"""
csv_anonymize.py — Replace real PII in CSV files with realistic fake data.

Detects and replaces names, emails, phones, SSNs, addresses, and more with
convincing fake data generated locally. The output keeps the same structure
and statistical properties but contains zero real personal information.

Usage:
    python csv_anonymize.py customers.csv
    python csv_anonymize.py customers.csv -o anonymized.csv
    python csv_anonymize.py data.csv --columns name,email,phone
    python csv_anonymize.py data.csv --preview   # show what would change

Supported PII types: name, email, phone, ssn, address, city, state, zip,
                     company, date_of_birth, ip_address, credit_card
"""

import argparse
import csv
import hashlib
import re
import sys
from io import StringIO
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    pd = None

try:
    from faker import Faker

    fake = Faker()
except ImportError:
    Faker = None
    fake = None


def _check_dependencies():
    """Verify required libraries are installed before running.

    Raises ImportError when called as a library.
    When invoked from CLI (main()), the caller catches and exits.
    """
    if pd is None:
        raise ImportError("pandas is required. Install it with: pip install pandas")
    if Faker is None:
        raise ImportError("Faker is required. Install it with: pip install Faker")

    # ---------------------------------------------------------------------------


# Column Type Detection
# ---------------------------------------------------------------------------
# Maps common column name patterns to PII types. This is how we auto-detect
# which columns contain what kind of data without the user having to specify.

COLUMN_PATTERNS = {
    "name": [
        r"(?:full[_\s]?)?name", r"first[_\s]?name", r"last[_\s]?name",
        r"customer[_\s]?name", r"contact[_\s]?name", r"employee[_\s]?name",
        r"person", r"client",
    ],
    "email": [
        r"e[\-_\s]?mail", r"email[_\s]?address",
    ],
    "phone": [
        r"phone", r"tel(?:ephone)?", r"mobile", r"cell",
        r"fax", r"contact[_\s]?number",
    ],
    "ssn": [
        r"ssn", r"social[_\s]?security", r"ss[_\s]?(?:number|num|#)",
        r"tax[_\s]?id", r"tin",
    ],
    "address": [
        r"(?:street[_\s]?)?address", r"street", r"addr(?:ess)?[_\s]?(?:line)?",
        r"mailing[_\s]?address", r"home[_\s]?address",
    ],
    "city": [
        r"city", r"town", r"municipality",
    ],
    "state": [
        r"state", r"province", r"region",
    ],
    "zip": [
        r"zip(?:[_\s]?code)?", r"postal(?:[_\s]?code)?", r"postcode",
    ],
    "company": [
        r"company", r"org(?:anization)?", r"employer", r"business",
        r"firm", r"corp(?:oration)?",
    ],
    "date_of_birth": [
        r"(?:date[_\s]?of[_\s]?)?birth", r"dob", r"birthday",
    ],
    "ip_address": [
        r"ip(?:[_\s]?address)?", r"ip[_\s]?addr",
    ],
    "credit_card": [
        r"credit[_\s]?card", r"card[_\s]?(?:number|num|#)",
        r"cc[_\s]?(?:number|num|#)?", r"payment[_\s]?card",
    ],
}


def detect_column_type(column_name):
    """
    Detect PII type from a column name using pattern matching.

    Returns the PII type string or None if no match.
    """
    col_lower = column_name.lower().strip()
    for pii_type, patterns in COLUMN_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, col_lower):
                return pii_type
    return None


def detect_column_type_by_content(series):
    """
    Detect PII type by examining actual column values.
    Used as a fallback when column names don't match.
    """
    # Sample up to 20 non-null values
    sample = series.dropna().head(20).astype(str)
    if len(sample) == 0:
        return None

        # Check patterns in the data itself
    email_count = sum(1 for v in sample if re.match(r"^[^@]+@[^@]+\.[^@]+$", v))
    if email_count > len(sample) * 0.5:
        return "email"

    ssn_count = sum(1 for v in sample if re.match(r"^\d{3}-\d{2}-\d{4}$", v))
    if ssn_count > len(sample) * 0.5:
        return "ssn"

    phone_count = sum(1 for v in sample if re.match(
        r"^[\+]?1?[\s\-\.]?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}$", v))
    if phone_count > len(sample) * 0.5:
        return "phone"

    ip_count = sum(1 for v in sample if re.match(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v))
    if ip_count > len(sample) * 0.5:
        return "ip_address"

    return None


# ---------------------------------------------------------------------------
# Fake Data Generators
# ---------------------------------------------------------------------------
# Each generator produces a replacement value for one PII type.
# Uses a hash-based seed so the same input always maps to the same fake output
# (consistency within a dataset — "John Smith" always becomes "Jane Doe").

_consistency_cache = {}


def _consistent_fake(original_value, pii_type, generator_func):
    """
    Generate a consistent fake value — same input always produces same output.
    This preserves referential integrity (e.g., if the same name appears in
    multiple rows, it maps to the same fake name every time).
    """
    cache_key = (str(original_value).lower().strip(), pii_type)
    if cache_key not in _consistency_cache:
        # Use hash of original value as seed for reproducibility
        seed = int(hashlib.md5(str(original_value).encode()).hexdigest(), 16) % (2 ** 32)
        Faker.seed(seed)
        _consistency_cache[cache_key] = generator_func()
        Faker.seed(None)  # Reset to random
    return _consistency_cache[cache_key]


def _get_generators():
    """Build generators dict — called at runtime so fake is initialized."""
    return {
        "name": lambda: fake.name(),
        "email": lambda: fake.email(),
        "phone": lambda: fake.phone_number(),
        "ssn": lambda: fake.ssn(),
        "address": lambda: fake.street_address(),
        "city": lambda: fake.city(),
        "state": lambda: fake.state_abbr(),
        "zip": lambda: fake.zipcode(),
        "company": lambda: fake.company(),
        "date_of_birth": lambda: fake.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
        "ip_address": lambda: fake.ipv4_private(),
        "credit_card": lambda: fake.credit_card_number(),
    }


# Available PII type names (safe to reference even without Faker)
GENERATOR_TYPES = [
    "name", "email", "phone", "ssn", "address", "city",
    "state", "zip", "company", "date_of_birth", "ip_address", "credit_card",
]

# Lazy-initialized at runtime
GENERATORS = None


def _ensure_generators():
    """Lazily initialize GENERATORS on first use (requires Faker)."""
    global GENERATORS
    if GENERATORS is None:
        _check_dependencies()
        GENERATORS = _get_generators()


def anonymize_value(value, pii_type):
    """Replace a single value with a consistent fake."""
    _ensure_generators()
    if pd.isna(value) or str(value).strip() == "":
        return value

    generator = GENERATORS.get(pii_type)
    if generator is None:
        return value

    return _consistent_fake(value, pii_type, generator)


def anonymize_csv(input_path, output_path=None, columns=None, preview=False, verbose=False):
    """
    Anonymize PII columns in a CSV file.

    Args:
        input_path: Path to the input CSV
        output_path: Where to save (default: <input>_anonymized.csv)
        columns: Dict of {column_name: pii_type} to anonymize
                 (None = auto-detect)
        preview: If True, show what would change without modifying
        verbose: Print detailed progress

    Returns:
        Tuple of (success: bool, stats: dict)
    """
    input_path = Path(input_path)

    try:
        # Read CSV — try common encodings
        df = None
        for encoding in ["utf-8", "latin-1", "cp1252"]:
            try:
                df = pd.read_csv(input_path, encoding=encoding, dtype=str)
                break
            except (UnicodeDecodeError, ValueError):
                continue

        if df is None:
            print(f"  ERROR: Unable to read {input_path}", file=sys.stderr)
            return False, {}

        if verbose:
            print(f"  Read {len(df)} rows, {len(df.columns)} columns")

            # Detect or validate column types
        if columns is None:
            # Auto-detect PII columns
            columns = {}
            for col in df.columns:
                pii_type = detect_column_type(col)
                if pii_type is None:
                    pii_type = detect_column_type_by_content(df[col])
                if pii_type:
                    columns[col] = pii_type

        if not columns:
            print(f"  No PII columns detected in {input_path}")
            print("  Hint: Use --columns to specify columns manually")
            return True, {"columns_anonymized": 0, "rows": len(df)}

            # Preview mode
        if preview:
            print(f"\n  Preview — columns to anonymize in {input_path}:")
            print("  " + "-" * 55)
            for col, pii_type in sorted(columns.items()):
                sample_orig = df[col].dropna().head(3).tolist()
                sample_fake = [anonymize_value(v, pii_type) for v in sample_orig]
                print(f"  {col} ({pii_type}):")
                for orig, fake_val in zip(sample_orig, sample_fake):
                    print(f"    {orig}  →  {fake_val}")
            return True, {"columns_detected": len(columns)}

            # Anonymize
        stats = {"columns_anonymized": 0, "values_replaced": 0, "rows": len(df)}

        for col, pii_type in columns.items():
            if col not in df.columns:
                print(f"  Warning: Column '{col}' not found, skipping")
                continue

            if verbose:
                print(f"  Anonymizing column '{col}' as {pii_type}")

            original_count = df[col].notna().sum()
            df[col] = df[col].apply(lambda v: anonymize_value(v, pii_type))
            stats["columns_anonymized"] += 1
            stats["values_replaced"] += original_count

            # Save
        if output_path is None:
            stem = input_path.stem
            output_path = input_path.parent / f"{stem}_anonymized.csv"
        else:
            output_path = Path(output_path)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)

        if verbose:
            print(f"  Saved to {output_path}")

        return True, stats

    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        return False, {}


def parse_columns_arg(columns_str, df_columns):
    """
    Parse the --columns argument.

    Accepts formats:
        --columns name,email,phone           (auto-detect type from column name)
        --columns "Full Name:name,Email:email"  (explicit mapping)
    """
    columns = {}
    for item in columns_str.split(","):
        item = item.strip()
        if ":" in item:
            col_name, pii_type = item.split(":", 1)
            col_name = col_name.strip()
            pii_type = pii_type.strip().lower()
        else:
            # Try to find a matching column
            col_name = item
            pii_type = detect_column_type(col_name)

            # If no auto-detect, try case-insensitive match against actual columns
            if pii_type is None:
                for actual_col in df_columns:
                    if actual_col.lower() == col_name.lower():
                        col_name = actual_col
                        pii_type = detect_column_type(col_name)
                        break

            if pii_type is None:
                print(f"  Warning: Can't determine type for '{col_name}'. "
                      f"Use format 'column:type' (e.g., '{col_name}:name')")
                continue

        if pii_type not in GENERATOR_TYPES:
            print(f"  Warning: Unknown type '{pii_type}'. "
                  f"Valid types: {', '.join(sorted(GENERATOR_TYPES))}")
            continue

        columns[col_name] = pii_type

    return columns


def main():
    parser = argparse.ArgumentParser(
        description="Replace real PII in CSV files with realistic fake data.",
        epilog="Examples:\n"
               "  python csv_anonymize.py customers.csv\n"
               "  python csv_anonymize.py data.csv --columns name,email,phone\n"
               "  python csv_anonymize.py data.csv --columns 'Full Name:name,Contact:email'\n"
               "  python csv_anonymize.py data.csv --preview\n\n"
               "Valid PII types: " + ", ".join(sorted(GENERATOR_TYPES)),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        help="CSV file to anonymize",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <input>_anonymized.csv)",
    )
    parser.add_argument(
        "-c", "--columns",
        help="Columns to anonymize (comma-separated). "
             "Format: col1,col2 or 'col1:type,col2:type'",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Show what would change without modifying the file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()
    input_path = Path(args.input)

    if not input_path.exists():
        print(f"File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        _check_dependencies()
    except ImportError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

        # If columns specified, parse them (need to read CSV first for column names)
    columns = None
    if args.columns:
        # Quick read to get column names
        df_temp = pd.read_csv(input_path, nrows=0, dtype=str)
        columns = parse_columns_arg(args.columns, df_temp.columns.tolist())
        if not columns:
            print("No valid columns to anonymize.")
            sys.exit(1)

    print(f"Processing: {input_path}\n")

    # Clear consistency cache for fresh run
    _consistency_cache.clear()

    success, stats = anonymize_csv(
        input_path,
        output_path=args.output,
        columns=columns,
        preview=args.preview,
        verbose=args.verbose,
    )

    if success and not args.preview:
        print(f"\n--- Summary ---")
        print(f"Rows processed: {stats.get('rows', 0)}")
        print(f"Columns anonymized: {stats.get('columns_anonymized', 0)}")
        print(f"Values replaced: {stats.get('values_replaced', 0)}")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()