#!/usr/bin/env python3
"""
data_scan.py — Scan files for exposed PII (SSNs, credit cards, emails, phones).

Searches text files, CSVs, logs, and documents for personally identifiable
information using pattern matching. Helps you find data leaks before they
become breaches.

Usage:
    python data_scan.py document.txt
    python data_scan.py ./data_folder/ --recursive
    python data_scan.py report.csv --types ssn,email
    python data_scan.py ./logs/ -r --output report.json

Detects: SSNs, credit card numbers, email addresses, phone numbers, IP addresses
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# PII Detection Patterns
# ---------------------------------------------------------------------------
# Each pattern is a tuple of (name, compiled_regex, description, validator_func)
# Validators reduce false positives by checking additional constraints.

def _validate_credit_card(match_text):
    """Validate credit card numbers using the Luhn algorithm."""
    digits = re.sub(r"[\s\-]", "", match_text)
    if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
        return False
        # Luhn check
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(int(c) for c in reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _validate_ssn(match_text):
    """Basic SSN validation — reject known invalid ranges."""
    digits = match_text.replace("-", "").replace(" ", "")
    if len(digits) != 9:
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    # SSNs can't start with 000, 666, or 900-999
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0:
        return False
    if int(digits[5:]) == 0:
        return False
    return True


def _validate_phone(match_text):
    """Basic phone validation — must have 10+ digits."""
    digits = re.sub(r"\D", "", match_text)
    return 10 <= len(digits) <= 15


def _always_valid(_match_text):
    """No additional validation needed."""
    return True


# Pattern definitions
PII_PATTERNS = [
    (
        "SSN",
        re.compile(
            r"\b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b"
        ),
        "Social Security Number",
        _validate_ssn,
    ),
    (
        "CREDIT_CARD",
        re.compile(
            r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b"
            r"|"
            r"\b(\d{4}[-\s]?\d{6}[-\s]?\d{5})\b"  # Amex format
        ),
        "Credit Card Number",
        _validate_credit_card,
    ),
    (
        "EMAIL",
        re.compile(
            r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
        ),
        "Email Address",
        _always_valid,
    ),
    (
        "PHONE",
        re.compile(
            r"(?<!\d)"  # Not preceded by digit 
            r"(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})"
            r"(?!\d)"  # Not followed by digit
        ),
        "Phone Number",
        _validate_phone,
    ),
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        ),
        "IP Address",
        lambda m: all(0 <= int(p) <= 255 for p in m.split(".")),
    ),
]

# File extensions we can scan (text-based files)
SCANNABLE_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".html", ".htm",
    ".md", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".env",
    ".py", ".js", ".java", ".c", ".cpp", ".h", ".sql",
}


def scan_text(text, pii_types=None):
    """
    Scan a string for PII patterns.

    Args:
        text: The text to scan
        pii_types: Set of type names to scan for (None = all)

    Returns:
        List of dicts: [{type, value, line_number, column, context}]
    """
    findings = []
    lines = text.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pii_name, pattern, description, validator in PII_PATTERNS:
            # Skip if this type wasn't requested
            if pii_types and pii_name.lower() not in pii_types:
                continue

            for match in pattern.finditer(line):
                # Get the actual matched text (first non-None group)
                matched = match.group(0)
                for g in match.groups():
                    if g is not None:
                        matched = g
                        break

                        # Run validator to reduce false positives
                if not validator(matched):
                    continue

                    # Get surrounding context (mask the actual value for safety)
                col = match.start() + 1
                context_start = max(0, match.start() - 20)
                context_end = min(len(line), match.end() + 20)
                context = line[context_start:context_end].strip()

                findings.append({
                    "type": pii_name,
                    "description": description,
                    "value": matched,
                    "line": line_num,
                    "column": col,
                    "context": context,
                })

    return findings


def scan_file(file_path, pii_types=None, verbose=False):
    """
    Scan a single file for PII.

    Args:
        file_path: Path to the file
        pii_types: Set of types to scan for
        verbose: Print progress

    Returns:
        List of findings (same format as scan_text)
    """
    file_path = Path(file_path)

    # Check if file is scannable (text-based)
    if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
        if verbose:
            print(f"  Skipping {file_path} (unsupported format)")
        return []

    try:
        # Try reading as text with common encodings
        text = None
        for encoding in ["utf-8", "latin-1", "cp1252"]:
            try:
                text = file_path.read_text(encoding=encoding)
                break
            except (UnicodeDecodeError, ValueError):
                continue

        if text is None:
            if verbose:
                print(f"  Skipping {file_path} (unable to decode)")
            return []

        findings = scan_text(text, pii_types)

        # Add file path to each finding
        for f in findings:
            f["file"] = str(file_path)

        return findings

    except PermissionError:
        print(f"  Permission denied: {file_path}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"  Error scanning {file_path}: {e}", file=sys.stderr)
        return []


def find_files(path, recursive=False):
    """Find all scannable files in a path."""
    path = Path(path)
    if path.is_file():
        return [path]
    if path.is_dir():
        if recursive:
            return sorted(f for f in path.rglob("*") if f.is_file())
        else:
            return sorted(f for f in path.iterdir() if f.is_file())
    return []


def format_findings_table(findings):
    """Format findings as a readable table for terminal output."""
    if not findings:
        return "  No PII detected.\n"

    output = []
    # Group by file
    by_file = {}
    for f in findings:
        by_file.setdefault(f.get("file", "stdin"), []).append(f)

    for file_path, file_findings in by_file.items():
        output.append(f"\n  File: {file_path}")
        output.append("  " + "-" * 60)

        # Group by type within file
        by_type = {}
        for f in file_findings:
            by_type.setdefault(f["type"], []).append(f)

        for pii_type, type_findings in sorted(by_type.items()):
            output.append(f"  [{pii_type}] — {len(type_findings)} instance(s)")
            for f in type_findings:
                # Partially mask the value for safety in output
                masked = _mask_value(f["value"], f["type"])
                output.append(f"    Line {f['line']}, Col {f['column']}: {masked}")

    return "\n".join(output)


def _mask_value(value, pii_type):
    """Partially mask a PII value for safe display."""
    if pii_type == "SSN":
        return "***-**-" + value[-4:]
    elif pii_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        return "****-****-****-" + digits[-4:]
    elif pii_type == "EMAIL":
        parts = value.split("@")
        if len(parts) == 2:
            name = parts[0]
            masked_name = name[0] + "***" if len(name) > 1 else "***"
            return f"{masked_name}@{parts[1]}"
        return value
    elif pii_type == "PHONE":
        digits = re.sub(r"\D", "", value)
        return "***-***-" + digits[-4:] if len(digits) >= 4 else value
    return value


def main():
    parser = argparse.ArgumentParser(
        description="Scan files for exposed PII (SSNs, credit cards, emails, phones).",
        epilog="Examples:\n"
               "  python data_scan.py document.txt\n"
               "  python data_scan.py ./data/ -r --types ssn,credit_card\n"
               "  python data_scan.py report.csv --output findings.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        help="File or directory to scan",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Scan subdirectories recursively",
    )
    parser.add_argument(
        "-t", "--types",
        help="Comma-separated PII types to scan for: ssn,credit_card,email,phone,ip_address "
             "(default: all)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save findings to a JSON file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    # Parse PII types filter
    pii_types = None
    if args.types:
        pii_types = {t.strip().lower() for t in args.types.split(",")}
        valid_types = {name.lower() for name, _, _, _ in PII_PATTERNS}
        invalid = pii_types - valid_types
        if invalid:
            print(f"Unknown PII types: {', '.join(invalid)}")
            print(f"Valid types: {', '.join(sorted(valid_types))}")
            sys.exit(1)

            # Find files to scan
    files = find_files(args.input, recursive=args.recursive)
    if not files:
        print("No files found to scan.")
        sys.exit(1)

    type_label = ", ".join(sorted(pii_types)) if pii_types else "all types"
    print(f"Scanning {len(files)} file(s) for {type_label}...\n")

    # Scan all files
    all_findings = []
    files_with_pii = 0

    for file_path in files:
        if args.verbose:
            print(f"  Scanning: {file_path}")

        findings = scan_file(file_path, pii_types, verbose=args.verbose)
        if findings:
            files_with_pii += 1
        all_findings.extend(findings)

        # Output results
    print(format_findings_table(all_findings))

    # Summary
    type_counts = {}
    for f in all_findings:
        type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1

    print(f"\n--- Summary ---")
    print(f"Files scanned: {len(files)}")
    print(f"Files with PII: {files_with_pii}")
    print(f"Total findings: {len(all_findings)}")
    if type_counts:
        for pii_type, count in sorted(type_counts.items()):
            print(f"  {pii_type}: {count}")

            # Save JSON output if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Mask values in JSON output too
        safe_findings = []
        for f in all_findings:
            safe_f = f.copy()
            safe_f["value_masked"] = _mask_value(f["value"], f["type"])
            safe_f["value"] = f["value"]  # Full value in JSON for remediation
            safe_findings.append(safe_f)

        with open(output_path, "w") as fp:
            json.dump({
                "scan_summary": {
                    "files_scanned": len(files),
                    "files_with_pii": files_with_pii,
                    "total_findings": len(all_findings),
                    "types_found": type_counts,
                },
                "findings": safe_findings,
            }, fp, indent=2)
        print(f"\nDetailed report saved to: {output_path}")


if __name__ == "__main__":
    main()