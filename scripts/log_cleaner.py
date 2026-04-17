#!/usr/bin/env python3
"""
log_cleaner.py — Sanitize sensitive data from log files.

Replaces IP addresses, email addresses, API tokens/keys, auth headers,
and other sensitive patterns in log files with safe placeholder values.
Preserves log structure and formatting so sanitized logs remain useful
for debugging and analysis.

Usage:
    python log_cleaner.py server.log
    python log_cleaner.py app.log -o sanitized.log
    python log_cleaner.py ./logs/ --recursive
    python log_cleaner.py debug.log --preview
    python log_cleaner.py access.log --types ip,email

Detects: IPv4/IPv6, emails, API keys, bearer tokens, basic auth,
         AWS keys, JWTs, private keys, connection strings, cookies
"""

import argparse
import hashlib
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Sanitization Patterns
# ---------------------------------------------------------------------------
# Each pattern: (name, compiled_regex, replacement_template)
#
# Replacements use a consistent hashing approach: the same original value
# always produces the same placeholder, so you can still correlate entries
# in sanitized logs (e.g., all requests from the same IP get the same
# placeholder, just not the real IP).

def _consistent_placeholder(original, prefix="REDACTED"):
    """
    Generate a consistent short placeholder for a value.
    Same input always produces the same output, so log correlation
    still works after sanitization.
    """
    short_hash = hashlib.md5(original.encode()).hexdigest()[:8]
    return f"[{prefix}_{short_hash}]"


# Pattern definitions — order matters (more specific patterns first)
SANITIZATION_PATTERNS = [
    # --- Tokens and Keys (most specific first) ---
    (
        "JWT",
        re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        "jwt",
    ),
    (
        "AWS_KEY",
        re.compile(
            r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"
        ),
        "aws_key",
    ),
    (
        "BEARER_TOKEN",
        re.compile(
            r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}"
        ),
        "bearer",
    ),
    (
        "BASIC_AUTH",
        re.compile(
            r"[Bb]asic\s+[A-Za-z0-9+/=]{8,}"
        ),
        "basic_auth",
    ),
    (
        "API_KEY",
        re.compile(
            r"(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)"
            r"[\s]*[=:]\s*['\"]?([A-Za-z0-9\-._~+/]{16,})['\"]?",
            re.IGNORECASE,
        ),
        "api_key",
    ),
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |EC |DSA )?PRIVATE KEY-----"
        ),
        "private_key",
    ),
    (
        "CONNECTION_STRING",
        re.compile(
            r"(?:mongodb|postgres|mysql|redis|amqp|mssql)(?:\+\w+)?://"
            r"[^\s'\"]{10,}",
            re.IGNORECASE,
        ),
        "connection_string",
    ),
    # --- Network Identifiers ---
    (
        "IPV4",
        re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        ),
        "ip",
    ),
    (
        "IPV6",
        re.compile(
            r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})\b"
            r"|"
            r"\b((?:[0-9a-fA-F]{1,4}:){1,7}:)\b"
            r"|"
            r"\b(::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})\b"
        ),
        "ipv6",
    ),
    # --- Personal Information ---
    (
        "EMAIL",
        re.compile(
            r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        ),
        "email",
    ),
    # --- Session and Cookie Data ---
    (
        "SESSION_ID",
        re.compile(
            r"(?:session[_-]?id|sess[_-]?id|JSESSIONID|PHPSESSID|sid)"
            r"[\s]*[=:]\s*['\"]?([A-Za-z0-9\-._]{16,})['\"]?",
            re.IGNORECASE,
        ),
        "session",
    ),
    (
        "SET_COOKIE",
        re.compile(
            r"[Ss]et-[Cc]ookie:\s*(.+?)(?:\r?\n|$)"
        ),
        "cookie",
    ),
    # --- Hex Tokens (generic catch-all for long hex strings) ---
    (
        "HEX_TOKEN",
        re.compile(
            r"\b[0-9a-fA-F]{32,}\b"
        ),
        "token",
    ),
]

# Which types are enabled by default
DEFAULT_TYPES = {
    "jwt", "aws_key", "bearer_token", "basic_auth", "api_key",
    "private_key", "connection_string", "ipv4", "email",
    "session_id", "set_cookie",
}

# These are optional (noisy) and only enabled if explicitly requested
OPTIONAL_TYPES = {"ipv6", "hex_token"}


def sanitize_line(line, enabled_types=None):
    """
    Sanitize a single line of text.

    Args:
        line: The text line to sanitize
        enabled_types: Set of pattern names to apply (None = defaults)

    Returns:
        Tuple of (sanitized_line, list_of_replacements_made)
    """
    if enabled_types is None:
        enabled_types = DEFAULT_TYPES

    replacements = []
    result = line

    for name, pattern, prefix in SANITIZATION_PATTERNS:
        if name.lower() not in enabled_types:
            continue

        def replace_match(match):
            original = match.group(0)
            placeholder = _consistent_placeholder(original, prefix.upper())
            replacements.append({
                "type": name,
                "original_length": len(original),
                "placeholder": placeholder,
            })
            return placeholder

        result = pattern.sub(replace_match, result)

    return result, replacements


def sanitize_file(input_path, output_path=None, enabled_types=None,
                  preview=False, verbose=False):
    """
    Sanitize a log file.

    Args:
        input_path: Path to input file
        output_path: Where to save (None = <input>_sanitized.<ext>)
        enabled_types: Set of pattern names to apply
        preview: Show changes without writing
        verbose: Print detailed progress

    Returns:
        Tuple of (success: bool, stats: dict)
    """
    input_path = Path(input_path)

    try:
        # Read with encoding fallback
        text = None
        for encoding in ["utf-8", "latin-1", "cp1252"]:
            try:
                text = input_path.read_text(encoding=encoding)
                break
            except (UnicodeDecodeError, ValueError):
                continue

        if text is None:
            print(f"  ERROR: Unable to read {input_path}", file=sys.stderr)
            return False, {}

        lines = text.split("\n")
        sanitized_lines = []
        total_replacements = 0
        type_counts = {}
        lines_modified = 0

        for line_num, line in enumerate(lines, 1):
            clean_line, replacements = sanitize_line(line, enabled_types)
            sanitized_lines.append(clean_line)

            if replacements:
                lines_modified += 1
                total_replacements += len(replacements)

                for r in replacements:
                    type_counts[r["type"]] = type_counts.get(r["type"], 0) + 1

                if preview or verbose:
                    for r in replacements:
                        print(f"  Line {line_num}: [{r['type']}] → {r['placeholder']}")

        stats = {
            "total_lines": len(lines),
            "lines_modified": lines_modified,
            "total_replacements": total_replacements,
            "type_counts": type_counts,
        }

        # Write output
        if not preview and total_replacements > 0:
            if output_path is None:
                stem = input_path.stem
                suffix = input_path.suffix or ".log"
                output_path = input_path.parent / f"{stem}_sanitized{suffix}"
            else:
                output_path = Path(output_path)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("\n".join(sanitized_lines), encoding="utf-8")

            if verbose:
                print(f"  Saved to {output_path}")

        return True, stats

    except PermissionError:
        print(f"  Permission denied: {input_path}", file=sys.stderr)
        return False, {}
    except Exception as e:
        print(f"  Error processing {input_path}: {e}", file=sys.stderr)
        return False, {}


def find_log_files(path, recursive=False):
    """Find log and text files at the given path."""
    path = Path(path)
    if path.is_file():
        return [path]
    if path.is_dir():
        # Common log file extensions
        log_extensions = {
            ".log", ".txt", ".out", ".err", ".json", ".csv",
            ".xml", ".yaml", ".yml", ".conf", ".cfg", ".ini",
        }
        if recursive:
            files = sorted(path.rglob("*"))
        else:
            files = sorted(path.iterdir())
        return [f for f in files if f.is_file() and
                (f.suffix.lower() in log_extensions or f.suffix == "")]
    return []


def main():
    parser = argparse.ArgumentParser(
        description="Sanitize sensitive data from log files.",
        epilog="Examples:\n"
               "  python log_cleaner.py server.log\n"
               "  python log_cleaner.py app.log -o clean.log\n"
               "  python log_cleaner.py ./logs/ --recursive\n"
               "  python log_cleaner.py debug.log --preview\n"
               "  python log_cleaner.py access.log --types ip,email,bearer_token\n\n"
               "Default types: ip, email, jwt, aws_key, bearer_token, basic_auth,\n"
               "               api_key, private_key, connection_string, session_id, cookie\n"
               "Optional types: ipv6, hex_token (can be noisy)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        help="Log file or directory to sanitize",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <input>_sanitized.<ext>)",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Recursively process directories",
    )
    parser.add_argument(
        "-t", "--types",
        help="Comma-separated pattern types to apply "
             "(default: all standard types). Use 'all' to enable everything.",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Show what would be sanitized without modifying",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    # Parse enabled types
    if args.types:
        if args.types.lower() == "all":
            enabled_types = {name.lower() for name, _, _ in SANITIZATION_PATTERNS}
        else:
            enabled_types = {t.strip().lower() for t in args.types.split(",")}
            valid_types = {name.lower() for name, _, _ in SANITIZATION_PATTERNS}
            invalid = enabled_types - valid_types
            if invalid:
                print(f"Unknown types: {', '.join(invalid)}")
                print(f"Valid types: {', '.join(sorted(valid_types))}")
                sys.exit(1)
    else:
        enabled_types = {t.lower() for t in DEFAULT_TYPES}

        # Find files
    files = find_log_files(args.input, recursive=args.recursive)
    if not files:
        print("No log files found to process.")
        sys.exit(0)

    if args.preview:
        print(f"Preview mode — scanning {len(files)} file(s):\n")
    else:
        print(f"Sanitizing {len(files)} file(s)...\n")

        # Process files
    total_stats = {
        "files_processed": 0,
        "files_modified": 0,
        "total_replacements": 0,
        "type_counts": {},
    }

    for file_path in files:
        if args.verbose:
            print(f"\n  Processing: {file_path}")

            # Only use custom output for single file
        output_path = args.output if len(files) == 1 else None

        success, stats = sanitize_file(
            file_path,
            output_path=output_path,
            enabled_types=enabled_types,
            preview=args.preview,
            verbose=args.verbose,
        )

        if success:
            total_stats["files_processed"] += 1
            if stats.get("total_replacements", 0) > 0:
                total_stats["files_modified"] += 1
            total_stats["total_replacements"] += stats.get("total_replacements", 0)
            for ptype, count in stats.get("type_counts", {}).items():
                total_stats["type_counts"][ptype] = \
                    total_stats["type_counts"].get(ptype, 0) + count

                # Summary
    print(f"\n--- Summary ---")
    print(f"Files processed: {total_stats['files_processed']}")
    print(f"Files with sensitive data: {total_stats['files_modified']}")
    print(f"Total replacements: {total_stats['total_replacements']}")
    if total_stats["type_counts"]:
        print(f"By type:")
        for ptype, count in sorted(total_stats["type_counts"].items()):
            print(f"  {ptype}: {count}")


if __name__ == "__main__":
    main()