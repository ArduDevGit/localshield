#!/usr/bin/env python3
"""
hash_verify.py — SHA-256 file integrity verification.

Generate, verify, and compare cryptographic hashes of files to ensure
they haven't been tampered with or corrupted. Uses SHA-256 by default,
which is the industry standard for file integrity checking.

Common uses:
  - Verify a downloaded file matches the publisher's hash
  - Detect unauthorized changes to important files
  - Compare two files to check if they're identical
  - Generate hash manifests for a directory of files

Usage:
    python hash_verify.py generate document.pdf
    python hash_verify.py verify document.pdf abc123def456...
    python hash_verify.py compare file1.txt file2.txt
    python hash_verify.py manifest ./important_files/ -o checksums.txt

Algorithms: sha256 (default), sha512, sha1, md5
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Hashing Functions
# ---------------------------------------------------------------------------

# Block size for reading files — 64KB is a good balance between
# memory usage and read efficiency
BLOCK_SIZE = 65536


def hash_file(file_path, algorithm="sha256"):
    """
    Compute the cryptographic hash of a file.

    Reads the file in chunks to handle files of any size without
    loading the entire file into memory.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm name (sha256, sha512, sha1, md5)

    Returns:
        Hex digest string, or None on error
    """
    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        print(f"ERROR: Unsupported algorithm '{algorithm}'", file=sys.stderr)
        return None

    try:
        with open(file_path, "rb") as f:
            while True:
                block = f.read(BLOCK_SIZE)
                if not block:
                    break
                hasher.update(block)
        return hasher.hexdigest()
    except PermissionError:
        print(f"  Permission denied: {file_path}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"  File not found: {file_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Error reading {file_path}: {e}", file=sys.stderr)
        return None


def format_size(size_bytes):
    """Format bytes into human-readable size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_generate(args):
    """Generate and display the hash of one or more files."""
    algorithm = args.algorithm

    for file_path_str in args.files:
        file_path = Path(file_path_str)

        if file_path.is_dir():
            # Hash all files in directory
            files = sorted(f for f in file_path.rglob("*") if f.is_file()) \
                if args.recursive else \
                sorted(f for f in file_path.iterdir() if f.is_file())
        else:
            files = [file_path]

        for f in files:
            digest = hash_file(f, algorithm)
            if digest:
                if args.verbose:
                    size = f.stat().st_size
                    print(f"{digest}  {f}  ({format_size(size)}, {algorithm})")
                else:
                    # Standard format: hash  filename (compatible with sha256sum)
                    print(f"{digest}  {f}")


def cmd_verify(args):
    """Verify a file against a known hash."""
    file_path = Path(args.file)
    expected_hash = args.hash.strip().lower()
    algorithm = args.algorithm

    if not file_path.exists():
        print(f"File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

        # Auto-detect algorithm from hash length if not specified
    if algorithm == "sha256":
        hash_lengths = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
        detected = hash_lengths.get(len(expected_hash))
        if detected and detected != algorithm:
            print(f"  Note: Hash length suggests {detected.upper()}, "
                  f"using {detected} instead of {algorithm}")
            algorithm = detected

    print(f"Verifying: {file_path}")
    print(f"Algorithm: {algorithm.upper()}")
    print(f"Expected:  {expected_hash}")

    actual_hash = hash_file(file_path, algorithm)
    if actual_hash is None:
        sys.exit(1)

    print(f"Actual:    {actual_hash}")

    if actual_hash == expected_hash:
        print(f"\n  MATCH — File integrity verified.")
        sys.exit(0)
    else:
        print(f"\n  MISMATCH — File may have been tampered with or corrupted!")
        # Show where the hashes differ for debugging
        for i, (a, b) in enumerate(zip(actual_hash, expected_hash)):
            if a != b:
                print(f"  First difference at position {i}")
                break
        sys.exit(1)


def cmd_compare(args):
    """Compare two files by their hashes."""
    file1 = Path(args.file1)
    file2 = Path(args.file2)
    algorithm = args.algorithm

    if not file1.exists():
        print(f"File not found: {file1}", file=sys.stderr)
        sys.exit(1)
    if not file2.exists():
        print(f"File not found: {file2}", file=sys.stderr)
        sys.exit(1)

        # Quick check: if sizes differ, files are definitely different
    size1 = file1.stat().st_size
    size2 = file2.stat().st_size

    print(f"Comparing files using {algorithm.upper()}:\n")
    print(f"  File 1: {file1} ({format_size(size1)})")
    print(f"  File 2: {file2} ({format_size(size2)})")

    if size1 != size2:
        print(f"\n  DIFFERENT — Files have different sizes "
              f"({format_size(size1)} vs {format_size(size2)})")
        sys.exit(1)

    hash1 = hash_file(file1, algorithm)
    hash2 = hash_file(file2, algorithm)

    if hash1 is None or hash2 is None:
        sys.exit(1)

    if args.verbose:
        print(f"\n  Hash 1: {hash1}")
        print(f"  Hash 2: {hash2}")

    if hash1 == hash2:
        print(f"\n  IDENTICAL — Files have the same content.")
        sys.exit(0)
    else:
        print(f"\n  DIFFERENT — Files have different content.")
        if not args.verbose:
            print(f"  Hash 1: {hash1}")
            print(f"  Hash 2: {hash2}")
        sys.exit(1)


def cmd_manifest(args):
    """Generate a hash manifest for all files in a directory."""
    dir_path = Path(args.directory)
    algorithm = args.algorithm

    if not dir_path.is_dir():
        print(f"Not a directory: {dir_path}", file=sys.stderr)
        sys.exit(1)

        # Find all files
    if args.recursive:
        files = sorted(f for f in dir_path.rglob("*") if f.is_file())
    else:
        files = sorted(f for f in dir_path.iterdir() if f.is_file())

    if not files:
        print("No files found.")
        sys.exit(0)

    print(f"Generating {algorithm.upper()} manifest for {len(files)} file(s)...\n")

    lines = []
    total_size = 0

    for f in files:
        digest = hash_file(f, algorithm)
        if digest:
            # Use relative path from the directory for portability
            try:
                rel_path = f.relative_to(dir_path)
            except ValueError:
                rel_path = f
            line = f"{digest}  {rel_path}"
            lines.append(line)
            total_size += f.stat().st_size

            if args.verbose:
                print(f"  {digest}  {rel_path}")

                # Output
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Add header comment
        header = f"# {algorithm.upper()} manifest generated by hash_verify.py\n"
        header += f"# Directory: {dir_path.resolve()}\n"
        header += f"# Files: {len(lines)}\n\n"

        with open(output_path, "w") as fp:
            fp.write(header)
            fp.write("\n".join(lines) + "\n")

        print(f"\nManifest saved to: {output_path}")
    else:
        # Print to stdout
        for line in lines:
            print(line)

    print(f"\n--- Summary ---")
    print(f"Files hashed: {len(lines)}")
    print(f"Total size: {format_size(total_size)}")
    print(f"Algorithm: {algorithm.upper()}")


def main():
    parser = argparse.ArgumentParser(
        description="SHA-256 file integrity verification tool.",
        epilog="Examples:\n"
               "  python hash_verify.py generate report.pdf\n"
               "  python hash_verify.py verify app.zip abc123...\n"
               "  python hash_verify.py compare old.txt new.txt\n"
               "  python hash_verify.py manifest ./docs/ -o checksums.txt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Common arguments
    parser.add_argument(
        "-a", "--algorithm",
        choices=["sha256", "sha512", "sha1", "md5"],
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- generate ---
    gen_parser = subparsers.add_parser(
        "generate", aliases=["gen", "hash"],
        help="Generate hash(es) for file(s)",
    )
    gen_parser.add_argument("files", nargs="+", help="File(s) or directory to hash")
    gen_parser.add_argument("-r", "--recursive", action="store_true",
                            help="Recurse into directories")

    # --- verify ---
    ver_parser = subparsers.add_parser(
        "verify", aliases=["check"],
        help="Verify a file against a known hash",
    )
    ver_parser.add_argument("file", help="File to verify")
    ver_parser.add_argument("hash", help="Expected hash value")

    # --- compare ---
    cmp_parser = subparsers.add_parser(
        "compare", aliases=["cmp", "diff"],
        help="Compare two files by hash",
    )
    cmp_parser.add_argument("file1", help="First file")
    cmp_parser.add_argument("file2", help="Second file")

    # --- manifest ---
    man_parser = subparsers.add_parser(
        "manifest", aliases=["dir"],
        help="Generate hash manifest for a directory",
    )
    man_parser.add_argument("directory", help="Directory to hash")
    man_parser.add_argument("-o", "--output", help="Save manifest to file")
    man_parser.add_argument("-r", "--recursive", action="store_true",
                            help="Include subdirectories")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

        # Route to command handler
    command_map = {
        "generate": cmd_generate, "gen": cmd_generate, "hash": cmd_generate,
        "verify": cmd_verify, "check": cmd_verify,
        "compare": cmd_compare, "cmp": cmd_compare, "diff": cmd_compare,
        "manifest": cmd_manifest, "dir": cmd_manifest,
    }

    handler = command_map.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()