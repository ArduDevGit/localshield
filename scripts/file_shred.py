#!/usr/bin/env python3
"""
file_shred.py — Securely delete files by overwriting before removal.

Overwrites file contents with random data multiple times before deleting,
making recovery with forensic tools significantly harder. Unlike a normal
delete (which just removes the directory entry), shredding overwrites the
actual data on disk.

IMPORTANT CAVEAT: On SSDs, flash storage, and files on journaling/CoW
filesystems (ZFS, Btrfs), the OS or drive firmware may write to new
physical locations rather than overwriting in place. For SSDs, use the
manufacturer's "Secure Erase" command or full-disk encryption instead.
This tool is most effective on traditional HDDs.

Usage:
    python file_shred.py secret_file.txt
    python file_shred.py confidential.pdf --passes 7
    python file_shred.py ./temp_data/ --recursive
    python file_shred.py old_records.csv --passes 3 --verbose
    python file_shred.py sensitive.doc --dry-run

Default: 3 overwrite passes (random data), then delete.
"""

import argparse
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Shredding Implementation
# ---------------------------------------------------------------------------

def shred_file(file_path, passes=3, verbose=False):
    """
    Securely overwrite and delete a single file.

    Process:
        1. Get the file size
        2. For each pass: overwrite entire file with random bytes, flush to disk
        3. Overwrite with zeros (final pass — makes it clear the file was wiped)
        4. Truncate to zero length
        5. Delete the file

    Args:
        file_path: Path to the file to shred
        passes: Number of random-data overwrite passes (minimum 1)
        verbose: Print progress for each pass

    Returns:
        True if successful, False otherwise
    """
    file_path = Path(file_path)

    if not file_path.is_file():
        print(f"  Not a file: {file_path}", file=sys.stderr)
        return False

    try:
        file_size = file_path.stat().st_size

        if file_size == 0:
            # Empty file — just delete it
            file_path.unlink()
            if verbose:
                print(f"  Deleted empty file: {file_path}")
            return True

        if verbose:
            print(f"  Shredding: {file_path} ({file_size:,} bytes, {passes} passes)")

            # Use a reasonable block size for writing (1 MB)
        block_size = min(1024 * 1024, file_size)

        # Random data passes
        for pass_num in range(1, passes + 1):
            if verbose:
                print(f"    Pass {pass_num}/{passes}: random data overwrite")

            with open(file_path, "r+b") as f:
                written = 0
                while written < file_size:
                    chunk_size = min(block_size, file_size - written)
                    # os.urandom() uses the OS CSPRNG — cryptographically random
                    f.write(os.urandom(chunk_size))
                    written += chunk_size

                    # Force write to physical storage
                f.flush()
                os.fsync(f.fileno())

                # Final pass: overwrite with zeros
        if verbose:
            print(f"    Final pass: zero overwrite")

        with open(file_path, "r+b") as f:
            written = 0
            zero_block = b"\x00" * block_size
            while written < file_size:
                chunk_size = min(block_size, file_size - written)
                f.write(zero_block[:chunk_size])
                written += chunk_size
            f.flush()
            os.fsync(f.fileno())

            # Truncate the file to zero bytes
        with open(file_path, "w") as f:
            pass

            # Delete the file
        file_path.unlink()

        if verbose:
            print(f"    Deleted: {file_path}")

        return True

    except PermissionError:
        print(f"  Permission denied: {file_path}", file=sys.stderr)
        return False
    except OSError as e:
        print(f"  OS error shredding {file_path}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  Error shredding {file_path}: {e}", file=sys.stderr)
        return False


def find_files(path, recursive=False):
    """Find all files at the given path."""
    path = Path(path)
    if path.is_file():
        return [path]
    if path.is_dir():
        if recursive:
            # Walk bottom-up so we can remove empty dirs after shredding
            return sorted(f for f in path.rglob("*") if f.is_file())
        else:
            return sorted(f for f in path.iterdir() if f.is_file())
    return []


def format_size(size_bytes):
    """Format bytes into human-readable size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def main():
    parser = argparse.ArgumentParser(
        description="Securely delete files by overwriting before removal.",
        epilog="Examples:\n"
               "  python file_shred.py secret.txt\n"
               "  python file_shred.py data.csv --passes 7\n"
               "  python file_shred.py ./temp/ --recursive\n"
               "  python file_shred.py report.pdf --dry-run\n\n"
               "NOTE: On SSDs and flash storage, overwriting may not\n"
               "reach the same physical sectors due to wear leveling.\n"
               "For SSDs, prefer full-disk encryption or the drive's\n"
               "built-in Secure Erase command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        nargs="+",
        help="File(s) or directory to shred",
    )
    parser.add_argument(
        "-n", "--passes",
        type=int,
        default=3,
        help="Number of overwrite passes (default: 3)",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Recursively shred files in directories",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be shredded without actually doing it",
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Skip confirmation prompt",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    if args.passes < 1:
        print("ERROR: Must use at least 1 overwrite pass.", file=sys.stderr)
        sys.exit(1)

        # Collect all files to shred
    all_files = []
    for input_path in args.input:
        files = find_files(input_path, recursive=args.recursive)
        all_files.extend(files)

    if not all_files:
        print("No files found to shred.")
        sys.exit(0)

        # Calculate total size
    total_size = sum(f.stat().st_size for f in all_files if f.exists())

    # Dry run mode
    if args.dry_run:
        print(f"Dry run — would shred {len(all_files)} file(s) "
              f"({format_size(total_size)}):\n")
        for f in all_files:
            size = f.stat().st_size if f.exists() else 0
            print(f"  {f} ({format_size(size)})")
        print(f"\n  Overwrite passes: {args.passes}")
        sys.exit(0)

        # Confirmation prompt (unless --force)
    if not args.force:
        print(f"WARNING: About to permanently shred {len(all_files)} file(s) "
              f"({format_size(total_size)}).")
        print(f"  Overwrite passes: {args.passes}")
        print(f"  This action is IRREVERSIBLE.\n")

        try:
            confirm = input("Type 'yes' to confirm: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)

        if confirm != "yes":
            print("Aborted.")
            sys.exit(0)

    print(f"\nShredding {len(all_files)} file(s) with {args.passes} pass(es)...\n")

    # Shred files
    success_count = 0
    fail_count = 0
    bytes_shredded = 0

    for file_path in all_files:
        size = file_path.stat().st_size if file_path.exists() else 0
        result = shred_file(file_path, passes=args.passes, verbose=args.verbose)
        if result:
            success_count += 1
            bytes_shredded += size
        else:
            fail_count += 1

            # Summary
    print(f"\n--- Summary ---")
    print(f"Files shredded: {success_count}")
    if fail_count:
        print(f"Files failed: {fail_count}")
    print(f"Data destroyed: {format_size(bytes_shredded)}")
    print(f"Overwrite passes: {args.passes}")

    sys.exit(0 if fail_count == 0 else 1)


if __name__ == "__main__":
    main()