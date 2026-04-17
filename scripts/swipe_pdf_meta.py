#!/usr/bin/env python3
"""
pdf_meta_wipe.py — LocalShield PDF Metadata Wiper

Strips ALL embedded metadata from PDF files — author, creator, producer,
title, subject, keywords, timestamps, and any custom XMP metadata.
Outputs a clean PDF with zero identifying information.

Part of the LocalShield Privacy Toolkit.
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import fitz  # PyMuPDF
except ImportError:
    print("Error: PyMuPDF is required — pip install PyMuPDF")
    sys.exit(1)


# ──────────────────────────────────────────────
# Color helpers (disabled when piped / Windows)
# ──────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty() and os.name != "nt"

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def red(t):    return _c("31", t)
def yellow(t): return _c("33", t)
def green(t):  return _c("32", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1", t)
def dim(t):    return _c("2", t)


# ──────────────────────────────────────────────
# Metadata fields PyMuPDF exposes
# ──────────────────────────────────────────────
META_FIELDS = [
    "author", "creator", "producer", "title",
    "subject", "keywords", "creationDate", "modDate",
    "format", "encryption", "trapped",
]


def show_metadata(doc, label="Current"):
    """Display all metadata fields from a PDF document."""
    meta = doc.metadata or {}
    found = False
    print(f"\n  {bold(f'── {label} Metadata ──')}")
    for field in META_FIELDS:
        value = meta.get(field, "")
        if value:
            found = True
            print(f"    {yellow(field):>20s}: {value}")
    if not found:
        print(green("    ✓ No metadata found — file is clean"))
    return found


def wipe_metadata(input_path, output_path=None, preview=False, verbose=False):
    """Strip all metadata from a PDF file."""

    input_path = Path(input_path)
    if not input_path.exists():
        print(red(f"\n  ✗ File not found: {input_path}\n"))
        return False
    if input_path.suffix.lower() != ".pdf":
        print(red(f"\n  ✗ Not a PDF file: {input_path}\n"))
        return False

    if output_path is None:
        output_path = input_path
    else:
        output_path = Path(output_path)

    try:
        doc = fitz.open(str(input_path))
    except Exception as e:
        print(red(f"\n  ✗ Could not open PDF: {e}\n"))
        return False

    if preview or verbose:
        has_meta = show_metadata(doc, "BEFORE")
        if not has_meta and not verbose:
            print(green(f"\n  ✓ {input_path.name} is already clean — nothing to strip.\n"))
            doc.close()
            return True

    if preview:
        print(dim(f"\n  Preview mode — no changes written. Run without --preview to strip.\n"))
        doc.close()
        return True

    # ── Step 1: Clear standard metadata dictionary ──
    empty_meta = {field: "" for field in META_FIELDS}
    doc.set_metadata(empty_meta)

    # ── Step 2: Delete XMP metadata stream ──
    try:
        doc.del_xml_metadata()
    except Exception:
        try:
            doc.set_xml_metadata("")
        except Exception:
            if verbose:
                print(yellow("  ⚠ Could not clear XMP metadata (older PyMuPDF version)"))

    # ── Step 3: Save the cleaned PDF ──
    if output_path == input_path:
        temp_path = input_path.with_suffix(".tmp.pdf")
        doc.save(
            str(temp_path),
            garbage=4,
            deflate=True,
            clean=True,
            no_new_id=False,
        )
        doc.close()
        temp_path.replace(input_path)
        final_path = input_path
    else:
        doc.save(
            str(output_path),
            garbage=4,
            deflate=True,
            clean=True,
            no_new_id=False,
        )
        doc.close()
        final_path = output_path

    # ── Step 4: Verify the result ──
    verify_doc = fitz.open(str(final_path))
    remaining = verify_doc.metadata or {}
    still_dirty = any(remaining.get(f, "") for f in META_FIELDS)

    if verbose:
        show_metadata(verify_doc, "AFTER")

    verify_doc.close()

    if still_dirty:
        print(yellow(f"\n  ⚠ Some metadata may remain in {final_path.name} — inspect manually.\n"))
        return False
    else:
        print(green(f"\n  ✓ All metadata stripped from {final_path.name}"))
        print(dim(f"    Saved to: {final_path}\n"))
        return True


def process_batch(targets, output_dir=None, recursive=False, preview=False, verbose=False):
    """Process multiple files or directories."""
    files = []
    for target in targets:
        p = Path(target)
        if p.is_file():
            if p.suffix.lower() == ".pdf":
                files.append(p)
            else:
                print(yellow(f"  ⚠ Skipping (not a PDF): {p}"))
        elif p.is_dir():
            pattern = "**/*.pdf" if recursive else "*.pdf"
            for pdf in sorted(p.glob(pattern)):
                files.append(pdf)
        else:
            print(yellow(f"  ⚠ Skipping (not found): {target}"))

    if not files:
        print(red("\n  ✗ No PDF files found to process.\n"))
        return

    print(bold(f"\n  Processing {len(files)} PDF file(s)...\n"))

    success = 0
    failed = 0

    for filepath in files:
        print(bold(f"  {'─' * 50}"))
        print(bold(f"  {filepath}"))

        if output_dir:
            out = Path(output_dir) / filepath.name
            out.parent.mkdir(parents=True, exist_ok=True)
        else:
            out = None

        if wipe_metadata(filepath, out, preview=preview, verbose=verbose):
            success += 1
        else:
            failed += 1

    print(bold(f"\n  {'═' * 50}"))
    print(bold(f"  SUMMARY"))
    print(bold(f"  {'═' * 50}"))
    print(f"  Total:   {len(files)}")
    print(green(f"  Cleaned: {success}"))
    if failed:
        print(red(f"  Failed:  {failed}"))
    print()


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="pdf_meta_wipe.py",
        description=(
            "Strip ALL metadata from PDF files — author, creator, producer, "
            "timestamps, XMP data, and more. Outputs a clean PDF with zero "
            "identifying information."
        ),
        epilog="Part of the LocalShield Privacy Toolkit — https://github.com/ArduDevGit/localshield",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="PDF files or directories to process",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Output file (single file) or directory (batch mode). "
             "If omitted, files are overwritten in place.",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Recursively scan directories for PDFs",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Show current metadata without making changes",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show before/after metadata comparison",
    )

    args = parser.parse_args()

    if len(args.targets) == 1 and Path(args.targets[0]).is_file():
        wipe_metadata(
            args.targets[0],
            output_path=args.output,
            preview=args.preview,
            verbose=args.verbose,
        )
    else:
        process_batch(
            args.targets,
            output_dir=args.output,
            recursive=args.recursive,
            preview=args.preview,
            verbose=args.verbose,
        )


if __name__ == "__main__":
    main()
