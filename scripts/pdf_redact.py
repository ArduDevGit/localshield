#!/usr/bin/env python3
"""
pdf_redact.py — Permanently redact text and regions from PDF files.

Removes sensitive text from PDFs by replacing it with black rectangles.
Unlike simple overlay tools, this permanently removes the underlying text
so it cannot be recovered by copying, selecting, or inspecting the file.

Usage:
    python pdf_redact.py document.pdf --text "John Smith"
    python pdf_redact.py document.pdf --text "SSN: 123-45-6789" -o redacted.pdf
    python pdf_redact.py document.pdf --pattern "\\d{3}-\\d{2}-\\d{4}"
    python pdf_redact.py document.pdf --pages 1,3,5 --text "CONFIDENTIAL"
    python pdf_redact.py document.pdf --preview --text "secret"

Supports: text search, regex patterns, page filtering, preview mode
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

# Default redaction appearance
REDACT_COLOR = (0, 0, 0)  # Black fill
REDACT_TEXT = ""  # No replacement text
REDACT_FONTSIZE = 11


def _check_fitz():
    """Verify PyMuPDF is installed before running."""
    if fitz is None:
        print("ERROR: PyMuPDF is required. Install it with: pip install PyMuPDF",
              file=sys.stderr)
        sys.exit(1)


def find_text_instances(page, search_text, use_regex=False):
    """
    Find all instances of text on a page.

    Args:
        page: PyMuPDF page object
        search_text: Text or regex pattern to find
        use_regex: If True, treat search_text as a regex pattern

    Returns:
        List of fitz.Rect objects marking each instance location
    """
    if use_regex:
        # Use PyMuPDF's built-in text search with regex
        # Get all text on the page and find matches manually
        text_dict = page.get_text("dict")
        rects = []

        for block in text_dict.get("blocks", []):
            if block.get("type") != 0:  # Skip non-text blocks
                continue
            for line in block.get("lines", []):
                # Build the line text and track character positions
                line_text = ""
                spans = []
                for span in line.get("spans", []):
                    span_text = span.get("text", "")
                    spans.append({
                        "text": span_text,
                        "bbox": fitz.Rect(span["bbox"]),
                        "start": len(line_text),
                    })
                    line_text += span_text

                    # Search for regex matches in the line
                try:
                    for match in re.finditer(search_text, line_text):
                        # Find which spans this match covers
                        match_start = match.start()
                        match_end = match.end()

                        # Get bounding rectangles for matched text
                        match_rects = []
                        for span_info in spans:
                            span_start = span_info["start"]
                            span_end = span_start + len(span_info["text"])

                            if span_end > match_start and span_start < match_end:
                                match_rects.append(span_info["bbox"])

                        if match_rects:
                            # Union all rects for this match
                            combined = match_rects[0]
                            for r in match_rects[1:]:
                                combined |= r
                            rects.append(combined)
                except re.error as e:
                    print(f"  Invalid regex pattern: {e}", file=sys.stderr)
                    return []

        return rects
    else:
        # Simple text search using PyMuPDF's built-in method
        return page.search_for(search_text)


def redact_pdf(input_path, output_path, texts=None, patterns=None,
               pages=None, preview=False, verbose=False):
    """
    Redact text from a PDF file.

    Args:
        input_path: Path to input PDF
        output_path: Path for output PDF
        texts: List of exact text strings to redact
        patterns: List of regex patterns to redact
        pages: Set of page numbers to process (1-based, None=all)
        preview: Show what would be redacted without modifying
        verbose: Print detailed progress

    Returns:
        Tuple of (success: bool, stats: dict)
    """
    _check_fitz()

    if not texts and not patterns:
        print("ERROR: Provide at least one --text or --pattern to redact.",
              file=sys.stderr)
        return False, {}

    try:
        doc = fitz.open(str(input_path))
    except Exception as e:
        print(f"ERROR: Cannot open PDF: {e}", file=sys.stderr)
        return False, {}

    stats = {
        "pages_processed": 0,
        "total_redactions": 0,
        "pages_with_redactions": 0,
    }

    # Determine which pages to process
    page_range = range(len(doc))
    if pages:
        # Convert 1-based page numbers to 0-based indices
        page_range = [p - 1 for p in pages if 0 < p <= len(doc)]

    if verbose:
        print(f"  Document has {len(doc)} page(s)")
        print(f"  Processing {len(list(page_range))} page(s)")

    for page_idx in page_range:
        page = doc[page_idx]
        page_num = page_idx + 1
        page_redaction_count = 0

        # Search for exact text matches
        if texts:
            for text in texts:
                instances = find_text_instances(page, text, use_regex=False)
                for rect in instances:
                    if preview:
                        print(f"  Page {page_num}: Found '{text}' at "
                              f"({rect.x0:.0f}, {rect.y0:.0f})")
                    else:
                        # Add redaction annotation
                        page.add_redact_annot(
                            rect,
                            text=REDACT_TEXT,
                            fontsize=REDACT_FONTSIZE,
                            fill=REDACT_COLOR,
                        )
                    page_redaction_count += 1

                    # Search for regex patterns
        if patterns:
            for pattern in patterns:
                instances = find_text_instances(page, pattern, use_regex=True)
                for rect in instances:
                    if preview:
                        # Extract the matched text for preview
                        matched_text = page.get_textbox(rect).strip()
                        display = matched_text[:40] + ("..." if len(matched_text) > 40 else "")
                        print(f"  Page {page_num}: Pattern match '{display}' at "
                              f"({rect.x0:.0f}, {rect.y0:.0f})")
                    else:
                        page.add_redact_annot(
                            rect,
                            text=REDACT_TEXT,
                            fontsize=REDACT_FONTSIZE,
                            fill=REDACT_COLOR,
                        )
                    page_redaction_count += 1

                    # Apply redactions for this page (permanently removes text)
        if not preview and page_redaction_count > 0:
            page.apply_redactions()

        stats["pages_processed"] += 1
        stats["total_redactions"] += page_redaction_count
        if page_redaction_count > 0:
            stats["pages_with_redactions"] += 1

        if verbose and page_redaction_count > 0:
            print(f"  Page {page_num}: {page_redaction_count} redaction(s)")

            # Save the redacted PDF
    if not preview and stats["total_redactions"] > 0:
        try:
            # Save with garbage collection to clean up removed content
            doc.save(
                str(output_path),
                garbage=4,  # Maximum garbage collection
                deflate=True,  # Compress streams
                clean=True,  # Clean unused objects
            )
            if verbose:
                print(f"  Saved to {output_path}")
        except Exception as e:
            print(f"ERROR: Cannot save PDF: {e}", file=sys.stderr)
            doc.close()
            return False, stats

    doc.close()
    return True, stats


def main():
    parser = argparse.ArgumentParser(
        description="Permanently redact text and regions from PDF files.",
        epilog="Examples:\n"
               '  python pdf_redact.py doc.pdf --text "John Smith"\n'
               '  python pdf_redact.py doc.pdf --pattern "\\d{3}-\\d{2}-\\d{4}"\n'
               '  python pdf_redact.py doc.pdf --text "SECRET" --pages 1,2,3\n'
               '  python pdf_redact.py doc.pdf --text "SSN" --preview\n\n'
               "IMPORTANT: Redaction is permanent. The original text is\n"
               "completely removed from the file, not just covered up.\n"
               "Always keep a backup of the original file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input",
        help="PDF file to redact",
    )
    parser.add_argument(
        "-t", "--text",
        action="append",
        default=[],
        help="Exact text to redact (can specify multiple times)",
    )
    parser.add_argument(
        "-p", "--pattern",
        action="append",
        default=[],
        help="Regex pattern to redact (can specify multiple times)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <input>_redacted.pdf)",
    )
    parser.add_argument(
        "--pages",
        help="Comma-separated page numbers to process (default: all)",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Show what would be redacted without modifying the file",
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

    if not args.text and not args.pattern:
        print("ERROR: Provide at least one --text or --pattern to redact.")
        print("  Example: python pdf_redact.py doc.pdf --text \"John Smith\"")
        sys.exit(1)

        # Parse page numbers
    pages = None
    if args.pages:
        try:
            pages = {int(p.strip()) for p in args.pages.split(",")}
        except ValueError:
            print("ERROR: --pages must be comma-separated numbers (e.g., 1,2,3)")
            sys.exit(1)

            # Determine output path
    output_path = args.output
    if output_path is None:
        output_path = input_path.parent / f"{input_path.stem}_redacted.pdf"
    else:
        output_path = Path(output_path)

    if args.preview:
        print(f"Preview mode — showing redaction targets in {input_path}:\n")
    else:
        print(f"Redacting: {input_path}\n")

    success, stats = redact_pdf(
        input_path,
        output_path,
        texts=args.text if args.text else None,
        patterns=args.pattern if args.pattern else None,
        pages=pages,
        preview=args.preview,
        verbose=args.verbose,
    )

    if success:
        print(f"\n--- Summary ---")
        print(f"Pages processed: {stats.get('pages_processed', 0)}")
        print(f"Pages with redactions: {stats.get('pages_with_redactions', 0)}")
        print(f"Total redactions: {stats.get('total_redactions', 0)}")
        if not args.preview and stats.get("total_redactions", 0) > 0:
            print(f"Output saved to: {output_path}")
        elif stats.get("total_redactions", 0) == 0:
            print("No matching text found to redact.")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()