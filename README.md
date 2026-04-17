# LocalShield — The Python Privacy Toolkit

**Standalone Python scripts for protecting your personal data entirely offline.**

LocalShield gives you readable, auditable privacy tools that run 100% on your machine. No cloud uploads, no external APIs, no telemetry. Every script is plain `.py` source code you can inspect line-by-line before running.

---

## Why LocalShield?

Every time you need to redact a PDF, strip metadata from a photo, or anonymize a spreadsheet, the top search results want you to **upload your files to someone else's server**. That's the opposite of privacy.

LocalShield is a set of plain Python scripts that do all of this locally. No accounts, no subscriptions, no mystery binaries. You can read every line of code before you run it.

- **Redacting a PDF before sharing it?** The text is actually removed, not just covered with a black box.
- **Stripping EXIF data from photos?** GPS, camera model, timestamps — gone before you post.
- **Anonymizing a CSV for a demo?** Real PII gets replaced with realistic fake data.
- **Need to securely delete a file?** Multi-pass overwrite, not just "move to trash."

If you've ever thought *"I just need a SIMPLE script for this"* — that's what LocalShield is.

---

## Support This Project

LocalShield is free and open source. If these scripts save you time or you want to support an independent developer, you can grab the full package (with usage guide) on Gumroad — pay what you want, including nothing.

👉 [**LocalShield on Gumroad**](https://ardudev.gumroad.com/l/localshield)

---

## What's Inside

| Script | What It Does | Key Library |
|--------|-------------|-------------|
| `exif_strip.py` | Strip GPS, camera, and timestamp metadata from photos | Pillow |
| `file_encrypt.py` | AES-256-GCM file encryption with password-based key derivation | cryptography |
| `data_scan.py` | Scan documents for exposed SSNs, credit cards, emails, phones | stdlib (`re`) |
| `csv_anonymize.py` | Replace real PII in CSV files with realistic fake data | Faker, pandas |
| `pdf_redact.py` | Permanently redact text and regions from PDFs | PyMuPDF |
| `password_forge.py` | Generate cryptographically strong passwords and passphrases | stdlib (`secrets`) |
| `file_shred.py` | Multi-pass overwrite before deletion (secure delete) | stdlib (`os`) |
| `hash_verify.py` | SHA-256 file integrity verification and comparison | stdlib (`hashlib`) |
| `log_cleaner.py` | Sanitize IPs, tokens, emails, and keys from log files | stdlib (`re`) |
| `meta_wipe.py` | Strip author/revision metadata from Word and Excel files | python-docx, openpyxl |

---

## Quick Start

### 1. Install Python 3.8+

Check your version: `python3 --version`

### 2. Install Dependencies

```bash
cd localshield
pip install -r requirements.txt
```

### 3. Run Any Script

Every script has built-in help:

```bash
python scripts/exif_strip.py --help
python scripts/data_scan.py --help
python scripts/file_encrypt.py --help
```

### 4. Try It Out

```bash
# Strip metadata from a photo
python scripts/exif_strip.py vacation.jpg --preview
python scripts/exif_strip.py vacation.jpg -o clean_vacation.jpg

# Scan a folder for exposed PII
python scripts/data_scan.py ./my_documents/ --recursive

# Generate a strong password
python scripts/password_forge.py --length 24 --verbose

# Encrypt a sensitive file
python scripts/file_encrypt.py encrypt taxes.pdf

# Anonymize a customer CSV
python scripts/csv_anonymize.py customers.csv --preview
python scripts/csv_anonymize.py customers.csv -o anonymized.csv

# Verify a downloaded file's integrity
python scripts/hash_verify.py verify download.zip abc123def456...

# Sanitize a log file before sharing
python scripts/log_cleaner.py server.log -o sanitized.log

# Redact SSNs from a PDF
python scripts/pdf_redact.py report.pdf --pattern "\d{3}-\d{2}-\d{4}"

# Strip metadata from a Word document
python scripts/meta_wipe.py contract.docx

# Securely delete a file
python scripts/file_shred.py old_records.csv --passes 3
```

---

## Design Philosophy

- **Readable Source Code** — You can read every line. No obfuscation, no compiled binaries. The code *is* the documentation.
- **Zero Network Calls** — Nothing leaves your machine. No APIs, no analytics, no phone-home.
- **Standalone Scripts** — Each script works independently. Use one, use all — your choice.
- **Standard Libraries** — Built on well-known, battle-tested Python packages.
- **CLI-First** — Every script has a full command-line interface with `--help`, `--verbose`, `--preview`, and `--output` options.

---

## File Structure

```
localshield/
├── GUIDE.pdf                  # Comprehensive usage guide
├── README.md                  # This file
├── LICENSE.txt                # License terms
├── requirements.txt           # Python dependencies
└── scripts/
    ├── exif_strip.py
    ├── file_encrypt.py
    ├── data_scan.py
    ├── csv_anonymize.py
    ├── pdf_redact.py
    ├── password_forge.py
    ├── file_shred.py
    ├── hash_verify.py
    ├── log_cleaner.py
    └── meta_wipe.py
```

---

## Requirements

- Python 3.8 or higher
- pip (Python package manager)
- See `requirements.txt` for library dependencies

**Operating System:** Tested on Windows, works on macOS, and Linux.

---

## Important Notes

- **`file_shred.py` and SSDs:** On solid-state drives, the drive's wear-leveling firmware may write data to new physical locations rather than overwriting in place. For SSDs, use full-disk encryption or your drive manufacturer's Secure Erase command for guaranteed data destruction.

- **`pdf_redact.py` is permanent:** Redacted text is completely removed from the PDF file, not just covered with a black box. Always keep a backup of the original.

- **`file_encrypt.py` passwords:** If you lose your encryption password, your data is unrecoverable. There is no backdoor or recovery mechanism. This is by design.

---

## Ideas?

What would you add as another script that's needed but has no good tools? [Open an issue](../../issues) — no guarantees, but I'll see what I can do.

---



## Disclaimer

This software is provided "as is" without warranty of any kind. It is intended as an educational resource and practical toolkit for personal data privacy. It is not a substitute for professional security auditing, legal compliance review, or enterprise data protection solutions. See `LICENSE.txt` for full terms.
