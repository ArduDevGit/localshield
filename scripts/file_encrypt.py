#!/usr/bin/env python3 
""" 
file_encrypt.py — Encrypt and decrypt files locally with AES-256-GCM. 
  
Uses industry-standard AES-256-GCM authenticated encryption with a password-derived 
key (PBKDF2 with 600,000 iterations). Your files never leave your machine. 
  
Usage: 
    python file_encrypt.py encrypt secret_doc.pdf 
    python file_encrypt.py encrypt secret_doc.pdf -o encrypted_doc.bin 
    python file_encrypt.py decrypt encrypted_doc.bin -o secret_doc.pdf 
    python file_encrypt.py encrypt ./folder/ --recursive 
  
File format: 
    [16 bytes salt][12 bytes nonce][16 bytes auth tag][...ciphertext...] 
    All values are stored as raw bytes. The salt is used to derive the key 
    from your password via PBKDF2-HMAC-SHA256. 
""" 
  
import argparse 
import getpass 
import os 
import sys 
from pathlib import Path 
  
try: 
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM 
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
    from cryptography.hazmat.primitives import hashes 
except ImportError: 
    print("ERROR: cryptography is required. Install it with: pip install cryptography") 
    sys.exit(1) 
  
# --- Configuration --- 
# These values follow current NIST/OWASP recommendations (as of 2025). 
SALT_LENGTH = 16          # 128-bit salt for key derivation 
NONCE_LENGTH = 12         # 96-bit nonce for AES-GCM (standard) 
KEY_LENGTH = 32           # 256-bit key (AES-256) 
KDF_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256 
ENCRYPTED_SUFFIX = ".enc" 
  
  
def derive_key(password, salt): 
    """ 
    Derive a 256-bit encryption key from a password using PBKDF2. 
  
    PBKDF2 (Password-Based Key Derivation Function 2) deliberately makes 
    key derivation slow to resist brute-force attacks. 600,000 iterations 
    means an attacker trying billions of passwords will be significantly slowed. 
  
    Args: 
        password: The user's password as a string 
        salt: Random bytes to ensure the same password produces different keys 
  
    Returns: 
        32 bytes (256-bit) encryption key 
    """ 
    kdf = PBKDF2HMAC( 
        algorithm=hashes.SHA256(), 
        length=KEY_LENGTH, 
        salt=salt, 
        iterations=KDF_ITERATIONS, 
    ) 
    return kdf.derive(password.encode("utf-8")) 
  
  
def encrypt_file(input_path, output_path, password, verbose=False): 
    """ 
    Encrypt a file using AES-256-GCM. 
  
    AES-GCM provides both confidentiality (nobody can read the data) AND 
    authenticity (nobody can tamper with it without detection). If even one 
    bit of the encrypted file is modified, decryption will fail with an 
    authentication error rather than producing corrupted output. 
  
    Args: 
        input_path: Path to the file to encrypt 
        output_path: Where to save the encrypted file 
        password: Password to derive the encryption key from 
        verbose: Print progress details 
  
    Returns: 
        True if successful, False otherwise 
    """ 
    input_path = Path(input_path) 
    output_path = Path(output_path) 
  
    try: 
        # Read the original file 
        plaintext = input_path.read_bytes() 
        if verbose: 
            print(f"  Read {len(plaintext):,} bytes from {input_path}") 
  
        # Generate cryptographically random salt and nonce 
        salt = os.urandom(SALT_LENGTH) 
        nonce = os.urandom(NONCE_LENGTH) 
  
        # Derive encryption key from password + salt 
        key = derive_key(password, salt) 
        if verbose: 
            print(f"  Key derived ({KDF_ITERATIONS:,} PBKDF2 iterations)") 
  
        # Encrypt with AES-256-GCM 
        aesgcm = AESGCM(key) 
        ciphertext = aesgcm.encrypt(nonce, plaintext, None) 
        # Note: ciphertext includes the 16-byte auth tag appended by AES-GCM 
  
        # Write: salt + nonce + ciphertext (which includes auth tag) 
        output_path.parent.mkdir(parents=True, exist_ok=True) 
        with open(output_path, "wb") as f: 
            f.write(salt) 
            f.write(nonce) 
            f.write(ciphertext) 
  
        if verbose: 
            print(f"  Encrypted {len(ciphertext):,} bytes to {output_path}") 
  
        return True 
  
    except Exception as e: 
        print(f"  ERROR encrypting {input_path}: {e}", file=sys.stderr) 
        return False 
  
  
def decrypt_file(input_path, output_path, password, verbose=False): 
    """ 
    Decrypt a file that was encrypted with encrypt_file(). 
  
    If the password is wrong or the file has been tampered with, 
    decryption will fail with an InvalidTag error — this is the 
    authentication guarantee of AES-GCM. 
  
    Args: 
        input_path: Path to the encrypted file 
        output_path: Where to save the decrypted file 
        password: Password used during encryption 
        verbose: Print progress details 
  
    Returns: 
        True if successful, False otherwise 
    """ 
    input_path = Path(input_path) 
    output_path = Path(output_path) 
  
    try: 
        raw = input_path.read_bytes() 
  
        # Minimum size: salt (16) + nonce (12) + auth tag (16) = 44 bytes 
        min_size = SALT_LENGTH + NONCE_LENGTH + 16 
        if len(raw) < min_size: 
            print(f"  ERROR: File too small to be a valid encrypted file", file=sys.stderr) 
            return False 
  
        # Extract components 
        salt = raw[:SALT_LENGTH] 
        nonce = raw[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH] 
        ciphertext = raw[SALT_LENGTH + NONCE_LENGTH:] 
  
        if verbose: 
            print(f"  Read {len(raw):,} bytes from {input_path}") 
  
        # Derive the same key from password + salt 
        key = derive_key(password, salt) 
        if verbose: 
            print(f"  Key derived ({KDF_ITERATIONS:,} PBKDF2 iterations)") 
  
        # Decrypt and verify authenticity 
        aesgcm = AESGCM(key) 
        try: 
            plaintext = aesgcm.decrypt(nonce, ciphertext, None) 
        except Exception: 
            print("  ERROR: Decryption failed — wrong password or file has been tampered with.", 
                  file=sys.stderr) 
            return False 
  
        # Write decrypted file 
        output_path.parent.mkdir(parents=True, exist_ok=True) 
        output_path.write_bytes(plaintext) 
  
        if verbose: 
            print(f"  Decrypted {len(plaintext):,} bytes to {output_path}") 
  
        return True 
  
    except Exception as e: 
        print(f"  ERROR decrypting {input_path}: {e}", file=sys.stderr) 
        return False 
  
  
def get_password(confirm=False): 
    """Securely prompt for a password (input is hidden).""" 
    password = getpass.getpass("Enter password: ") 
    if not password: 
        print("ERROR: Password cannot be empty.", file=sys.stderr) 
        sys.exit(1) 
  
    if confirm: 
        password2 = getpass.getpass("Confirm password: ") 
        if password != password2: 
            print("ERROR: Passwords do not match.", file=sys.stderr) 
            sys.exit(1) 
  
    return password 
  
  
def find_files(path, recursive=False): 
    """Find all files in a path (file or directory).""" 
    path = Path(path) 
    if path.is_file(): 
        return [path] 
    if path.is_dir(): 
        if recursive: 
            return sorted(f for f in path.rglob("*") if f.is_file()) 
        else: 
            return sorted(f for f in path.iterdir() if f.is_file()) 
    print(f"Path not found: {path}", file=sys.stderr) 
    return [] 
  
  
def main(): 
    parser = argparse.ArgumentParser( 
        description="Encrypt and decrypt files locally with AES-256-GCM.", 
        epilog="Examples:\n" 
               "  python file_encrypt.py encrypt secret.pdf\n" 
               "  python file_encrypt.py decrypt secret.pdf.enc -o secret.pdf\n" 
               "  python file_encrypt.py encrypt ./docs/ --recursive", 
        formatter_class=argparse.RawDescriptionHelpFormatter, 
    ) 
    parser.add_argument( 
        "action", 
        choices=["encrypt", "decrypt"], 
        help="Action to perform", 
    ) 
    parser.add_argument( 
        "input", 
        help="File or directory to process", 
    ) 
    parser.add_argument( 
        "-o", "--output", 
        help="Output file or directory (default: adds/removes .enc suffix)", 
    ) 
    parser.add_argument( 
        "-r", "--recursive", 
        action="store_true", 
        help="Process directories recursively", 
    ) 
    parser.add_argument( 
        "-v", "--verbose", 
        action="store_true", 
        help="Print detailed progress", 
    ) 
  
    args = parser.parse_args() 
  
    # Get password 
    confirm = args.action == "encrypt" 
    password = get_password(confirm=confirm) 
  
    # Find files 
    files = find_files(args.input, recursive=args.recursive) 
    if not files: 
        print("No files found to process.") 
        sys.exit(1) 
  
    print(f"\nFound {len(files)} file(s) to {args.action}.\n") 
  
    success = 0 
    failed = 0 
  
    for file_path in files: 
        # Determine output path 
        if args.output and len(files) == 1: 
            out_path = Path(args.output) 
        elif args.output and len(files) > 1: 
            out_path = Path(args.output) / file_path.name 
            if args.action == "encrypt": 
                out_path = out_path.with_suffix(out_path.suffix + ENCRYPTED_SUFFIX) 
            else: 
                if out_path.suffix == ENCRYPTED_SUFFIX: 
                    out_path = out_path.with_suffix("") 
        else: 
            if args.action == "encrypt": 
                out_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_SUFFIX) 
            else: 
                if file_path.suffix == ENCRYPTED_SUFFIX: 
                    out_path = file_path.with_suffix("") 
                else: 
                    out_path = file_path.with_suffix(file_path.suffix + ".dec") 
  
        action_label = "Encrypting" if args.action == "encrypt" else "Decrypting" 
        print(f"{action_label}: {file_path} -> {out_path}") 
  
        if args.action == "encrypt": 
            ok = encrypt_file(file_path, out_path, password, verbose=args.verbose) 
        else: 
            ok = decrypt_file(file_path, out_path, password, verbose=args.verbose) 
  
        if ok: 
            success += 1 
        else: 
            failed += 1 
  
    print(f"\nDone. {success} succeeded, {failed} failed.") 
  
  
if __name__ == "__main__": 
    main() 