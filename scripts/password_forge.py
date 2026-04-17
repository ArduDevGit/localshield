#!/usr/bin/env python3
"""
password_forge.py — Cryptographically strong password generator.

Generates passwords using Python's `secrets` module, which provides
cryptographically strong random numbers suitable for security-sensitive
applications. No network calls, no external APIs — everything runs locally.

Usage:
    python password_forge.py
    python password_forge.py --length 24
    python password_forge.py --mode passphrase --words 6
    python password_forge.py --mode pin --length 8
    python password_forge.py --count 10 --length 20
    python password_forge.py --exclude-ambiguous --no-symbols

Modes: random (default), passphrase, pin
"""

import argparse
import math
import os
import secrets
import string
import sys

# ---------------------------------------------------------------------------
# Word List for Passphrase Mode
# ---------------------------------------------------------------------------
# EFF Short Wordlist style — common, easy-to-type English words.
# We ship a built-in list so the script works offline with zero dependencies.
# These words are selected for clarity: no homophones, no offensive terms,
# no easily confused spellings.

WORDLIST = [
    "about", "above", "acid", "actor", "adopt", "adult", "again", "agent",
    "agree", "ahead", "alarm", "album", "alert", "alien", "align", "alive",
    "allow", "alone", "along", "alpha", "alter", "among", "ample", "angel",
    "anger", "angle", "ankle", "annex", "apart", "apple", "apply", "arena",
    "argue", "arise", "armor", "array", "arrow", "aside", "asset", "atlas",
    "avoid", "award", "aware", "bacon", "badge", "baker", "basic", "basin",
    "batch", "beach", "beard", "begun", "being", "bench", "berry", "blade",
    "blame", "blank", "blast", "blaze", "blend", "bless", "blind", "block",
    "bloom", "blown", "board", "bonus", "bound", "brace", "brain", "brand",
    "brave", "bread", "break", "breed", "brick", "bride", "brief", "bring",
    "broad", "brook", "brown", "brush", "build", "bunch", "burst", "cabin",
    "cable", "camel", "candy", "cargo", "carry", "catch", "cause", "cedar",
    "chain", "chair", "chalk", "charm", "chart", "chase", "cheap", "check",
    "chess", "chief", "child", "chunk", "civic", "civil", "claim", "clash",
    "clean", "clear", "clerk", "click", "cliff", "climb", "cling", "clips",
    "clock", "clone", "close", "cloud", "coach", "coast", "color", "comic",
    "coral", "couch", "could", "count", "court", "cover", "crack", "craft",
    "crane", "crash", "crawl", "crazy", "cream", "creek", "crest", "crowd",
    "crown", "crush", "cubic", "curve", "cycle", "daily", "dance", "debug",
    "decay", "decoy", "delta", "dense", "depth", "devil", "digit", "dodge",
    "donor", "doubt", "draft", "drain", "drake", "drama", "drawn", "dream",
    "drift", "drink", "drive", "drums", "dusty", "dwarf", "eager", "eagle",
    "early", "earth", "eight", "elder", "elite", "ember", "empty", "enjoy",
    "enter", "entry", "equal", "error", "essay", "event", "every", "exact",
    "exile", "exist", "extra", "fable", "facet", "faith", "false", "farce",
    "fault", "feast", "fence", "ferry", "fiber", "field", "fifth", "fifty",
    "final", "first", "fixed", "flame", "flash", "flask", "fleet", "flesh",
    "flint", "float", "flock", "flood", "floor", "flora", "flour", "fluid",
    "flush", "flute", "focal", "focus", "force", "forge", "forum", "found",
    "foxes", "frame", "frank", "fraud", "freed", "fresh", "front", "frost",
    "fruit", "fungi", "fuzzy", "gazer", "giant", "given", "glass", "gleam",
    "glide", "globe", "gloom", "glory", "glove", "grace", "grade", "grain",
    "grand", "grant", "graph", "grasp", "grass", "grave", "great", "green",
    "greet", "grief", "grind", "gripe", "groom", "group", "grove", "grown",
    "guard", "guess", "guide", "guild", "habit", "haiku", "happy", "hardy",
    "haven", "heart", "hedge", "helix", "hence", "herbs", "hinge", "hobby",
    "honor", "horse", "hotel", "house", "human", "humor", "hyper", "ideal",
    "image", "inbox", "index", "indie", "inner", "input", "irony", "ivory",
    "jewel", "joint", "joker", "juice", "jumbo", "kebab", "knack", "kneel",
    "knife", "knock", "known", "label", "lance", "large", "laser", "latch",
    "later", "laugh", "layer", "leapt", "learn", "lease", "leave", "ledge",
    "legal", "lemon", "level", "lever", "light", "lilac", "linen", "liver",
    "llama", "lobby", "local", "lodge", "logic", "lotus", "lover", "lower",
    "lucky", "lunar", "lunch", "lyric", "magic", "major", "maker", "manor",
    "maple", "march", "match", "mayor", "media", "melon", "mercy", "merge",
    "merit", "metal", "meter", "might", "minor", "minus", "mixed", "model",
    "money", "month", "moral", "motor", "mount", "mouse", "mouth", "moved",
    "mural", "music", "naive", "nerve", "never", "newly", "night", "noble",
    "noise", "north", "noted", "novel", "nudge", "nurse", "nylon", "ocean",
    "offer", "olive", "onset", "opera", "orbit", "order", "organ", "other",
    "outer", "owner", "oxide", "ozone", "paced", "paint", "panel", "panic",
    "paper", "patch", "pause", "peace", "pearl", "pedal", "penny", "phase",
    "photo", "piano", "piece", "pilot", "pinch", "pixel", "pizza", "place",
    "plain", "plane", "plant", "plate", "plaza", "plead", "plumb", "plume",
    "plunk", "point", "polar", "poser", "pound", "power", "press", "price",
    "pride", "prime", "print", "prior", "prize", "probe", "prose", "proud",
    "prove", "proxy", "psalm", "pulse", "pupil", "purge", "queen", "query",
    "quest", "queue", "quick", "quiet", "quota", "quote", "radar", "radio",
    "raise", "rally", "range", "rapid", "raven", "reach", "react", "realm",
    "rebel", "recap", "refer", "reign", "relax", "renew", "repay", "reply",
    "ridge", "right", "rigid", "risky", "rival", "river", "roast", "robin",
    "robot", "rocky", "rogue", "roman", "rouge", "round", "route", "royal",
    "ruler", "rural", "sadly", "saint", "salon", "sandy", "sauna", "saved",
    "scale", "scene", "scope", "score", "scout", "screw", "sedan", "sense",
    "serve", "seven", "shade", "shake", "shall", "shame", "shape", "share",
    "shark", "sharp", "shelf", "shell", "shift", "shine", "shirt", "shock",
    "shore", "short", "shout", "shown", "sigma", "sight", "since", "sixth",
    "sixty", "sized", "skill", "slate", "sleep", "slice", "slide", "slope",
    "smart", "smile", "smoke", "snack", "snake", "solar", "solid", "solve",
    "sorry", "south", "space", "spare", "spark", "speak", "speed", "spend",
    "spice", "spike", "spine", "spoke", "spoon", "spray", "squad", "stack",
    "staff", "stage", "stake", "stale", "stall", "stamp", "stand", "stark",
    "state", "stave", "stays", "steam", "steel", "steep", "steer", "stern",
    "stick", "still", "stock", "stomp", "stone", "stood", "store", "storm",
    "story", "stout", "stove", "straw", "strip", "stuck", "study", "stuff",
    "style", "suite", "sunny", "super", "surge", "swamp", "swear", "sweep",
    "sweet", "swept", "swift", "swing", "sword", "syrup", "table", "taken",
    "taste", "teach", "tempo", "tenor", "tenth", "theme", "thick", "thing",
    "think", "third", "thorn", "those", "three", "throw", "thumb", "tiger",
    "tight", "timer", "tired", "title", "toast", "token", "total", "touch",
    "tough", "towel", "tower", "toxic", "trace", "track", "trade", "trail",
    "train", "trait", "trash", "treat", "trend", "trial", "tribe", "trick",
    "trout", "truly", "trump", "trunk", "trust", "truth", "tulip", "tuner",
    "tutor", "twist", "ultra", "uncle", "under", "union", "unite", "unity",
    "until", "upper", "upset", "urban", "usage", "usual", "valid", "valor",
    "valve", "vault", "verse", "video", "vigor", "vinyl", "viola", "viral",
    "virus", "visit", "vista", "vital", "vivid", "vocal", "vodka", "voice",
    "voter", "vowel", "wafer", "wages", "wagon", "waste", "watch", "water",
    "weary", "wedge", "wheat", "wheel", "where", "which", "while", "white",
    "whole", "widen", "width", "witch", "woman", "world", "worry", "worth",
    "wound", "wrist", "wrote", "yacht", "yield", "young", "youth", "zebra",
]

# Ambiguous characters that look similar across fonts
AMBIGUOUS_CHARS = set("0O1lI|`'\"")


def generate_random_password(length=16, use_upper=True, use_lower=True,
                             use_digits=True, use_symbols=True,
                             exclude_ambiguous=False, custom_chars=None):
    """
    Generate a cryptographically random character-based password.

    Uses secrets.choice() which draws from the OS CSPRNG, suitable for
    security-sensitive applications.

    Args:
        length: Number of characters
        use_upper: Include uppercase letters
        use_lower: Include lowercase letters
        use_digits: Include digits
        use_symbols: Include special characters
        exclude_ambiguous: Exclude visually ambiguous chars (0/O, 1/l/I)
        custom_chars: If provided, use only these characters

    Returns:
        Generated password string
    """
    if custom_chars:
        charset = custom_chars
    else:
        charset = ""
        if use_upper:
            charset += string.ascii_uppercase
        if use_lower:
            charset += string.ascii_lowercase
        if use_digits:
            charset += string.digits
        if use_symbols:
            charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"

        if exclude_ambiguous:
            charset = "".join(c for c in charset if c not in AMBIGUOUS_CHARS)

    if not charset:
        print("ERROR: No characters available. Enable at least one character set.",
              file=sys.stderr)
        sys.exit(1)

        # Generate password ensuring at least one char from each enabled set
    # (if the password is long enough)
    if length >= 4 and not custom_chars:
        required = []
        if use_upper:
            pool = string.ascii_uppercase
            if exclude_ambiguous:
                pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
            if pool:
                required.append(secrets.choice(pool))
        if use_lower:
            pool = string.ascii_lowercase
            if exclude_ambiguous:
                pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
            if pool:
                required.append(secrets.choice(pool))
        if use_digits:
            pool = string.digits
            if exclude_ambiguous:
                pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
            if pool:
                required.append(secrets.choice(pool))
        if use_symbols:
            pool = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            if exclude_ambiguous:
                pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
            if pool:
                required.append(secrets.choice(pool))

                # Fill remaining length
        remaining = length - len(required)
        password_chars = required + [secrets.choice(charset) for _ in range(remaining)]

        # Shuffle using Fisher-Yates with secrets
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        return "".join(password_chars)
    else:
        return "".join(secrets.choice(charset) for _ in range(length))


def generate_passphrase(words=5, separator="-", capitalize=False):
    """
    Generate a passphrase from random dictionary words.

    Passphrases are easier to remember than random characters while
    providing excellent entropy (each word adds ~log2(len(WORDLIST)) bits).

    Args:
        words: Number of words
        separator: Character(s) between words
        capitalize: Capitalize each word

    Returns:
        Generated passphrase string
    """
    chosen = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def generate_pin(length=6):
    """
    Generate a numeric PIN.

    Uses secrets.randbelow() for cryptographic randomness.

    Args:
        length: Number of digits

    Returns:
        PIN string
    """
    # Generate each digit independently for true randomness
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def calculate_entropy(password, mode, **kwargs):
    """
    Calculate the entropy (bits of randomness) of a generated password.

    Higher entropy = harder to brute force.
    - 40 bits: Weak (okay for low-value accounts)
    - 60 bits: Reasonable
    - 80 bits: Strong
    - 100+ bits: Excellent
    """
    if mode == "passphrase":
        word_count = kwargs.get("words", 5)
        return word_count * math.log2(len(WORDLIST))
    elif mode == "pin":
        return kwargs.get("length", 6) * math.log2(10)
    else:
        # Character-based: entropy = length * log2(charset_size)
        charset_size = 0
        if kwargs.get("use_upper", True):
            charset_size += 26
        if kwargs.get("use_lower", True):
            charset_size += 26
        if kwargs.get("use_digits", True):
            charset_size += 10
        if kwargs.get("use_symbols", True):
            charset_size += len("!@#$%^&*()-_=+[]{}|;:,.<>?")
        if kwargs.get("exclude_ambiguous", False):
            charset_size -= len(AMBIGUOUS_CHARS)
            charset_size = max(charset_size, 1)

        return kwargs.get("length", 16) * math.log2(max(charset_size, 1))


def entropy_rating(bits):
    """Human-readable strength rating based on entropy."""
    if bits < 40:
        return "Weak"
    elif bits < 60:
        return "Fair"
    elif bits < 80:
        return "Good"
    elif bits < 100:
        return "Strong"
    else:
        return "Excellent"


def main():
    parser = argparse.ArgumentParser(
        description="Generate cryptographically strong passwords locally.",
        epilog="Examples:\n"
               "  python password_forge.py                          # 16-char random\n"
               "  python password_forge.py --length 24              # 24-char random\n"
               "  python password_forge.py --mode passphrase -w 6   # 6-word passphrase\n"
               "  python password_forge.py --mode pin --length 8    # 8-digit PIN\n"
               "  python password_forge.py --count 5 --length 20    # 5 passwords\n"
               "  python password_forge.py --exclude-ambiguous      # No 0/O, 1/l/I",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["random", "passphrase", "pin"],
        default="random",
        help="Password generation mode (default: random)",
    )
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=None,
        help="Password length in characters (random/pin) — default: 16 for random, 6 for pin",
    )
    parser.add_argument(
        "-w", "--words",
        type=int,
        default=5,
        help="Number of words for passphrase mode (default: 5)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=1,
        help="Number of passwords to generate (default: 1)",
    )
    parser.add_argument(
        "--separator",
        default="-",
        help="Word separator for passphrase mode (default: -)",
    )
    parser.add_argument(
        "--capitalize",
        action="store_true",
        help="Capitalize each word in passphrase mode",
    )
    parser.add_argument(
        "--no-upper",
        action="store_true",
        help="Exclude uppercase letters",
    )
    parser.add_argument(
        "--no-lower",
        action="store_true",
        help="Exclude lowercase letters",
    )
    parser.add_argument(
        "--no-digits",
        action="store_true",
        help="Exclude digits",
    )
    parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Exclude special characters",
    )
    parser.add_argument(
        "--exclude-ambiguous",
        action="store_true",
        help="Exclude visually ambiguous characters (0/O, 1/l/I)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show entropy and strength analysis",
    )

    args = parser.parse_args()

    # Set defaults based on mode
    if args.length is None:
        if args.mode == "pin":
            args.length = 6
        else:
            args.length = 16

            # Validate
    if args.length < 1:
        print("ERROR: Length must be at least 1", file=sys.stderr)
        sys.exit(1)
    if args.count < 1:
        print("ERROR: Count must be at least 1", file=sys.stderr)
        sys.exit(1)
    if args.words < 2:
        print("ERROR: Passphrase must have at least 2 words", file=sys.stderr)
        sys.exit(1)

        # Calculate entropy for display
    entropy_kwargs = {
        "length": args.length,
        "words": args.words,
        "use_upper": not args.no_upper,
        "use_lower": not args.no_lower,
        "use_digits": not args.no_digits,
        "use_symbols": not args.no_symbols,
        "exclude_ambiguous": args.exclude_ambiguous,
    }
    entropy_bits = calculate_entropy("", args.mode, **entropy_kwargs)
    rating = entropy_rating(entropy_bits)

    # Generate passwords
    passwords = []
    for _ in range(args.count):
        if args.mode == "passphrase":
            pw = generate_passphrase(
                words=args.words,
                separator=args.separator,
                capitalize=args.capitalize,
            )
        elif args.mode == "pin":
            pw = generate_pin(length=args.length)
        else:
            pw = generate_random_password(
                length=args.length,
                use_upper=not args.no_upper,
                use_lower=not args.no_lower,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous,
            )
        passwords.append(pw)

        # Output
    if args.verbose:
        mode_label = args.mode.capitalize()
        if args.mode == "passphrase":
            print(f"Mode: {mode_label} ({args.words} words, separator: '{args.separator}')")
        elif args.mode == "pin":
            print(f"Mode: {mode_label} ({args.length} digits)")
        else:
            print(f"Mode: {mode_label} ({args.length} characters)")
        print(f"Entropy: {entropy_bits:.1f} bits — {rating}")
        print(f"Generated: {args.count} password(s)\n")

    for pw in passwords:
        print(pw)


if __name__ == "__main__":
    main()