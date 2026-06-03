#!/usr/bin/env python3
"""
Sh4d0w - Hash Algorithm Identifier
Usage:
    python shadow.py              # interactive mode
    python shadow.py '<hash>'     # single hash
    python shadow.py '<hash>' '<plaintext>'  # verify against plaintext

Always wrap hashes in single quotes to prevent shell variable expansion.
"""

import re
import sys
import hashlib

GREEN = "\033[92m"
RESET = "\033[0m"

ASCII_ART_LINES = [
    " .d8888b. 888         d8888      888 .d8888b.               ",
    "d88P  Y88b888        d8P888      888d88P  Y88b              ",
    "Y88b.     888       d8P 888      888888    888              ",
    " \"Y888b.  88888b.  d8P  888  .d88888888    888888  888  888 ",
    "    \"Y88b.888 \"88bd88   888 d88\" 888888    888888  888  888 ",
    "      \"888888  8888888888888888  888888    888888  888  888 ",
    "Y88b  d88P888  888      888 Y88b 888Y88b  d88PY88b 888 d88P ",
    " \"Y8888P\" 888  888      888  \"Y88888 \"Y8888P\"  \"Y8888888P\"",
]

MODULAR_PATTERNS = [
    (r"^\$y\$",                       "yescrypt (Linux default, Debian 11+/Ubuntu 22.04+)"),
    (r"^\$gy\$",                      "gost-yescrypt"),
    (r"^\$7\$",                       "scrypt ($7$)"),
    (r"^\$2[ayb]?\$\d{2}\$.{53}$",   "bcrypt"),
    (r"^\$argon2(i|d|id)\$",          "Argon2"),
    (r"^\$s0\$",                      "scrypt ($s0$)"),
    (r"^pbkdf2_sha(1|256|512)\$",     "PBKDF2 (Django)"),
    (r"^\$1\$.{1,8}\$.{22}$",         "Unix MD5 crypt ($1$)"),
    (r"^\$5\$",                       "Unix SHA-256 crypt ($5$)"),
    (r"^\$6\$",                       "Unix SHA-512 crypt ($6$)"),
    (r"^\$md5",                       "SunMD5 crypt"),
    (r"^\$sha1\$",                    "SHA-1 crypt (NetBSD)"),
    (r"^\$P\$.{31}$|^\$H\$.{31}$",   "WordPress / phpBB MD5"),
    (r"^\$S\$.{52}$",                 "Drupal 7 (SHA-512)"),
    (r"^\*[a-f0-9]{40}$",             "MySQL 4.1+"),
]

HEX_LENGTH_MAP = {
    8:   ["CRC32", "Adler-32"],
    16:  ["MySQL 3.x"],
    32:  ["MD5", "MD4", "NTLM", "LM Hash"],
    40:  ["SHA-1", "RIPEMD-160"],
    56:  ["SHA-224", "SHA3-224"],
    64:  ["SHA-256", "SHA3-256", "BLAKE2s"],
    96:  ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
}


def print_banner():
    W = 78  # inner width between the two # chars
    g = GREEN
    r = RESET
    print(g + "#" * 80 + r)
    print(g + "#" + " " * W + "#" + r)
    for line in ASCII_ART_LINES:
        print(g + "#" + line.center(W) + "#" + r)
    print(g + "#" + " " * W + "#" + r)
    print(g + "#" + "Hash Algorithm Identifier".center(W) + "#" + r)
    print(g + "#" + "By Sh4d0wSpl01t v1.0".center(W) + "#" + r)
    print(g + "#" + " " * W + "#" + r)
    print(g + "#" * 80 + r)


def identify(hash_string):
    h = hash_string.strip()
    for pattern, name in MODULAR_PATTERNS:
        if re.match(pattern, h, re.IGNORECASE):
            return name, "HIGH", None
    if re.match(r"^[a-f0-9]+$", h, re.IGNORECASE):
        candidates = HEX_LENGTH_MAP.get(len(h))
        if candidates:
            confidence = "HIGH" if len(candidates) == 1 else "MEDIUM"
            return ", ".join(candidates), confidence, None
        return "Unknown (unrecognised hex length)", "LOW", None
    if not h.startswith("$") and len(h) in (44, 52, 53, 31):
        return "Unknown", "LOW", "Hash may be shell-expanded — wrap in single quotes"
    return "Unknown", "LOW", None


def verify(hash_string, plaintext):
    h = hash_string.strip().lower()
    matched = []
    for algo in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                 "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2s", "blake2b"]:
        try:
            if hashlib.new(algo, plaintext.encode()).hexdigest() == h:
                matched.append(algo.upper().replace("_", "-").replace("SHA3", "SHA3-"))
        except ValueError:
            pass
    return matched


def analyse(hash_string):
    algo, confidence, warning = identify(hash_string)
    short = hash_string[:60] + ("..." if len(hash_string) > 60 else "")
    print(f"\n  Hash      : {short}")
    print(GREEN + f"  Algorithm : {algo}" + RESET)
    print(f"  Confidence: {confidence}")
    if warning:
        print(f"  Warning   : {warning}")
    print()


def interactive():
    print_banner()
    print()
    print("-" * 80)
    print("  Type a hash to identify it. Ctrl+C or 'quit' to exit.")
    print("-" * 80)
    while True:
        try:
            hash_input = input(GREEN + "\n  HASH: " + RESET).strip()
            if not hash_input:
                continue
            if hash_input.lower() in ("quit", "exit", "q"):
                print("\n  Goodbye.\n")
                break
            analyse(hash_input)
            print("-" * 80)
        except KeyboardInterrupt:
            print("\n\n  Goodbye.\n")
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        interactive()
    else:
        h = sys.argv[1]
        plaintext = sys.argv[2] if len(sys.argv) > 2 else None
        algo, confidence, warning = identify(h)
        short = h[:60] + ("..." if len(h) > 60 else "")
        if plaintext and re.match(r"^[a-f0-9]+$", h.strip(), re.IGNORECASE):
            matched = verify(h, plaintext)
            if matched:
                algo = ", ".join(matched) + " (verified)"
                confidence = "HIGH"
        print(f"Hash      : {short}")
        print(GREEN + f"Algorithm : {algo}" + RESET)
        print(f"Confidence: {confidence}")
        if warning:
            print(f"Warning   : {warning}")
