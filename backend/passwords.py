# -*- coding: utf-8 -*-
"""
Part 3 — Passwords: attacks and protection.

Three target cases from the assignment:
  - "bin3" : 3 characters, each in {0,1}          -> 2^3  = 8 combinations
  - "num4" : 4 characters, each in {1,2,3,4}       -> 4^4  = 256 combinations
  - "full" : charset a-z A-Z 0-9 + *               -> 64^length combinations

Two attacks (with time and number of attempts measured):
  - brute force  : try every combination of the charset
  - dictionary   : try every word of a list

Protection (what to do against those attacks):
  - salted slow hashing (PBKDF2-HMAC-SHA256) so each guess costs a lot
  - rate limiting / lockout, the ONLY thing that helps a tiny keyspace (8, 256)

Everything uses the Python standard library only (no external dependency), so
the team can read and run it anywhere.
"""

import hashlib
import hmac
import itertools
import secrets
import string
import time

# Charsets of the three cases.
FULL_CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "+*"

CASES = {
    "bin3": {"charset": "01", "length": 3, "label": "3 characters in {0,1}"},
    "num4": {"charset": "1234", "length": 4, "label": "4 characters in {1,2,3,4}"},
    "full": {"charset": FULL_CHARSET, "length": 4, "label": "a-z A-Z 0-9 + *"},
}

# Hard cap so the server never hangs on a huge keyspace.
MAX_ATTEMPTS = 3_000_000

# A tiny demo dictionary of common passwords (enough to show the idea).
DEFAULT_DICTIONARY = [
    "123", "0000", "1111", "1234", "12345", "123456", "password", "admin",
    "root", "qwerty", "azerty", "letmein", "welcome", "abc", "abcd", "test",
    "111", "000", "101", "010", "110", "011", "001", "100",
    "1111", "2222", "3333", "4444", "1234", "4321", "2413", "3142",
]


def keyspace(charset, length):
    return len(charset) ** length


def _resolve_case(case, length=None):
    """Return (charset, length, label) for a case id, with an optional length
    override for the 'full' case."""
    if case not in CASES:
        raise ValueError(f"Unknown case '{case}'. Use one of: {', '.join(CASES)}.")
    cfg = CASES[case]
    charset = cfg["charset"]
    chosen_length = length if (case == "full" and length) else cfg["length"]
    return charset, chosen_length, cfg["label"]


def brute_force(target, case, length=None):
    """Try every combination of the case charset until the target is found."""
    charset, length, label = _resolve_case(case, length)
    space = keyspace(charset, length)
    start = time.perf_counter()
    attempts = 0
    for combo in itertools.product(charset, repeat=length):
        attempts += 1
        if "".join(combo) == target:
            return {
                "found": True, "password": target, "attempts": attempts,
                "seconds": time.perf_counter() - start, "keyspace": space,
                "label": label, "stopped": False,
            }
        if attempts >= MAX_ATTEMPTS:
            return {
                "found": False, "attempts": attempts,
                "seconds": time.perf_counter() - start, "keyspace": space,
                "label": label, "stopped": True,
            }
    return {
        "found": False, "attempts": attempts,
        "seconds": time.perf_counter() - start, "keyspace": space,
        "label": label, "stopped": False,
    }


def dictionary_attack(target, words=None):
    """Try every word of the list until the target is found."""
    words = words if words else DEFAULT_DICTIONARY
    start = time.perf_counter()
    attempts = 0
    for w in words:
        attempts += 1
        if w == target:
            return {
                "found": True, "password": target, "attempts": attempts,
                "seconds": time.perf_counter() - start, "size": len(words),
            }
    return {
        "found": False, "attempts": attempts,
        "seconds": time.perf_counter() - start, "size": len(words),
    }


def estimate(case, length=None, guesses_per_second=1_000_000_000):
    """Keyspace and brute-force time estimate at a given guessing rate.

    1e9 guesses/s is a rough figure for a fast offline attack on a plain (fast)
    hash. A slow salted hash (see hash_password) collapses that rate, which is
    exactly why it is used for protection.
    """
    charset, length, label = _resolve_case(case, length)
    space = keyspace(charset, length)
    seconds_fast = space / guesses_per_second
    # Same keyspace, but a slow KDF caps throughput to ~1e4 guesses/s.
    seconds_slow = space / 10_000
    return {
        "label": label,
        "charsetSize": len(charset),
        "length": length,
        "keyspace": space,
        "secondsFast": seconds_fast,
        "secondsSlow": seconds_slow,
    }


def hash_password(password, iterations=200_000):
    """Protection: salted slow hash. Never store a plain password."""
    salt = secrets.token_bytes(16)
    start = time.perf_counter()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    elapsed = time.perf_counter() - start
    return {
        "algo": "PBKDF2-HMAC-SHA256",
        "salt": salt.hex(),
        "iterations": iterations,
        "hash": dk.hex(),
        "secondsPerGuess": elapsed,
    }


def verify_password(password, salt_hex, iterations, hash_hex):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iterations)
    return hmac.compare_digest(dk.hex(), hash_hex)
