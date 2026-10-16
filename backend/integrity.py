# -*- coding: utf-8 -*-
"""
Part 4 — Authenticity / Integrity with HMAC-SHA256.

Idea: encryption HIDES a message but does not detect if someone CHANGES it in
transit (exactly what the course says: "encryption does not protect against
modification"). A MAC (Message Authentication Code) adds a short tag computed
from the message AND a shared secret key.

  - Sender A:   tag = HMAC(key, message), sends (message, tag)
  - Receiver B: recomputes HMAC(key, received_message) and compares with tag
      -> tags match    => message intact AND from someone who knows the key
      -> tags differ   => message was altered (or wrong key)

HMAC-SHA256 therefore gives BOTH integrity (not modified) and authenticity
(comes from a holder of the secret). Uses the Python standard library only.
"""

import hashlib
import hmac


def sign(key, message):
    """Compute the HMAC-SHA256 tag (hex) of a message under a shared key."""
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify(key, message, tag):
    """Recompute the tag and compare it in constant time with the received one."""
    expected = sign(key, message)
    return hmac.compare_digest(expected, tag)


def demo(key, original, received):
    """Full A -> (channel) -> B demonstration.

    `original` is what A sent, `received` is what B got (possibly tampered with
    on the way). Returns everything the UI needs to show the detection.
    """
    tag = sign(key, original)              # computed by A
    recomputed = sign(key, received)       # computed by B on what it received
    return {
        "tag": tag,
        "recomputed": recomputed,
        "tampered": original != received,
        "valid": hmac.compare_digest(tag, recomputed),
    }
