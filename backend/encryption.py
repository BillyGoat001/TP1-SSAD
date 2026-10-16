# -*- coding: utf-8 -*-
"""
Part 2 — Ciphers: Caesar, Playfair, Hill.

Pure cipher logic (no interface, no web). This is the original Python code from
the Tkinter version, kept as-is so the team reads the algorithms in one place.
The web backend imports these functions; the animations are built on top in
traces.py.
"""

#  Caesar
CAESAR_ALPHABET = 26


def _shift_char(ch, shift):
    if ch.isupper():
        base = ord("A")
    elif ch.islower():
        base = ord("a")
    else:
        return ch
    return chr((ord(ch) - base + shift) % CAESAR_ALPHABET + base)


def caesar_encrypt(text, shift, direction="right"):
    if direction == "left":
        shift = -shift
    return "".join(_shift_char(c, shift) for c in text)


def caesar_decrypt(text, shift, direction="right"):
    return caesar_encrypt(text, shift, "left" if direction == "right" else "right")


def caesar_weak_key(shift):
    if shift % CAESAR_ALPHABET == 0:
        return ("Zero shift (key = 0 or a multiple of 26): the message would "
                "come out identical to the original; it would not be encrypted.")
    if shift % CAESAR_ALPHABET == 13:
        return ("Key 13 (ROT13) is weak: applying it twice brings back the "
                "original message, and it is a well-known convention.")
    return None


#  Playfair
PLAYFAIR_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # alphabet without J


def _playfair_matrix(key):
    key = key.upper().replace("J", "I")  # I and J share the same cell
    seen = []
    for ch in key + PLAYFAIR_ALPHABET:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def _playfair_pos(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c
    raise ValueError(f"The letter '{ch}' is missing in the alphabet")


def _playfair_clean(text):
    return "".join(c for c in text.upper() if c.isalpha()).replace("J", "I")


def _playfair_digrams(text):
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else None
        if b is None:
            pairs.append((a, "X" if a != "X" else "Q"))
            i += 1
        elif a == b:
            pairs.append((a, "X" if a != "X" else "Q"))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def playfair_encrypt(text, key):
    m = _playfair_matrix(key)
    out = []
    for a, b in _playfair_digrams(_playfair_clean(text)):
        ra, ca = _playfair_pos(m, a)
        rb, cb = _playfair_pos(m, b)
        if ra == rb:
            out += [m[ra][(ca + 1) % 5], m[rb][(cb + 1) % 5]]
        elif ca == cb:
            out += [m[(ra + 1) % 5][ca], m[(rb + 1) % 5][cb]]
        else:
            out += [m[ra][cb], m[rb][ca]]
    return "".join(out)


def playfair_decrypt(text, key):
    m = _playfair_matrix(key)
    text = _playfair_clean(text)
    pairs = [(text[i], text[i + 1]) for i in range(0, len(text) - 1, 2)]
    out = []
    for a, b in pairs:
        ra, ca = _playfair_pos(m, a)
        rb, cb = _playfair_pos(m, b)
        if ra == rb:
            out += [m[ra][(ca - 1) % 5], m[rb][(cb - 1) % 5]]
        elif ca == cb:
            out += [m[(ra - 1) % 5][ca], m[(rb - 1) % 5][cb]]
        else:
            out += [m[ra][cb], m[rb][ca]]
    return "".join(out)


#  Hill
MOD = 26


def _egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def _mod_inverse(a, m=MOD):
    g, x, _ = _egcd(a % m, m)
    return None if g != 1 else x % m


def _minor(mat, i, j):
    return [row[:j] + row[j + 1:] for k, row in enumerate(mat) if k != i]


def _determinant(mat):
    n = len(mat)
    if n == 1:
        return mat[0][0]
    if n == 2:
        return mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]
    return sum((-1) ** j * mat[0][j] * _determinant(_minor(mat, 0, j))
               for j in range(n))


def matrix_mod_inverse(mat, m=MOD):
    n = len(mat)
    det = _determinant(mat) % m
    det_inv = _mod_inverse(det, m)
    if det_inv is None:
        raise ValueError(
            f"Invalid key: its determinant ({det}) shares a factor with {m}, "
            f"so the matrix has no inverse mod {m}.")
    cof = [[(-1) ** (i + j) * _determinant(_minor(mat, i, j)) for j in range(n)]
           for i in range(n)]
    adj = [[cof[j][i] for j in range(n)] for i in range(n)]
    return [[(det_inv * adj[i][j]) % m for j in range(n)] for i in range(n)]


def _hill_clean(text):
    return "".join(c for c in text.upper() if c.isalpha())


def _hill_apply(mat, text):
    n = len(mat)
    nums = [ord(c) - ord("A") for c in text]
    out = []
    for i in range(0, len(nums), n):
        block = nums[i:i + n]
        for row in mat:
            out.append(sum(row[k] * block[k] for k in range(n)) % MOD)
    return "".join(chr(v + ord("A")) for v in out)


def hill_encrypt(text, key_matrix):
    text = _hill_clean(text)
    n = len(key_matrix)
    while len(text) % n != 0:
        text += "X"
    return _hill_apply(key_matrix, text)


def hill_decrypt(text, key_matrix):
    inverse = matrix_mod_inverse(key_matrix, MOD)
    return _hill_apply(inverse, _hill_clean(text))


def parse_matrix(s):
    # Transform '3 3 2 5' (or '3,3;2,5') into a square matrix [[3,3],[2,5]].
    nums = [int(x) for x in s.replace(",", " ").replace(";", " ").split()]
    if not nums:
        raise ValueError("Enter the matrix numbers, ex: 3 3 2 5")
    n = round(len(nums) ** 0.5)
    if n * n != len(nums):
        raise ValueError(
            "The size of the key must form a square matrix (4 -> 2x2, 9 -> 3x3).")
    return [nums[i * n:(i + 1) * n] for i in range(n)]


def validate_matrix(matrix):
    """Check a matrix coming from the UI grid: square and made of integers."""
    if not matrix or not all(isinstance(row, list) for row in matrix):
        raise ValueError("The matrix is empty.")
    n = len(matrix)
    if any(len(row) != n for row in matrix):
        raise ValueError("The matrix must be square (same number of rows and columns).")
    for row in matrix:
        for v in row:
            if not isinstance(v, int):
                raise ValueError("The matrix must contain whole numbers only.")
    return matrix


def hill_weak_key(matrix):
    try:
        matrix_mod_inverse(matrix)
    except ValueError as e:
        return f"{e} You can encrypt, but NOT decrypt."
    n = len(matrix)
    identity = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    if matrix == identity:
        return ("Identity matrix: the message would come out identical to the "
                "original; it would not be encrypted.")
    off_diagonal_zero = all(matrix[i][j] == 0
                            for i in range(n) for j in range(n) if i != j)
    if off_diagonal_zero:
        return ("Diagonal matrix: each letter would be encrypted separately, "
                "which amounts to a very weak monoalphabetic cipher.")
    return None
