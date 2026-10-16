# -*- coding: utf-8 -*-
"""
Step-by-step traces for the animations (Part 1).

The ciphers themselves live in encryption.py. Here, for each algorithm, we
rebuild the SAME computation but record every step as plain data (which cell to
highlight, which shift to apply, which multiplication to show). The React
frontend only reads this data and animates it — all the real logic stays in
Python, so the team understands the algorithms from a single source.

Each function returns a dict with "kind", "result" and "steps" (plus whatever
the animation needs: the alphabet rows, the Playfair grid, the Hill matrix...).
"""

import encryption as en

A = ord("A")


# ---------------------------------------------------------------- Caesar ----
def caesar_trace(message, shift, direction, operation):
    """Two alphabet rows (input / output) and one step per character."""
    if operation == "encrypt":
        eff = -shift if direction == "left" else shift
        result = en.caesar_encrypt(message, shift, direction)
    else:  # decrypt = encrypt with the opposite direction
        eff = shift if direction == "left" else -shift
        result = en.caesar_decrypt(message, shift, direction)
    eff %= 26

    alphabet_in = [chr(A + i) for i in range(26)]
    alphabet_out = [alphabet_in[(i + eff) % 26] for i in range(26)]

    steps = []
    for ch in message:
        up = ch.upper()
        if "A" <= up <= "Z":
            idx = ord(up) - A
            out_up = alphabet_out[idx]
            out = out_up if ch.isupper() else out_up.lower()
            steps.append({"type": "map", "char": ch, "out": out, "index": idx})
        else:
            steps.append({"type": "skip", "char": ch})

    return {
        "kind": "caesar",
        "shift": eff,
        "alphabetIn": alphabet_in,
        "alphabetOut": alphabet_out,
        "steps": steps,
        "result": result,
    }


# -------------------------------------------------------------- Playfair ----
def playfair_trace(message, key, operation):
    """The 5x5 grid and one step per digram, with the rule used."""
    m = en._playfair_matrix(key)
    clean = en._playfair_clean(message)

    if operation == "encrypt":
        pairs = en._playfair_digrams(clean)
        delta = 1
        result = en.playfair_encrypt(message, key)
    else:
        pairs = [(clean[i], clean[i + 1]) for i in range(0, len(clean) - 1, 2)]
        delta = -1
        result = en.playfair_decrypt(message, key)

    steps = []
    for a, b in pairs:
        ra, ca = en._playfair_pos(m, a)
        rb, cb = en._playfair_pos(m, b)
        if ra == rb:
            rule = "row"
            out_a, oa = m[ra][(ca + delta) % 5], [ra, (ca + delta) % 5]
            out_b, ob = m[rb][(cb + delta) % 5], [rb, (cb + delta) % 5]
        elif ca == cb:
            rule = "col"
            out_a, oa = m[(ra + delta) % 5][ca], [(ra + delta) % 5, ca]
            out_b, ob = m[(rb + delta) % 5][cb], [(rb + delta) % 5, cb]
        else:
            rule = "rect"
            out_a, oa = m[ra][cb], [ra, cb]
            out_b, ob = m[rb][ca], [rb, ca]
        steps.append({
            "a": a, "b": b, "rule": rule,
            "aPos": [ra, ca], "bPos": [rb, cb],
            "outA": out_a, "outB": out_b, "outAPos": oa, "outBPos": ob,
        })

    return {"kind": "playfair", "grid": m, "steps": steps, "result": result}


# ------------------------------------------------------------------ Hill ----
def hill_trace(message, matrix, operation):
    """The matrix (or its inverse for decrypt) times each block, row by row."""
    n = len(matrix)
    if operation == "encrypt":
        use = matrix
        result = en.hill_encrypt(message, matrix)
        text = en._hill_clean(message)
        while len(text) % n != 0:
            text += "X"
    else:
        use = en.matrix_mod_inverse(matrix)  # raises if not invertible
        result = en.hill_decrypt(message, matrix)
        text = en._hill_clean(message)
        while len(text) % n != 0:            # safety, normally already aligned
            text += "X"

    nums = [ord(c) - A for c in text]
    blocks, steps = [], []
    out_pos = 0
    for i in range(0, len(nums), n):
        block_vals = nums[i:i + n]
        blocks.append({
            "letters": [chr(v + A) for v in block_vals],
            "values": block_vals,
        })
        bidx = i // n
        for r in range(n):
            row = use[r]
            s = sum(row[k] * block_vals[k] for k in range(n))
            steps.append({
                "blockIndex": bidx,
                "rowIndex": r,
                "row": row,
                "values": block_vals,
                "terms": [[row[k], block_vals[k]] for k in range(n)],
                "sum": s,
                "mod": s % 26,
                "outChar": chr(s % 26 + A),
                "outIndex": out_pos,
            })
            out_pos += 1

    return {
        "kind": "hill",
        "n": n,
        "matrix": use,
        "cleaned": text,
        "blocks": blocks,
        "steps": steps,
        "result": result,
    }
