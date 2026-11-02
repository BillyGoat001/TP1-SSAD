import encryption as en

A = ord("A")


# Trace du chiffre de Cesar : construit les deux rangees d'alphabet (entree /
# sortie) et un pas par caractere. Dechiffrer revient a chiffrer dans le sens
# oppose, d'ou le decalage effectif `eff` inverse.
def caesar_trace(message, shift, direction, operation):
    if operation == "encrypt":
        eff = -shift if direction == "left" else shift
        result = en.caesar_encrypt(message, shift, direction)
    else:
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


# Trace de Playfair : la grille 5x5 et un pas par digramme, avec la regle
# appliquee (meme ligne, meme colonne, ou rectangle) et les positions avant /
# apres. `delta` vaut -1 au dechiffrement pour parcourir la grille a l'envers.
def playfair_trace(message, key, operation):
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


# Trace de Hill : un pas par ligne de la matrice et par bloc, avec les termes du
# produit, la somme et son modulo 26. Au dechiffrement on utilise l'inverse
# modulaire de la matrice (leve une exception si elle n'est pas inversible).
def hill_trace(message, matrix, operation):
    n = len(matrix)
    if operation == "encrypt":
        use = matrix
        result = en.hill_encrypt(message, matrix)
        text = en._hill_clean(message)
        while len(text) % n != 0:
            text += "X"
    else:
        use = en.matrix_mod_inverse(matrix)
        result = en.hill_decrypt(message, matrix)
        text = en._hill_clean(message)
        while len(text) % n != 0:
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
