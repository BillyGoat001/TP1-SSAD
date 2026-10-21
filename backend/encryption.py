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
        return ("Décalage nul (clé = 0 ou un multiple de 26) : le message "
                "ressortirait identique, il ne serait pas chiffré.")
    if shift % CAESAR_ALPHABET == 13:
        return ("La clé 13 (ROT13) est faible : l'appliquer deux fois redonne "
                "le message d'origine, et c'est une convention très connue.")
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


def playfair_weak_key(key):
    """Avertissement si la clé laisse la grille de l'alphabet (A B C D E / F G H I K / …) :
    c'est la clé vide, ou un début d'alphabet (A, AB, ABC, ABCDE…), le J comptant pour I."""
    grid = "".join("".join(row) for row in _playfair_matrix(key))
    if grid == PLAYFAIR_ALPHABET:
        return ("Cette clé laisse la grille de l'alphabet (A B C D E / F G H I K…) : "
                "c'est la première grille qu'un attaquant essaie. Sur une même ligne, "
                "une lettre est simplement décalée d'une place, comme un César de clé 1.")
    return None


def _playfair_pos(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c
    raise ValueError(f"La lettre « {ch} » n'existe pas dans la grille.")


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
            f"Clé invalide : son déterminant ({det}) a un facteur commun avec {m}, "
            f"la matrice n'a donc pas d'inverse modulo {m}.")
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
        raise ValueError("Saisis les nombres de la matrice, ex. 3 3 2 5")
    n = round(len(nums) ** 0.5)
    if n * n != len(nums):
        raise ValueError(
            "La clé doit former une matrice carrée (4 nombres → 2×2, 9 → 3×3).")
    return [nums[i * n:(i + 1) * n] for i in range(n)]


def validate_matrix(matrix):
    """Check a matrix coming from the UI grid: square and made of integers."""
    if not matrix or not all(isinstance(row, list) for row in matrix):
        raise ValueError("La matrice est vide.")
    n = len(matrix)
    if any(len(row) != n for row in matrix):
        raise ValueError("La matrice doit être carrée (autant de lignes que de colonnes).")
    for row in matrix:
        for v in row:
            if not isinstance(v, int):
                raise ValueError("La matrice ne doit contenir que des nombres entiers.")
    return matrix


def hill_weak_key(matrix):
    try:
        matrix_mod_inverse(matrix)
    except ValueError as e:
        return f"{e} Tu peux chiffrer, mais PAS déchiffrer."
    n = len(matrix)
    identity = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    if matrix == identity:
        return ("Matrice identité : le message ressortirait identique, il ne "
                "serait pas chiffré.")
    off_diagonal_zero = all(matrix[i][j] == 0
                            for i in range(n) for j in range(n) if i != j)
    if off_diagonal_zero:
        return ("Matrice diagonale : chaque lettre serait chiffrée seule, ce qui "
                "revient à une substitution monoalphabétique très faible.")
    if _is_permutation_matrix(matrix):
        return ("Matrice de permutation : les lettres du message sont seulement "
                "déplacées dans chaque bloc, pas remplacées. On reconnaît tout de "
                "suite les mêmes lettres dans un autre ordre.")
    return None


def _is_permutation_matrix(matrix):
    """Un seul 1 par ligne et par colonne, des 0 partout ailleurs (modulo 26)."""
    m = [[v % 26 for v in row] for row in matrix]
    n = len(m)
    for rows in (m, [list(col) for col in zip(*m)]):
        for row in rows:
            if sorted(row) != [0] * (n - 1) + [1]:
                return False
    return True


# -------------------------------- mise en forme : espaces & bourrage (X) ------
# Les trois algorithmes ne travaillent que sur des lettres. Pour que le message
# chiffré sorte « en un seul morceau » (sans espaces) ET que le déchiffrement
# retrouve les espaces, on range à côté du bloc chiffré deux métadonnées :
#   - layout  : les non-lettres (espaces, ponctuation...) et leur position ;
#   - fillers : les positions des lettres AJOUTÉES par l'algo (les X de Playfair
#               et de Hill), pour pouvoir les retirer au déchiffrement ;
#   - cases   : les positions des lettres écrites en MINUSCULES. On chiffre en
#               majuscules (les algos ne changent pas) et on remet les minuscules
#               aux mêmes positions au déchiffrement.
# César n'ajoute rien : fillers y est toujours vide.

def split_layout(message):
    """(lettres, layout). lettres = uniquement les caractères alphabétiques ;
    layout = [[index_dans_l_original, caractère], ...] pour chaque non-lettre."""
    letters, layout = [], []
    for i, ch in enumerate(message):
        if ch.isalpha():
            letters.append(ch)
        else:
            layout.append([i, ch])
    return "".join(letters), layout


def merge_layout(letters, layout):
    """Réinsère les non-lettres à leurs positions d'origine (layout dans l'ordre)."""
    chars = list(letters)
    for item in layout:
        i, ch = item[0], item[1]
        chars.insert(i if i <= len(chars) else len(chars), ch)
    return "".join(chars)


def strip_fillers(letters, fillers):
    """Retire les lettres ajoutées par l'algo (X de Playfair/Hill), repérées par
    leur position dans le flux de lettres."""
    drop = set(fillers or [])
    return "".join(c for i, c in enumerate(letters) if i not in drop)


def hill_fillers(letter_count, n):
    """Positions des X de bourrage ajoutés par Hill (fin du dernier bloc)."""
    padded = letter_count
    while padded % n != 0:
        padded += 1
    return list(range(letter_count, padded))


def playfair_fillers(clean):
    """Positions, dans le flux de lettres, des X insérés par Playfair (entre deux
    lettres identiques ou pour compléter un digramme final). Reproduit exactement
    la logique de _playfair_digrams, mais ne note que les positions."""
    fillers = []
    i = 0
    pair = 0
    while i < len(clean):
        b = clean[i + 1] if i + 1 < len(clean) else None
        if b is None or clean[i] == b:
            fillers.append(2 * pair + 1)
            i += 1
        else:
            i += 2
        pair += 1
    return fillers


def playfair_jmap(letters):
    """Positions des lettres J d'origine dans le flux de lettres. Playfair fusionne
    J avec I (ils partagent une case) ; on mémorise où étaient les J pour pouvoir
    les restituer au déchiffrement — exactement comme le layout pour les espaces."""
    return [i for i, ch in enumerate(letters) if ch.upper() == "J"]


def lower_positions(letters):
    """Positions (dans le flux de lettres) des minuscules a-z : la « casse » à mémoriser."""
    return [i for i, ch in enumerate(letters) if "a" <= ch <= "z"]


def to_upper(letters):
    """Passe les lettres a-z en majuscules, une pour une (la longueur ne change jamais,
    donc les positions mémorisées restent valables)."""
    return "".join(ch.upper() if "a" <= ch <= "z" else ch for ch in letters)


def restore_case(letters, cases):
    """Inverse de to_upper : remet en minuscules les lettres aux positions mémorisées
    (cases). À appliquer après strip_fillers et restore_j, avant merge_layout."""
    if not cases:
        return letters
    chars = list(letters)
    for i in cases:
        if 0 <= i < len(chars) and "A" <= chars[i] <= "Z":
            chars[i] = chars[i].lower()
    return "".join(chars)


def restore_j(letters, jmap):
    """Inverse de la fusion J→I : reconvertit en J les I situés aux positions
    mémorisées (jmap). Les positions sont celles du flux de lettres SANS les X
    ajoutés, donc à appliquer après strip_fillers et avant merge_layout."""
    if not jmap:
        return letters
    chars = list(letters)
    for i in jmap:
        if 0 <= i < len(chars) and chars[i].upper() == "I":
            chars[i] = "J"
    return "".join(chars)
