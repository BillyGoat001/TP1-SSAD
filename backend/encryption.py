"""
Partie 2 — Chiffrements : César, Playfair, Hill.

Logique pure des chiffrements (aucune interface, aucun web). C'est le code
Python d'origine de la version Tkinter, gardé tel quel pour que l'équipe lise les
algorithmes à un seul endroit. Le backend web importe ces fonctions ; les
animations sont construites par-dessus dans traces.py.
"""

CAESAR_ALPHABET = 26


# Decale une lettre de `shift` positions dans l'alphabet (en respectant la
# casse) ; renvoie les non-lettres inchangees.
def _shift_char(ch, shift):
    if ch.isupper():
        base = ord("A")
    elif ch.islower():
        base = ord("a")
    else:
        return ch
    return chr((ord(ch) - base + shift) % CAESAR_ALPHABET + base)


# Chiffre un texte par Cesar ; `direction="left"` inverse le sens du decalage.
def caesar_encrypt(text, shift, direction="right"):
    if direction == "left":
        shift = -shift
    return "".join(_shift_char(c, shift) for c in text)


# Dechiffre un Cesar : chiffre dans la direction opposee.
def caesar_decrypt(text, shift, direction="right"):
    return caesar_encrypt(text, shift, "left" if direction == "right" else "right")


# Message d'avertissement si la cle de Cesar est faible (decalage nul ou ROT13),
# None sinon.
def caesar_weak_key(shift):
    if shift % CAESAR_ALPHABET == 0:
        return ("Décalage nul (clé = 0 ou un multiple de 26) : le message "
                "ressortirait identique, il ne serait pas chiffré.")
    if shift % CAESAR_ALPHABET == 13:
        return ("La clé 13 (ROT13) est faible : l'appliquer deux fois redonne "
                "le message d'origine, et c'est une convention très connue.")
    return None


PLAYFAIR_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # alphabet sans J


# Construit la grille 5x5 de Playfair a partir de la cle (I et J partagent une case).
def _playfair_matrix(key):
    key = key.upper().replace("J", "I")
    seen = []
    for ch in key + PLAYFAIR_ALPHABET:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


# Avertit si la cle laisse la grille de l'alphabet (cle vide ou debut d'alphabet,
# J comptant pour I), None sinon.
def playfair_weak_key(key):
    grid = "".join("".join(row) for row in _playfair_matrix(key))
    if grid == PLAYFAIR_ALPHABET:
        return ("Cette clé laisse la grille de l'alphabet (A B C D E / F G H I K…) : "
                "c'est la première grille qu'un attaquant essaie. Sur une même ligne, "
                "une lettre est simplement décalée d'une place, comme un César de clé 1.")
    return None


# Position (ligne, colonne) d'une lettre dans la grille ; leve ValueError si absente.
def _playfair_pos(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c
    raise ValueError(f"La lettre « {ch} » n'existe pas dans la grille.")


# Ne garde que les lettres (en majuscules) et fusionne J en I.
def _playfair_clean(text):
    return "".join(c for c in text.upper() if c.isalpha()).replace("J", "I")


# Decoupe le texte en digrammes, en inserant un bourrage (X, ou Q apres un X)
# entre deux lettres identiques ou pour completer un digramme final.
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


# Chiffre un texte par Playfair (meme ligne -> +1 colonne, meme colonne -> +1
# ligne, sinon echange des colonnes du rectangle).
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


# Dechiffre un Playfair (regles inverses du chiffrement : -1 colonne / -1 ligne).
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


MOD = 26


# Algorithme d'Euclide etendu : renvoie (pgcd, x, y) tel que a*x + b*y = pgcd.
def _egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


# Inverse modulaire de a modulo m (None s'il n'existe pas).
def _mod_inverse(a, m=MOD):
    g, x, _ = _egcd(a % m, m)
    return None if g != 1 else x % m


# Mineur de la matrice : la supprime de sa ligne i et de sa colonne j.
def _minor(mat, i, j):
    return [row[:j] + row[j + 1:] for k, row in enumerate(mat) if k != i]


# Determinant d'une matrice carree, par developpement recursif de Laplace.
def _determinant(mat):
    n = len(mat)
    if n == 1:
        return mat[0][0]
    if n == 2:
        return mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]
    return sum((-1) ** j * mat[0][j] * _determinant(_minor(mat, 0, j))
               for j in range(n))


# Inverse d'une matrice modulo m (via comatrice et inverse du determinant). Leve
# ValueError si le determinant n'est pas inversible modulo m (cle indechiffrable).
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


# Ne garde que les lettres (en majuscules).
def _hill_clean(text):
    return "".join(c for c in text.upper() if c.isalpha())


# Applique la matrice de Hill au texte, bloc par bloc (produit matrice-vecteur mod 26).
def _hill_apply(mat, text):
    n = len(mat)
    nums = [ord(c) - ord("A") for c in text]
    out = []
    for i in range(0, len(nums), n):
        block = nums[i:i + n]
        for row in mat:
            out.append(sum(row[k] * block[k] for k in range(n)) % MOD)
    return "".join(chr(v + ord("A")) for v in out)


# Chiffre un texte par Hill (complete le dernier bloc avec des X si besoin).
def hill_encrypt(text, key_matrix):
    text = _hill_clean(text)
    n = len(key_matrix)
    while len(text) % n != 0:
        text += "X"
    return _hill_apply(key_matrix, text)


# Dechiffre un Hill en appliquant l'inverse modulaire de la matrice cle.
def hill_decrypt(text, key_matrix):
    inverse = matrix_mod_inverse(key_matrix, MOD)
    return _hill_apply(inverse, _hill_clean(text))


# Transforme une saisie '3 3 2 5' (ou '3,3;2,5') en matrice carree [[3,3],[2,5]].
def parse_matrix(s):
    nums = [int(x) for x in s.replace(",", " ").replace(";", " ").split()]
    if not nums:
        raise ValueError("Saisis les nombres de la matrice, ex. 3 3 2 5")
    n = round(len(nums) ** 0.5)
    if n * n != len(nums):
        raise ValueError(
            "La clé doit former une matrice carrée (4 nombres → 2×2, 9 → 3×3).")
    return [nums[i * n:(i + 1) * n] for i in range(n)]


# Verifie une matrice venue de la grille de l'UI : carree et faite d'entiers.
def validate_matrix(matrix):
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


# Message d'avertissement si la cle de Hill est faible (non inversible, identite,
# diagonale ou permutation), None sinon.
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


# Vrai si la matrice est une permutation : un seul 1 par ligne et par colonne,
# des 0 partout ailleurs (modulo 26).
def _is_permutation_matrix(matrix):
    m = [[v % 26 for v in row] for row in matrix]
    n = len(m)
    for rows in (m, [list(col) for col in zip(*m)]):
        for row in rows:
            if sorted(row) != [0] * (n - 1) + [1]:
                return False
    return True


# -------------------------------- mise en forme : espaces & bourrage (X) ------
# Les trois algorithmes ne travaillent que sur des lettres. Pour que le message
# chiffre sorte « en un seul morceau » (sans espaces) ET que le dechiffrement
# retrouve les espaces, on range a cote du bloc chiffre trois metadonnees :
#   - layout  : les non-lettres (espaces, ponctuation...) et leur position ;
#   - fillers : les positions des lettres AJOUTEES par l'algo (les X de Playfair
#               et de Hill), pour pouvoir les retirer au dechiffrement ;
#   - cases   : les positions des lettres ecrites en MINUSCULES.
# Cesar n'ajoute rien : fillers y est toujours vide.


# Separe le message en (lettres, layout) : lettres = caracteres alphabetiques
# seuls ; layout = [[index_dans_l_original, caractere], ...] pour chaque non-lettre.
def split_layout(message):
    letters, layout = [], []
    for i, ch in enumerate(message):
        if ch.isalpha():
            letters.append(ch)
        else:
            layout.append([i, ch])
    return "".join(letters), layout


# Reinsere les non-lettres a leurs positions d'origine (layout dans l'ordre).
def merge_layout(letters, layout):
    chars = list(letters)
    for item in layout:
        i, ch = item[0], item[1]
        chars.insert(i if i <= len(chars) else len(chars), ch)
    return "".join(chars)


# Retire les lettres ajoutees par l'algo (X de Playfair/Hill), reperees par leur
# position dans le flux de lettres.
def strip_fillers(letters, fillers):
    drop = set(fillers or [])
    return "".join(c for i, c in enumerate(letters) if i not in drop)


# Positions des X de bourrage ajoutes par Hill (fin du dernier bloc).
def hill_fillers(letter_count, n):
    padded = letter_count
    while padded % n != 0:
        padded += 1
    return list(range(letter_count, padded))


# Positions, dans le flux de lettres, des X inseres par Playfair. Reproduit
# exactement la logique de _playfair_digrams, mais ne note que les positions.
def playfair_fillers(clean):
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


# Positions des lettres J d'origine dans le flux de lettres : Playfair fusionne J
# avec I, on memorise ou etaient les J pour les restituer au dechiffrement.
def playfair_jmap(letters):
    return [i for i, ch in enumerate(letters) if ch.upper() == "J"]


# Positions (dans le flux de lettres) des minuscules a-z : la « casse » a memoriser.
def lower_positions(letters):
    return [i for i, ch in enumerate(letters) if "a" <= ch <= "z"]


# Passe les lettres a-z en majuscules une pour une (la longueur ne change jamais,
# donc les positions memorisees restent valables).
def to_upper(letters):
    return "".join(ch.upper() if "a" <= ch <= "z" else ch for ch in letters)


# Inverse de to_upper : remet en minuscules les lettres aux positions memorisees
# (cases). A appliquer apres strip_fillers et restore_j, avant merge_layout.
def restore_case(letters, cases):
    if not cases:
        return letters
    chars = list(letters)
    for i in cases:
        if 0 <= i < len(chars) and "A" <= chars[i] <= "Z":
            chars[i] = chars[i].lower()
    return "".join(chars)


# Inverse de la fusion J->I : reconvertit en J les I situes aux positions
# memorisees (jmap, dans le flux de lettres sans les X). A appliquer apres
# strip_fillers et avant merge_layout.
def restore_j(letters, jmap):
    if not jmap:
        return letters
    chars = list(letters)
    for i in jmap:
        if 0 <= i < len(chars) and chars[i].upper() == "I":
            chars[i] = "J"
    return "".join(chars)
