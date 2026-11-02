"""
Partie 2 — Échange de clés avec RSA (implémentation complète, sans bibliothèque).

Le problème : B doit savoir avec quel algorithme (César, Playfair, Hill) et quelle
clé A a chiffré son message, sans que l'espion qui écoute le canal l'apprenne.

La solution (chiffrement hybride) : chaque utilisateur possède une paire de clés
RSA. A enferme le « mode d'emploi » du message (algo + clé) avec la clé PUBLIQUE
de B ; seul B, avec sa clé PRIVÉE, peut l'ouvrir. Le message lui-même est chiffré
avec l'algorithme symétrique choisi (encryption.py).

Génération d'une paire de clés :
  1. deux grands nombres premiers p et q (test de primalité de Miller-Rabin) ;
  2. n = p·q                        → le module, public ;
  3. φ(n) = (p − 1)(q − 1)          → l'indicatrice d'Euler, secrète ;
  4. e = 65537, premier avec φ(n)   → clé publique (e, n) ;
  5. d = e⁻¹ mod φ(n)               → clé privée (d, n), par Euclide étendu.

Chiffrer : c = m^e mod n          Déchiffrer : m = c^d mod n

Le texte est d'abord transformé en nombres : on le découpe en blocs d'octets assez
petits pour que chaque bloc m soit strictement inférieur à n.

Remarque : c'est le RSA « de manuel », sans remplissage. En pratique on ajoute un
remplissage aléatoire (OAEP) pour qu'un même message ne donne jamais le même
chiffré ; on l'omet ici pour que chaque calcul reste lisible.
"""

import math
import secrets
import time

import encryption as en

PUBLIC_EXPONENT = 65537
KEY_SIZES = (32, 64, 128, 256, 512, 1024, 2048)
DEFAULT_BITS = 1024

# Petits nombres premiers : un premier filtre très rapide avant Miller-Rabin.
_SMALL_PRIMES = [p for p in range(3, 2000, 2)
                 if all(p % k for k in range(3, int(p ** 0.5) + 1, 2))]


# Test de primalité de Miller-Rabin : faux pour un composé, vrai pour un premier
# (erreur possible <= 4^-rounds, négligeable avec 40 témoins). Un filtre par les
# petits premiers élimine d'abord la plupart des composés sans calcul coûteux.
def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # n − 1 = d · 2^s avec d impair
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2          # témoin aléatoire dans [2, n − 2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False                           # a prouve que n est composé
    return True


# Nombre premier aléatoire d'exactement `bits` bits. Les deux bits de poids fort
# sont forcés à 1 pour que le produit n = p·q ait pile 2×bits bits.
def random_prime(bits):
    top = (1 << (bits - 1)) | (1 << (bits - 2))
    while True:
        candidate = secrets.randbits(bits) | top | 1   # impair, bonne taille
        if is_probable_prime(candidate):
            return candidate


# Algorithme d'Euclide étendu : renvoie (g, x, y) avec a·x + b·y = g = pgcd(a, b).
def egcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


# Inverse de a modulo m (existe seulement si pgcd(a, m) = 1).
def mod_inverse(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} n'a pas d'inverse modulo {m}.")
    return x % m


# Génère une paire de clés RSA de `bits` bits. Renvoie tous les nombres (p, q, φ
# et d restent secrets : seuls e et n sont publics). Rejette un tirage où e n'est
# pas premier avec φ(n).
def generate_keypair(bits=DEFAULT_BITS):
    if bits not in KEY_SIZES:
        raise ValueError(f"Taille de clé non prise en charge ({bits} bits).")
    start = time.perf_counter()
    half = bits // 2
    while True:
        p = random_prime(half)
        q = random_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(PUBLIC_EXPONENT, phi) != 1:
            continue
        n = p * q
        d = mod_inverse(PUBLIC_EXPONENT, phi)
        break
    return {
        "bits": n.bit_length(),
        "p": p, "q": q, "n": n, "phi": phi,
        "e": PUBLIC_EXPONENT, "d": d,
        "ms": round((time.perf_counter() - start) * 1000, 1),
    }


# Octets par bloc : assez peu pour que chaque bloc m vérifie m < n.
def block_size(n):
    return (n.bit_length() - 1) // 8


# Chiffre un texte avec la clé publique (e, n) : c = m^e mod n pour chaque bloc.
def encrypt_text(text, e, n):
    data = text.encode("utf-8")
    k = block_size(n)
    if k < 1:
        raise ValueError("Clé trop petite pour chiffrer un texte.")
    blocks = []
    for i in range(0, len(data), k):
        chunk = data[i:i + k]
        m = int.from_bytes(chunk, "big")
        blocks.append({"text": chunk.decode("utf-8", errors="replace"), "m": m, "c": pow(m, e, n)})
    return {"blockBytes": k, "blocks": blocks}


# Déchiffre avec la clé privée (d, n) : m = c^d mod n pour chaque bloc, puis
# rassemble les octets en texte (erreur si ce n'est pas la bonne clé privée).
def decrypt_blocks(cipher_blocks, d, n):
    blocks, data = [], b""
    for c in cipher_blocks:
        if not 0 <= c < n:
            raise ValueError("Un bloc chiffré est hors de l'intervalle [0, n).")
        m = pow(c, d, n)
        chunk = m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")
        data += chunk
        blocks.append({"c": c, "m": m, "text": chunk.decode("utf-8", errors="replace")})
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Coffre illisible : ce n'est pas la bonne clé privée.")
    return {"blocks": blocks, "text": text}


# Écrit l'algo et sa clé sous forme de texte compact, prêt à être chiffré par RSA.
# Pour Hill, vérifie que la matrice est inversible mod 26 (sinon B ne pourrait pas
# déchiffrer).
def params_to_text(algo, shift=None, direction="right", key=None, matrix=None):
    if algo == "caesar":
        if shift is None or shift < 0:
            raise ValueError("Le décalage César doit être un entier positif.")
        if direction not in ("right", "left"):
            raise ValueError("Direction César inconnue.")
        return f"caesar|{shift}|{direction}"
    if algo == "playfair":
        letters = "".join(c for c in (key or "").upper() if "A" <= c <= "Z")
        if not letters:
            raise ValueError("La clé Playfair doit contenir au moins une lettre.")
        return f"playfair|{letters}"
    if algo == "hill":
        m = en.validate_matrix(matrix)
        try:
            en.matrix_mod_inverse(m)
        except ValueError:
            raise ValueError("Matrice non inversible modulo 26 : le destinataire ne "
                             "pourrait pas déchiffrer. Choisis une autre matrice.")
        return f"hill|{len(m)}|" + ",".join(str(v) for row in m for v in row)
    raise ValueError(f"Algorithme inconnu « {algo} ».")


# Relit le mode d'emploi sorti du coffre : {algo, shift/direction | key | matrix}.
# Lève une erreur si le texte est illisible (mauvaise clé privée).
def text_to_params(text):
    try:
        parts = text.split("|")
        if parts[0] == "caesar" and len(parts) == 3 and parts[2] in ("right", "left"):
            return {"algo": "caesar", "shift": int(parts[1]), "direction": parts[2]}
        if parts[0] == "playfair" and len(parts) == 2 and parts[1].isalpha():
            return {"algo": "playfair", "key": parts[1]}
        if parts[0] == "hill" and len(parts) == 3:
            size = int(parts[1])
            nums = [int(x) for x in parts[2].split(",")]
            if size >= 2 and size * size == len(nums):
                return {"algo": "hill", "matrix": [nums[i * size:(i + 1) * size] for i in range(size)]}
    except ValueError:
        pass
    raise ValueError("Mode d'emploi illisible : le coffre n'a pas été ouvert avec la bonne clé privée.")


# Convertit en entier un grand nombre reçu en texte (JSON ne garde pas leur précision).
def parse_int(value, name):
    value = str(value).strip()
    if not value.isdigit():
        raise ValueError(f"Valeur invalide pour {name}.")
    return int(value)
