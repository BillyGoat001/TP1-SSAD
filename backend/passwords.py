# -*- coding: utf-8 -*-
"""
Partie 3 — Mots de passe : attaques et protection.

TOUT repose sur une seule formule :

        temps de craquage  =  espace de recherche  /  vitesse de l'attaquant

et chaque protection déplace l'un des deux termes :
  - une POLITIQUE (classes de caractères exigées, longueur minimale) agrandit
    l'espace que l'attaquant doit forcément parcourir ;
  - la LIMITE DE TENTATIVES (verrouillage) et le HACHAGE LENT (PBKDF2) font
    chuter la vitesse de l'attaquant.

Trois cas cible de l'énoncé :
  - "binaire"   : 3 caractères dans {0,1}        -> 2^3 = 8
  - "numerique" : 4 caractères dans {1,2,3,4}     -> 4^4 = 256
  - "complexe"  : a-z A-Z 0-9 symboles, longueur choisie par l'utilisateur (0..64)

Uniquement la bibliothèque standard de Python : toute l'équipe peut lire et
lancer ce fichier sans rien installer.
"""

import hashlib
import hmac
import itertools
import math
import os
import secrets
import string
import time

# -- classes de caractères (cas complexe + protections) ----------------------
LOWER = string.ascii_lowercase                 # 26
UPPER = string.ascii_uppercase                 # 26
DIGITS = string.digits                         # 10
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"            # 24, sûrs à saisir/générer
FULL_CHARSET = LOWER + UPPER + DIGITS + SYMBOLS

CLASS_SIZES = {
    "lower": len(LOWER),
    "upper": len(UPPER),
    "digit": len(DIGITS),
    "symbol": len(SYMBOLS),
}

CASES = {
    "binaire":   {"charset": "01",         "length": 3, "label": "3 caractères dans {0,1}"},
    "numerique": {"charset": "1234",       "length": 4, "label": "4 caractères dans {1,2,3,4}"},
    "complexe":  {"charset": FULL_CHARSET, "length": 8, "label": "a-z  A-Z  0-9  symboles"},
}

# -- hypothèses sur l'attaquant (affichées dans l'interface, ajustables) ------
FAST_RATE = 1e10          # 10 milliards d'essais/s : un GPU sur un hash rapide
SLOW_HASH_RATE = 6.5      # ~1 essai / 155 ms : PBKDF2 salé (cf. hash_password)
LOCKOUT_ATTEMPTS = 10     # 10 essais autorisés...
LOCKOUT_WINDOW = 300.0    # ...par tranche de 5 min, puis le compte se verrouille
LOCKOUT_RATE = LOCKOUT_ATTEMPTS / LOCKOUT_WINDOW   # ~0,033 essai/s

# plafond : la démonstration de force brute « en direct » ne doit jamais figer
MAX_ATTEMPTS = 1_000_000

# Vrai dictionnaire d'attaque : mots de passe réels issus de fuites (listes
# publiques NCSC 100k + rockyou + 10k-most-common), mots français courants
# placés en tête. Chargé une seule fois depuis wordlist.txt, à côté de ce
# fichier. C'est une VRAIE attaque par dictionnaire, pas une simulation.
_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "wordlist.txt")
_FALLBACK = ["azerty", "motdepasse", "soleil", "123456", "password", "qwerty",
             "bonjour", "coucou", "doudou", "iloveyou", "admin", "sunshine"]


def _load_wordlist():
    try:
        with open(_WORDLIST_PATH, encoding="utf-8") as f:
            words = [w.rstrip("\n") for w in f if w.strip()]
        return words if words else list(_FALLBACK)
    except OSError:
        return list(_FALLBACK)


DEFAULT_DICTIONARY = _load_wordlist()


# ---------------------------------------------------------------- helpers ----
def keyspace(charset, length):
    return len(charset) ** length


def _resolve_case(case, length=None):
    """(charset, longueur, libellé) d'un cas ; la longueur n'est modifiable que
    pour le cas « complexe », et bornée à 0..64."""
    if case not in CASES:
        raise ValueError(f"Cas inconnu « {case} ». Utilise : {', '.join(CASES)}.")
    cfg = CASES[case]
    chosen = length if (case == "complexe" and length is not None) else cfg["length"]
    chosen = max(0, min(64, int(chosen)))
    return cfg["charset"], chosen, cfg["label"]


def _grp(x):
    """Entier arrondi, groupé à la française : 12345 -> '12 345'."""
    return f"{int(round(x)):,}".replace(",", " ")


def fmt_count(n):
    """Nombre de combinaisons lisible : groupé si petit, sinon notation
    scientifique française (3,4 × 10^15)."""
    if n < 1_000_000_000:
        return f"{n:,}".replace(",", " ")
    s = str(int(n))
    exp = len(s) - 1
    return f"{s[0]},{s[1:3]} × 10^{exp}"


YEAR = 31_536_000.0  # secondes dans une année


def human_time(seconds):
    """(libellé français, catégorie de force) pour une durée en secondes.
    Catégories : instant / faible / moyen / fort / inviolable."""
    s = seconds
    if s is None or s == float("inf"):
        return "des milliards d'années", "inviolable"
    if s < 1e-3:
        return "instantané", "instant"
    if s < 1:
        return "moins d'une seconde", "instant"
    if s < 60:
        return f"{s:.0f} s", "faible"
    if s < 3600:
        return f"{s/60:.0f} min", "faible"
    if s < 86400:
        return f"{s/3600:.0f} h", "moyen"
    if s < 2_592_000:               # < 30 jours
        n = round(s / 86400)
        return (f"{n} jour" if n == 1 else f"{n} jours"), "moyen"
    if s < YEAR:
        return f"{s/2_592_000:.0f} mois", "moyen"
    if s < 1000 * YEAR:
        n = round(s / YEAR)
        return (f"{n} an" if n == 1 else f"{_grp(n)} ans"), "fort"
    if s < 1e6 * YEAR:
        return "des siècles", "fort"
    if s < 1e9 * YEAR:
        return "des millions d'années", "inviolable"
    return "des milliards d'années", "inviolable"


def estimate_for(alphabet_size, length, rate):
    """Estimation { espace, vitesse, temps } pour un alphabet et une longueur."""
    space = int(alphabet_size) ** int(length)      # entier exact (gros possible)
    try:
        seconds = space / rate
    except OverflowError:
        seconds = float("inf")
    human, strength = human_time(seconds)
    return {
        "alphabet": int(alphabet_size),
        "length": int(length),
        "keyspace": float(space) if space < 1e300 else None,
        "keyspaceText": fmt_count(space),
        "seconds": None if seconds == float("inf") else seconds,
        "human": human,
        "strength": strength,
        "rate": rate,
    }


# ------------------------------------------------------- analyse de force ----
def _classes_present(password):
    present = set()
    for ch in password:
        if ch in LOWER:
            present.add("lower")
        elif ch in UPPER:
            present.add("upper")
        elif ch in DIGITS:
            present.add("digit")
        else:
            present.add("symbol")
    return present


def _alphabet_size(classes):
    size = sum(CLASS_SIZES.get(c, len(SYMBOLS)) for c in classes)
    return max(1, size)


def _ratio_badge(ratio):
    """(texte, sens) comparant le temps protégé au temps non protégé.
    sens ∈ {longer, shorter, equal}."""
    if ratio == float("inf"):
        return "× 10^18+ plus long", "longer"
    if ratio != ratio:  # NaN (inf / inf)
        return "temps identique", "equal"
    if ratio > 1.5:
        txt = f"× {ratio:.0f}" if ratio < 1000 else f"× 10^{int(math.log10(ratio))}"
        return txt + " plus long", "longer"
    if 0 < ratio < 0.67:
        m = 1.0 / ratio
        txt = f"÷ {m:.0f}" if m < 1000 else f"÷ 10^{int(math.log10(m))}"
        return txt + " plus court", "shorter"
    if ratio == 0:
        return "÷ 10^18+ plus court", "shorter"
    return "temps identique", "equal"


def analyze(password, protections=None):
    """Compare le temps de craquage SANS protection et AVEC les protections
    activées (politique + verrouillage + hachage lent)."""
    p = protections or {}

    # --- sans protection : le mot de passe tel quel, attaquant rapide ---
    classes0 = _classes_present(password) or {"lower"}
    a0 = _alphabet_size(classes0)
    l0 = max(1, len(password))
    unprotected = estimate_for(a0, l0, FAST_RATE)

    # --- avec protection : la politique impose un jeu de caractères et une
    #     longueur minimale ; verrouillage / hachage lent réduisent la vitesse.
    #     Le jeu de caractères protégé = EXACTEMENT les classes activées : en
    #     retirer une réduit l'espace (donc rend l'attaque PLUS rapide).
    required = set()
    if p.get("require_lower"):
        required.add("lower")
    if p.get("require_upper"):
        required.add("upper")
    if p.get("require_digit"):
        required.add("digit")
    if p.get("require_symbol"):
        required.add("symbol")
    a1 = _alphabet_size(required)            # aucune classe -> 1 -> instantané

    min_len = p.get("min_length")
    l1 = max(l0, int(min_len)) if min_len else l0
    l1 = min(64, l1)

    rate1 = FAST_RATE
    notes = []
    if p.get("slow_hash"):
        rate1 = min(rate1, SLOW_HASH_RATE)
        notes.append("hachage lent")
    if p.get("limit_attempts"):
        rate1 = min(rate1, LOCKOUT_RATE)
        notes.append("tentatives limitées")

    protected = estimate_for(a1, l1, rate1)
    protected["rateNotes"] = notes

    us = unprotected["seconds"]
    ps = protected["seconds"]
    us = float("inf") if us is None else (us if us > 0 else 1e-12)
    ps = float("inf") if ps is None else ps
    ratio = float("inf") if (ps == float("inf") and us != float("inf")) else ps / us
    factor_text, direction = _ratio_badge(ratio)

    return {
        "unprotected": unprotected,
        "protected": protected,
        "factorText": factor_text,
        "direction": direction,
    }


# -------------------------------------------------------------- attaques ----
def brute_force(target, case, length=None):
    """Essaie toutes les combinaisons du charset du cas jusqu'à trouver la
    cible (plafonnée à MAX_ATTEMPTS). Renvoie aussi l'ESTIMATION réaliste :
    c'est elle le vrai verdict, pas le temps de notre petite boucle."""
    charset, length, label = _resolve_case(case, length)
    space = keyspace(charset, length)
    est = estimate_for(len(charset), length, FAST_RATE)

    start = time.perf_counter()
    attempts = 0
    found = False
    stopped = False
    if length == 0:
        found = (target == "")
    else:
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            if "".join(combo) == target:
                found = True
                break
            if attempts >= MAX_ATTEMPTS:
                stopped = True
                break
    return {
        "found": found,
        "stopped": stopped,
        "password": target if found else None,
        "attempts": attempts,
        "seconds": time.perf_counter() - start,
        "keyspace": float(space) if space < 1e300 else None,
        "keyspaceText": fmt_count(space),
        "charsetSize": len(charset),
        "length": length,
        "label": label,
        "estimate": est,
    }


def dictionary_attack(target, words=None):
    """Essaie chaque mot de la liste (anglais + français) jusqu'à la cible."""
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


# ------------------------------------------------------------ protection ----
def hash_password(password, iterations=200_000):
    """Protection concrète : hachage lent et salé. On ne stocke jamais le mot
    de passe en clair, seulement cette empreinte."""
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
