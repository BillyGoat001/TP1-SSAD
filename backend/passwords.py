# -*- coding: utf-8 -*-
"""
Partie 3 — Mots de passe : attaques et protection.

TOUT repose sur une seule formule :

        temps de craquage  =  espace de recherche  /  vitesse de l'attaquant

Trois cas cible de l'énoncé :
  - "binaire"   : 3 caractères dans {0,1}        -> 2^3 = 8
  - "numerique" : 4 caractères dans {1,2,3,4}     -> 4^4 = 256
  - "complexe"  : a-z A-Z 0-9 symboles, longueur choisie par l'utilisateur (0..64)

Deux vraies attaques :
  - force brute : on parcourt les combinaisons dans l'ordre jusqu'à la cible.
    Pour les petits espaces (binaire, numérique) la boucle tourne réellement ;
    pour l'espace complexe (3×10^15), aucune machine ne peut tout parcourir, donc
    on calcule DIRECTEMENT le rang de la cible (le numéro d'essai auquel on
    tomberait dessus) — c'est exact, et c'est ce rang qui pilote la progression.
  - dictionnaire : on lit un vrai dictionnaire de fuites (rockyou, ~14,3 M de
    mots réels, mots français courants en tête) mot par mot jusqu'à la cible.

Une seule protection ralentit l'attaquant ici : LIMITER LE NOMBRE DE TENTATIVES
(verrouillage du compte). Sur le mot de passe complexe s'ajoute une POLITIQUE
(classes de caractères exigées, longueur minimale) : si le mot de passe ne la
respecte pas, il est refusé avant même l'attaque.

Uniquement la bibliothèque standard de Python : toute l'équipe peut lire et
lancer ce fichier sans rien installer.
"""

import gzip
import itertools
import math
import os
import string

# -- classes de caractères (cas complexe + politique) ------------------------
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
SMALL_CASES = ("binaire", "numerique")        # espace imposé, pas de politique

# -- hypothèse sur l'attaquant (affichée dans l'interface) --------------------
# 10 milliards d'essais/s : un GPU sur un hachage rapide. Ordre de grandeur.
FAST_RATE = 1e10

# Au-delà de cette taille d'espace, la boucle réelle figerait : on calcule le
# rang de la cible au lieu de parcourir. En dessous, on parcourt pour de vrai.
LIVE_LOOP_MAX = 5_000_000

# Vrai dictionnaire d'attaque : un dossier de plusieurs fichiers (certains très
# gros), lus mot par mot sans jamais tout charger en mémoire.
#   dictionnaires/
#     general_part1.txt.gz, general_part2.txt.gz, general_part3.txt.gz   (toujours en premier)
#     langues/<nom>.txt                                                   (ensuite, voir _dict_order)
_DICT_DIR = os.path.join(os.path.dirname(__file__), "dictionnaires")
_GENERAL_PARTS = ["general_part1.txt.gz", "general_part2.txt.gz", "general_part3.txt.gz"]
_LANG_FILES = {
    "francais": "francais.txt", "anglais": "anglais.txt", "allemand": "allemand.txt",
    "italien": "italien.txt", "espagnol": "espagnol.txt", "neerlandais": "neerlandais.txt",
    "polonais": "polonais.txt", "chinois_pinyin": "chinois_pinyin.txt",
    "arabe_arabizi": "arabe_arabizi.txt", "portugais": "portugais.txt", "turc": "turc.txt",
}
# ordre des langues "restantes", une fois celle de l'interface et son complément
# (français/anglais) déjà passées — du plus fourni au plus thin
_LANG_REST_ORDER = ["allemand", "espagnol", "neerlandais", "polonais",
                     "chinois_pinyin", "portugais", "turc", "arabe_arabizi", "italien"]

# Repli si le dossier dictionnaires/ n'a pas encore été déposé (ancien fichier unique)
_WORDLIST_GZ = os.path.join(os.path.dirname(__file__), "wordlist.txt.gz")
_WORDLIST_TXT = os.path.join(os.path.dirname(__file__), "wordlist.txt")
_FALLBACK = ["azerty", "motdepasse", "soleil", "123456", "password", "qwerty",
             "bonjour", "coucou", "doudou", "iloveyou", "admin", "sunshine"]

# Complément ajouté à la main (ex. les PIN à 4 chiffres absents d'un dictionnaire de
# fuites réelles — personne n'a jamais utilisé "3134" comme mot de passe en ligne,
# mais un vrai attaquant teste quand même tout l'espace numérique en premier avant
# le dictionnaire). Toujours lu EN DERNIER : les positions des mots déjà présents
# ailleurs (dictionary_size(), les rangs #N des tests) ne bougent jamais.
_EXTRA_FILE = os.path.join(os.path.dirname(__file__), "dictionnaire_extra.txt")


def _extra_words():
    if not os.path.exists(_EXTRA_FILE):
        return
    with open(_EXTRA_FILE, "rt", encoding="utf-8") as f:
        for line in f:
            w = line.rstrip("\n")
            if w:
                yield w

_dict_size = None          # taille du dictionnaire, comptée une seule fois


def _dict_order(lang="fr"):
    """Ordre de lecture : d'abord le général (mots de passe les plus communs,
    toutes langues), puis la langue de l'interface, puis l'autre de
    français/anglais, puis le reste des langues (le total lu est toujours le
    même quelle que soit `lang` : seul l'ORDRE change, pas l'ensemble)."""
    first_lang = "francais" if lang == "fr" else "anglais"
    second_lang = "anglais" if lang == "fr" else "francais"
    rest = [n for n in _LANG_REST_ORDER if n not in (first_lang, second_lang)]
    return [first_lang, second_lang] + rest


def _dict_paths(lang="fr"):
    """Liste ordonnée des fichiers à lire, avec leur encodage ('utf-8' pour le
    dossier dictionnaires/, 'latin-1' pour l'ancien wordlist.txt(.gz) en repli).
    Renvoie [] si même le repli est absent (dictionnaire minimal codé en dur,
    voir _FALLBACK, géré à part car il n'est pas dans un fichier)."""
    if os.path.isdir(_DICT_DIR):
        paths = [os.path.join(_DICT_DIR, p) for p in _GENERAL_PARTS]
        paths += [os.path.join(_DICT_DIR, "langues", _LANG_FILES[n]) for n in _dict_order(lang)]
        return [(p, "utf-8") for p in paths if os.path.exists(p)]
    if os.path.exists(_WORDLIST_GZ):
        return [(_WORDLIST_GZ, "latin-1")]
    if os.path.exists(_WORDLIST_TXT):
        return [(_WORDLIST_TXT, "latin-1")]
    return []


def _iter_words(lang="fr"):
    """Parcourt tout le dictionnaire mot par mot, sans jamais tout charger en
    mémoire. `lang` ('fr' ou 'en') ne change que l'ORDRE de lecture (les mots
    de la langue de l'interface arrivent plus tôt), pas le total parcouru.
    Le complément (_extra_words) est toujours ajouté EN DERNIER, fichier
    principal présent ou non : les positions déjà testées ne changent jamais."""
    paths = _dict_paths(lang)
    if not paths:
        for w in _FALLBACK:
            yield w
        yield from _extra_words()
        return
    for path, enc in paths:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding=enc, errors="replace", newline="\n") as f:
            for line in f:
                w = line.rstrip("\n")
                if w:
                    yield w
    yield from _extra_words()


def dictionary_size():
    """Nombre de mots du dictionnaire (compté une fois, puis mémorisé) — le
    même quel que soit `lang`, seul l'ordre de lecture en dépend."""
    global _dict_size
    if _dict_size is None:
        _dict_size = sum(1 for _ in _iter_words())
    return _dict_size


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


# ---- mise en forme française -------------------------------------------------
NBSP = " "


def _round2(x):
    """x arrondi à 2 chiffres significatifs : 1234 -> 1200 ; 0,0333 -> 0,033."""
    return float(f"{x:.2g}")


def _num(x):
    """Nombre à la française : 1.2 -> '1,2' ; 15.0 -> '15' ; 45000 -> '45 000'."""
    if x == int(x):
        return f"{int(x):,}".replace(",", NBSP)
    return f"{x:g}".replace(".", ",")


def _plural(n):
    return "s" if n >= 2 else ""


def fmt_count(n):
    """Nombre de combinaisons lisible : groupé si petit, sinon notation
    scientifique française (3,4 × 10^15)."""
    if n < 1_000_000_000:
        return f"{n:,}".replace(",", NBSP)
    s = str(int(n))
    exp = len(s) - 1
    return f"{s[0]},{s[1:3]} × 10^{exp}"


def fmt_rate(r):
    """Vitesse d'un attaquant : 1e10 -> '10 milliards d'essais/s'."""
    if r >= 1e9:
        n = _round2(r / 1e9)
        return f"{_num(n)} milliard{_plural(n)} d'essais/s"
    if r >= 1e6:
        n = _round2(r / 1e6)
        return f"{_num(n)} million{_plural(n)} d'essais/s"
    n = _round2(r)
    return f"{_num(n)} essai{_plural(n)}/s"


YEAR = 31_536_000.0                  # secondes dans une année


def human_time(seconds, compact=False):
    """(libellé français, catégorie de force) pour une durée en secondes.

    UNE SEULE échelle pour tout le site : les phrases complètes et les libellés
    courts du tableau (compact=True) sortent d'ici, avec les mêmes seuils.
    Catégories : instant / faible / moyen / fort / inviolable."""
    s = seconds
    if s is None or s == float("inf"):
        return "10^100+ ans", "inviolable"
    if s < 1e-3:
        return "instantané", "instant"
    if s < 1:
        return ("< 1 s" if compact else "moins d'une seconde"), "instant"
    if s < 60:
        return f"{s:.0f} s", "faible"
    if s < 3600:
        return f"{s / 60:.0f} min", "faible"
    if s < 86400:
        return f"{s / 3600:.0f} h", "moyen"
    if s < 2_592_000:               # < 30 jours
        n = round(s / 86400)
        return (f"{n} j" if compact else (f"{n} jour" if n == 1 else f"{n} jours")), "moyen"
    if s < YEAR:
        return f"{s / 2_592_000:.0f} mois", "moyen"
    y = s / YEAR
    # années -> siècles -> millénaires -> puissances de 10. Pas de « milliards
    # d'années » ni de plafond « > Univers » : au-delà, on passe en 10^k ans.
    if y < 100:
        n = round(y)
        return ("1 an" if n == 1 else f"{_num(n)} ans"), "fort"
    if y < 1000:
        c = round(y / 100)
        return (f"{c} siècle" if c == 1 else f"{c} siècles"), "fort"
    if y < 1_000_000:
        m = round(y / 1000)
        return (f"{m} millénaire" if m == 1 else f"{m} millénaires"), "inviolable"
    k = int(math.floor(math.log10(y)))
    return f"10^{k} ans", "inviolable"


def estimate_for(alphabet_size, length, rate=FAST_RATE):
    """Estimation { espace, bits, temps } pour un alphabet et une longueur."""
    space = int(alphabet_size) ** int(length)
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
        "bits": round(math.log2(space), 1) if space > 1 else 0.0,
        "seconds": None if seconds == float("inf") else seconds,
        "human": human,
        "strength": strength,
        "rate": rate,
    }


# ------------------------------------------------------- tableau des durées ----
TABLE_LENGTHS = [4, 6, 8, 10, 12, 16]
TABLE_ALPHABETS = [                      # (nom, détail, taille de l'alphabet)
    ("Chiffres", "0-9", 10),
    ("Minuscules", "a-z", 26),
    ("+ Majusc.", "a-z A-Z", 52),
    ("+ Chiffres", "a-z A-Z 0-9", 62),
    ("+ Symboles", "complet", len(FULL_CHARSET)),
]


def speed_table(rate=FAST_RATE):
    """Durée pour épuiser l'espace, selon la longueur et le type de caractères.
    Mêmes seuils et mêmes mots que le reste du site."""
    rows = []
    for length in TABLE_LENGTHS:
        cells = []
        for _name, _detail, size in TABLE_ALPHABETS:
            human, strength = human_time((size ** length) / rate, compact=True)
            cells.append({"human": human, "strength": strength})
        rows.append({"length": length, "cells": cells})
    return {
        "columns": [{"name": n, "detail": d, "size": z} for n, d, z in TABLE_ALPHABETS],
        "rows": rows,
        "rate": rate,
        "rateText": fmt_rate(rate),
    }


# ------------------------------------------------------- politique (complexe) ----
def classes_present(password):
    """Ensemble des classes de caractères présentes dans le mot de passe."""
    present = set()
    for ch in password:
        if ch in LOWER:
            present.add("lower")
        elif ch in UPPER:
            present.add("upper")
        elif ch in DIGITS:
            present.add("digit")
        elif ch in SYMBOLS:
            present.add("symbol")
        else:
            present.add("other")          # hors du jeu autorisé
    return present


def detected_charset(target):
    """Jeu de caractères RÉELLEMENT utilisé par le mot de passe (cas complexe).
    Un mot de passe en minuscules seules donne 'a-z' (26), pas le jeu complet :
    la force brute n'a pas à supposer des symboles qui ne sont pas là."""
    present = classes_present(target) - {"other"}
    parts = []
    if "lower" in present:
        parts.append(LOWER)
    if "upper" in present:
        parts.append(UPPER)
    if "digit" in present:
        parts.append(DIGITS)
    if "symbol" in present:
        parts.append(SYMBOLS)
    return "".join(parts)


_CLASS_LABEL = {"lower": "une minuscule", "upper": "une majuscule",
                "digit": "un chiffre", "symbol": "un symbole"}


def validate(target, case, length=None, rules=None):
    """Le mot de passe est-il valide pour ce cas / cette politique ?
    Renvoie { valid, reasons: [...] } ; `reasons` liste ce qui manque."""
    charset, fixed_len, _label = _resolve_case(case, length)
    reasons = []

    if case in SMALL_CASES:
        extra = set(target) - set(charset)
        if extra:
            reasons.append(f"caractères non autorisés : {' '.join(sorted(extra))}")
        if len(target) != fixed_len:
            reasons.append(f"il faut exactement {fixed_len} caractères")
        return {"valid": not reasons, "reasons": reasons}

    # --- cas complexe : jeu autorisé + politique optionnelle ---
    r = rules or {}
    present = classes_present(target)
    if "other" in present:
        reasons.append("caractères hors du jeu autorisé")
    if len(target) == 0:
        reasons.append("mot de passe vide")
    for key, flag in (("lower", "require_lower"), ("upper", "require_upper"),
                      ("digit", "require_digit"), ("symbol", "require_symbol")):
        if r.get(flag) and key not in present:
            reasons.append(f"il manque {_CLASS_LABEL[key]}")
    min_len = r.get("min_length")
    if min_len and len(target) < int(min_len):
        reasons.append(f"longueur minimale : {int(min_len)} (actuelle : {len(target)})")
    return {"valid": not reasons, "reasons": reasons}


# -------------------------------------------------------------- force brute ----
def rank_of(target, charset, length):
    """Numéro d'essai (1-based) auquel la force brute, parcourant les
    combinaisons dans l'ordre, tomberait sur la cible. None si la cible n'est
    pas une combinaison valide de ce charset / cette longueur."""
    if len(target) != length:
        return None
    base = len(charset)
    idx = {c: i for i, c in enumerate(charset)}
    r = 0
    for ch in target:
        if ch not in idx:
            return None
        r = r * base + idx[ch]
    return r + 1


def brute_force(target, case, length=None, limit=None, rules=None, know_composition=True):
    """Prépare la force brute : valide la cible, donne l'espace, l'estimation
    pire-cas, et le rang exact de la cible (le front anime la progression).

    `limit` : si une limite de tentatives est active, l'attaque s'arrête à ce
    nombre d'essais ; craqué seulement si le rang y est inférieur ou égal.
    `know_composition` : si vrai (et cas complexe), l'attaquant connaît les
    classes réellement présentes et restreint son jeu de caractères ; sinon il
    suppose le pire cas (jeu complet)."""
    charset, length, label = _resolve_case(case, length)
    check = validate(target, case, length, rules)

    # cas complexe : l'attaquant qui CONNAÎT la composition restreint son jeu de
    # caractères (minuscules seules -> 26, pas 86). Sinon il garde le jeu complet.
    if case == "complexe" and know_composition:
        detected = detected_charset(target)
        if detected:
            charset = detected

    space = keyspace(charset, length)
    est = estimate_for(len(charset), length, FAST_RATE)

    really_looped = False
    if not check["valid"]:
        rank = None
    elif space <= LIVE_LOOP_MAX:
        # petit espace : on parcourt POUR DE VRAI jusqu'à la cible
        really_looped = True
        rank = None
        attempts = 0
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            if "".join(combo) == target:
                rank = attempts
                break
    else:
        # espace astronomique : la boucle figerait, on calcule le rang exact
        rank = rank_of(target, charset, length)

    cracked = rank is not None and (limit is None or rank <= int(limit))

    # temps pour ATTEINDRE la cible (au rang trouvé), à la vitesse de référence
    if rank is not None:
        find_seconds = rank / FAST_RATE
        find_human, find_strength = human_time(find_seconds)
    else:
        find_seconds, find_human, find_strength = None, None, None

    return {
        "valid": check["valid"],
        "reasons": check["reasons"],
        "charset": charset,
        "charsetSize": len(charset),
        "length": length,
        "label": label,
        "keyspace": float(space) if space < 1e300 else None,
        "keyspaceText": fmt_count(space),
        "rate": FAST_RATE,
        "rateText": fmt_rate(FAST_RATE),
        "worstCaseSeconds": est["seconds"],
        "worstCaseHuman": est["human"],
        "strength": est["strength"],
        "rank": rank,                         # essais pour atteindre la cible
        "findSeconds": find_seconds,
        "findHuman": find_human,              # temps pour atteindre la cible
        "findStrength": find_strength,
        "reallyLooped": really_looped,        # True = boucle réelle, pas un calcul
        "limit": int(limit) if limit is not None else None,
        "cracked": cracked,
    }


# -------------------------------------------------------------- dictionnaire ----
def dictionary_attack(target, limit=None, lang="fr"):
    """Lit le dictionnaire mot par mot jusqu'à la cible (ou la limite de
    tentatives). Renvoie la position trouvée et la taille totale."""
    size = dictionary_size()
    pos = 0
    for w in _iter_words(lang):
        pos += 1
        if limit is not None and pos > int(limit):
            return {"found": False, "stopped": True, "position": None,
                    "scanned": pos - 1, "size": size, "limit": int(limit)}
        if w == target:
            return {"found": True, "stopped": False, "password": target,
                    "position": pos, "scanned": pos, "size": size,
                    "limit": int(limit) if limit is not None else None}
    return {"found": False, "stopped": False, "position": None,
            "scanned": size, "size": size,
            "limit": int(limit) if limit is not None else None}


# ------------------------------------------------------------- hypothèses ----
def assumptions():
    return {
        "fastRate": FAST_RATE,
        "fastRateText": fmt_rate(FAST_RATE),
        "liveLoopMax": LIVE_LOOP_MAX,
    }
