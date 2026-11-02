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
import secrets

import auth   # réutilise le chiffrement « César/Playfair/Hill » des mots de passe
import encryption as en


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


# ---------------------------------------------------- canal A -> B réel ----
# Au-delà de la démo ci-dessus (où on tape soi-même le message "reçu"), le
# panneau Intégrité fait maintenant vraiment chiffrer le message (César,
# Playfair ou Hill : au hasard par défaut, ou celui que A choisit), et c'est le
# CHIFFRÉ qui "voyage" — avec l'algorithme, la clé et l'étiquette : tout ce paquet
# est visible sur le canal, un attaquant C peut le lire et altérer le chiffré avant
# qu'il arrive chez B.
#
# L'étiquette HMAC est calculée sur ce qui VOYAGE réellement, c'est-à-dire le
# CHIFFRÉ (chiffrer-puis-signer) et non sur le clair. Pourquoi : signée sur le clair,
# une altération du chiffré qui ne change pas le clair retrouvé par B passe inaperçue
# (ex. Playfair ignore une lettre ajoutée en fin de chiffré, et efface les lettres de
# bourrage ; B retombe sur le même clair, donc la même étiquette : « intact » à tort).
# Signée sur le chiffré, le moindre caractère modifié change l'étiquette (effet
# d'avalanche), quel que soit l'algorithme. Sans chiffrement, le « chiffré » est le
# message lui-même : rien ne change. Chiffrer protège la confidentialité, l'étiquette
# protège l'intégrité -- deux choses différentes, c'est le point pédagogique de cette partie.

def custom_key(method, key_in):
    """La clé que A a choisie pour `method`, au format de auth.encipher, ou None si A n'en a
    pas donné (la clé est alors tirée au hasard). `key_in` : {"shift": int} (César),
    {"key": "LETTRES"} (Playfair) ou {"matrix": [[...]]} (Hill). Lève ValueError (message en
    français) si la clé ne convient pas."""
    key_in = key_in or {}
    if method == "caesar":
        if key_in.get("shift") is None:
            return None
        return {"shift": int(key_in["shift"])}
    if method == "playfair":
        letters = "".join(c for c in (key_in.get("key") or "").upper() if "A" <= c <= "Z")
        return {"key": letters} if letters else None
    if method == "hill":
        if not key_in.get("matrix"):
            return None
        matrix = en.validate_matrix(key_in["matrix"])
        if len(matrix) > 5:
            raise ValueError("La matrice Hill ne peut pas dépasser 5×5.")
        try:
            en.matrix_mod_inverse(matrix)
        except ValueError:
            raise ValueError("Cette matrice n'est pas inversible modulo 26 : B ne pourrait pas déchiffrer. Choisis-en une autre.")
        return {"matrix": matrix}
    return None


def seal(hmac_key, message, encrypt=True, method=None, key_in=None):
    """Côté A : chiffrement (optionnel), PUIS étiquette HMAC sur ce qui voyage.
    L'algorithme est tiré au hasard (comme pour un mot de passe) sauf si A en
    impose un avec `method` (« caesar », « playfair » ou « hill »). La clé est tirée au
    hasard, sauf si A donne la sienne avec `key_in` (voir custom_key). `record` contient
    tout ce qu'il faut pour déchiffrer (voir auth.encipher) ; son champ `secret` est ce
    qui "voyage" -- c'est lui que C peut modifier, et c'est lui que l'étiquette protège.
    `warning` : avertissement du cours si la clé choisie par A est faible (sinon None).

    `encrypt=False` : le message voyage EN CLAIR (record["method"] = None,
    secret = message) -- pour montrer que l'étiquette protège l'intégrité
    indépendamment du chiffrement (les deux sont des choses différentes)."""
    if method is not None and method not in auth.METHODS:
        raise ValueError("méthode inconnue")
    warning = None
    if not encrypt:
        record = {"method": None, "key": {}, "secret": message,
                  "layout": [], "fillers": [], "jmap": [], "cases": []}
    else:
        method = method or secrets.choice(auth.METHODS)
        key = custom_key(method, key_in) or auth.random_key(method)
        record = auth.encipher(message, method, key)
        if custom_key(method, key_in):
            warning = (en.caesar_weak_key(key["shift"]) if method == "caesar"
                       else en.playfair_weak_key(key["key"]) if method == "playfair"
                       else en.hill_weak_key(key["matrix"]))
    return {"tag": sign(hmac_key, record["secret"]), "record": record, "warning": warning}


def tag_change(sent, recomputed):
    """De combien l'étiquette recalculée par B s'éloigne de celle envoyée par A.

    Les deux étiquettes sont des empreintes SHA-256 (64 caractères hexadécimaux = 256
    bits). On compte les bits qui diffèrent (distance de Hamming) : `changeRate` en est
    la part, en %. 0 % = étiquettes identiques (message intact). Dès que le message
    change, ne serait-ce que d'un seul caractère, SHA-256 fait basculer environ la
    moitié des bits (effet d'avalanche) : le taux tourne donc autour de 50 %, et c'est
    justement ce qui rend toute altération flagrante.

    Renvoie des None quand il n'y a rien à comparer (protection désactivée, chiffré
    illisible, étiquette absente ou mal formée)."""
    none = {"changeRate": None, "bitsChanged": None, "bitsTotal": None,
            "charsChanged": None, "charsTotal": None}
    try:
        if not sent or not recomputed or len(sent) != len(recomputed):
            return none
        a, b = bytes.fromhex(sent), bytes.fromhex(recomputed)
    except (TypeError, ValueError):
        return none
    bits_total = len(a) * 8
    bits = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    chars = sum(1 for x, y in zip(sent.lower(), recomputed.lower()) if x != y)
    return {"changeRate": round(100 * bits / bits_total, 1), "bitsChanged": bits, "bitsTotal": bits_total,
            "charsChanged": chars, "charsTotal": len(sent)}


def open_channel(hmac_key, record, protect, tag):
    """Côté B : déchiffre ce qui est arrivé (potentiellement altéré par C dans
    `record["secret"]`), et si la protection est active, recalcule l'étiquette
    sur ce qui est ARRIVÉ (le chiffré reçu, avant tout déchiffrement) et la
    compare à celle de A.

    `protect=False` : B affiche ce qu'il a déchiffré SANS AUCUNE vérification
    -- c'est la faille qu'on démontre : un chiffré altéré est quand même
    affiché comme "reçu", silencieusement.
    `protect=True`  : B recalcule l'étiquette et la compare ; toute altération
    du chiffré (donc du clair obtenu après déchiffrement) fait diverger les
    deux étiquettes, quel que soit le caractère changé."""
    received = record.get("secret", "")
    try:
        if record.get("method") is None:
            decrypted, broken = received, False       # voyageait en clair : rien à déchiffrer
        else:
            decrypted, broken = auth.decipher(record), False
    except Exception:
        # chiffré altéré au point de ne même plus pouvoir se déchiffrer
        # proprement (ex. Hill : longueur qui n'est plus un multiple du bloc)
        decrypted, broken = None, True

    if not protect:
        return {"decrypted": decrypted, "valid": None, "recomputed": None, "broken": broken, **tag_change(None, None)}

    # B vérifie l'étiquette sur le chiffré tel qu'il l'a reçu : même un chiffré devenu
    # illisible est donc détecté (étiquettes différentes), avec son taux de changement.
    recomputed = sign(hmac_key, received)
    valid = hmac.compare_digest(recomputed, tag or "")
    return {"decrypted": decrypted, "valid": valid, "recomputed": recomputed, "broken": broken,
            **tag_change(tag, recomputed)}
