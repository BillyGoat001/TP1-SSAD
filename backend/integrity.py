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

import auth   # réutilise le chiffrement « César/Playfair/Hill tiré au hasard » des mots de passe


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
# Playfair ou Hill tirés au hasard, EXACTEMENT comme auth.make_record() pour
# les mots de passe), et c'est le CHIFFRÉ qui "voyage" — un attaquant C peut
# l'altérer avant qu'il arrive chez B. L'étiquette HMAC, elle, est calculée
# sur le CLAIR, avant chiffrement (signer-puis-chiffrer) : chiffrer protège la
# confidentialité, l'étiquette protège l'intégrité -- ce sont deux choses
# différentes, c'est tout le point pédagogique de cette partie.

def seal(hmac_key, message, encrypt=True):
    """Côté A : étiquette HMAC sur le clair, PUIS chiffrement (optionnel) avec
    un algo et une clé tirés au hasard (comme pour un mot de passe). `record`
    contient tout ce qu'il faut pour déchiffrer (voir auth.encipher) ; son
    champ `secret` est ce qui "voyage" -- c'est lui que C peut modifier.

    `encrypt=False` : le message voyage EN CLAIR (record["method"] = None,
    secret = message) -- pour montrer que l'étiquette protège l'intégrité
    indépendamment du chiffrement (les deux sont des choses différentes)."""
    tag = sign(hmac_key, message)
    if not encrypt:
        record = {"method": None, "key": {}, "secret": message,
                  "layout": [], "fillers": [], "jmap": [], "cases": []}
        return {"tag": tag, "record": record}
    method = secrets.choice(auth.METHODS)
    record = auth.encipher(message, method, auth.random_key(method))
    return {"tag": tag, "record": record}


def open_channel(hmac_key, record, protect, tag):
    """Côté B : déchiffre ce qui est arrivé (potentiellement altéré par C dans
    `record["secret"]`), et si la protection est active, vérifie l'étiquette
    sur le texte déchiffré.

    `protect=False` : B affiche ce qu'il a déchiffré SANS AUCUNE vérification
    -- c'est la faille qu'on démontre : un chiffré altéré est quand même
    affiché comme "reçu", silencieusement.
    `protect=True`  : B recalcule l'étiquette et la compare ; toute altération
    du chiffré (donc du clair obtenu après déchiffrement) fait diverger les
    deux étiquettes, quel que soit le caractère changé."""
    try:
        if record.get("method") is None:
            decrypted = record.get("secret", "")   # voyageait en clair : rien à déchiffrer
        else:
            decrypted = auth.decipher(record)
    except Exception:
        # chiffré altéré au point de ne même plus pouvoir se déchiffrer
        # proprement (ex. Hill : longueur qui n'est plus un multiple du bloc)
        return {"decrypted": None, "valid": None, "recomputed": None, "broken": True}

    if not protect:
        return {"decrypted": decrypted, "valid": None, "recomputed": None, "broken": False}

    recomputed = sign(hmac_key, decrypted)
    valid = hmac.compare_digest(recomputed, tag or "")
    return {"decrypted": decrypted, "valid": valid, "recomputed": recomputed, "broken": False}
