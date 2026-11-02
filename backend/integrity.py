import hashlib
import hmac
import secrets

import auth


# Calcule l'étiquette HMAC-SHA256 (en hexa) d'un message sous une clé partagée.
def sign(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


# Recalcule l'étiquette et la compare en temps constant avec celle reçue.
def verify(key, message, tag):
    expected = sign(key, message)
    return hmac.compare_digest(expected, tag)


# Démonstration A -> (canal) -> B où le message « reçu » est saisi à la main :
# `original` est ce que A a envoyé, `received` ce que B a obtenu.
def demo(key, original, received):
    tag = sign(key, original)
    recomputed = sign(key, received)
    return {
        "tag": tag,
        "recomputed": recomputed,
        "tampered": original != received,
        "valid": hmac.compare_digest(tag, recomputed),
    }


# Côté A : étiquette HMAC sur le CLAIR, puis chiffrement (signer-puis-chiffrer)
# avec un algo et une clé tirés au hasard. Le champ `record["secret"]` est ce qui
# voyage, donc ce qu'un attaquant peut modifier. `encrypt=False` envoie le
# message en clair, pour montrer que l'étiquette protège l'intégrité
# indépendamment de la confidentialité.
def seal(hmac_key, message, encrypt=True):
    tag = sign(hmac_key, message)
    if not encrypt:
        record = {"method": None, "key": {}, "secret": message,
                  "layout": [], "fillers": [], "jmap": [], "cases": []}
        return {"tag": tag, "record": record}
    method = secrets.choice(auth.METHODS)
    record = auth.encipher(message, method, auth.random_key(method))
    return {"tag": tag, "record": record}


# Côté B : déchiffre ce qui est arrivé (potentiellement altéré) et, si `protect`
# est actif, recalcule l'étiquette sur le clair obtenu pour la comparer.
# `protect=False` affiche le déchiffré sans aucune vérification : c'est la faille
# démontrée. `broken=True` signale un chiffré altéré au point d'être
# indéchiffrable (ex. Hill : longueur plus multiple du bloc).
def open_channel(hmac_key, record, protect, tag):
    try:
        if record.get("method") is None:
            decrypted = record.get("secret", "")
        else:
            decrypted = auth.decipher(record)
    except Exception:
        return {"decrypted": None, "valid": None, "recomputed": None, "broken": True}

    if not protect:
        return {"decrypted": decrypted, "valid": None, "recomputed": None, "broken": False}

    recomputed = sign(hmac_key, decrypted)
    valid = hmac.compare_digest(recomputed, tag or "")
    return {"decrypted": decrypted, "valid": valid, "recomputed": recomputed, "broken": False}
