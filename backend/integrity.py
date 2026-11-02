import hashlib
import hmac
import secrets

import auth


# Calcule l'etiquette HMAC-SHA256 (en hexa) d'un message sous une cle partagee.
def sign(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


# Recalcule l'etiquette et la compare en temps constant avec celle recue.
def verify(key, message, tag):
    expected = sign(key, message)
    return hmac.compare_digest(expected, tag)


# Demonstration A -> (canal) -> B ou le message « recu » est saisi a la main :
# `original` est ce que A a envoye, `received` ce que B a obtenu.
def demo(key, original, received):
    tag = sign(key, original)
    recomputed = sign(key, received)
    return {
        "tag": tag,
        "recomputed": recomputed,
        "tampered": original != received,
        "valid": hmac.compare_digest(tag, recomputed),
    }


# Cote A : etiquette HMAC sur le CLAIR, puis chiffrement (signer-puis-chiffrer)
# avec un algo et une cle tires au hasard. Le champ `record["secret"]` est ce qui
# voyage, donc ce qu'un attaquant peut modifier. `encrypt=False` envoie le
# message en clair, pour montrer que l'etiquette protege l'integrite
# independamment de la confidentialite.
def seal(hmac_key, message, encrypt=True):
    tag = sign(hmac_key, message)
    if not encrypt:
        record = {"method": None, "key": {}, "secret": message,
                  "layout": [], "fillers": [], "jmap": [], "cases": []}
        return {"tag": tag, "record": record}
    method = secrets.choice(auth.METHODS)
    record = auth.encipher(message, method, auth.random_key(method))
    return {"tag": tag, "record": record}


# Cote B : dechiffre ce qui est arrive (potentiellement altere) et, si `protect`
# est actif, recalcule l'etiquette sur le clair obtenu pour la comparer.
# `protect=False` affiche le dechiffre sans aucune verification : c'est la faille
# demontree. `broken=True` signale un chiffre altere au point d'etre
# indechiffrable (ex. Hill : longueur plus multiple du bloc).
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
