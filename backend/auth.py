# -*- coding: utf-8 -*-
"""
Connexion : comptes, mots de passe chiffrés, sessions, limitation des tentatives.

Les comptes sont rangés dans une base SQLite (db.py). Le mot de passe n'est jamais stocké
en clair NI haché : la règle du TP est de n'utiliser que les trois chiffrements codés dans
encryption.py. À chaque inscription, le serveur tire au hasard César, Playfair ou Hill, une
clé aléatoire, et range le mot de passe chiffré avec l'algorithme et la clé (voir plus bas
les limites de ce choix).

La session est un jeton signé (HMAC-SHA256) rangé dans un cookie HttpOnly : le JavaScript
de la page ne peut pas le lire, et toute modification le rend invalide.

Blocage : après 4 mots de passe erronés de suite DEPUIS LA MÊME IP, ce couple (compte, IP)
est bloqué (table `login_attempts` de la base) jusqu'à  python make_user.py nom --unlock
(débloque toutes les IP de ce compte à la fois). Une autre IP n'est pas affectée : c'est
voulu (sinon un attaquant pourrait bloquer le vrai propriétaire du compte depuis n'importe
où, sans jamais connaître son mot de passe — un déni de service par simple devinette).

Créer ou changer un compte à la main :  python make_user.py nom

Variables utiles : SECRET_KEY (clé de signature des sessions ; sinon tirée au hasard à
chaque démarrage, ce qui déconnecte tout le monde au redémarrage), USERS_DB (emplacement
de la base), TP_AUTH_OFF=1 (DÉVELOPPEMENT UNIQUEMENT : désactive la connexion).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import db
import encryption as en

SESSION_SECONDS = 12 * 3600
COOKIE = "tp_session"
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,40}$")

_lock = threading.RLock()
_SECRET = (os.environ.get("SECRET_KEY") or "").encode() or secrets.token_bytes(32)
_revoked: Dict[str, float] = {}          # signatures de sessions fermees → expiration


# ----------------------------------------------- mots de passe (chiffres) ----
# Regle du TP : aucune fonction de hachage pour les mots de passe, seulement les trois
# chiffrements codes dans encryption.py. A chaque inscription, le serveur tire AU HASARD
# l'un des trois (Cesar, Playfair ou Hill) et une cle, chiffre le mot de passe, puis range
# dans la base : le mot de passe chiffre, l'algorithme et sa cle (voir db.py).
#
# Limite assumee : un chiffrement se defait avec sa cle, et la cle est rangee a cote du
# secret. Quiconque lit la base peut donc retrouver les mots de passe (un hachage, lui,
# ne se defait pas). De plus, comme les algorithmes ne traitent que les lettres, les
# chiffres et les symboles ne sont pas chiffres : ils restent dans le « layout ».
METHODS = ("caesar", "playfair", "hill")
MAX_ATTEMPTS = 4                         # mots de passe errones de suite avant le blocage du compte
PASSWORD_MIN = 8
PASSWORD_MAX = 64
_PLAYFAIR_LETTERS = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
_SYMBOLS = set(string.punctuation)


def random_key(method: str) -> Dict[str, Any]:
    """Une clé aléatoire valable (et non « faible » au sens des avertissements du cours)."""
    if method == "caesar":
        while True:
            shift = 1 + secrets.randbelow(25)
            if en.caesar_weak_key(shift) is None:
                return {"shift": shift}
    if method == "playfair":
        while True:
            pool, picked = list(_PLAYFAIR_LETTERS), []
            for _ in range(6 + secrets.randbelow(5)):
                picked.append(pool.pop(secrets.randbelow(len(pool))))
            key = "".join(picked)
            if en.playfair_weak_key(key) is None:
                return {"key": key}
    n = 2 + secrets.randbelow(2)                                    # matrice 2×2 ou 3×3
    while True:
        m = [[secrets.randbelow(26) for _ in range(n)] for _ in range(n)]
        if en.hill_weak_key(m) is None:                            # inversible mod 26, ni identite, ni diagonale…
            return {"matrix": m}


def encipher(password: str, method: str, key: Dict[str, Any]) -> Dict[str, Any]:
    """Chiffre `password` avec l'algorithme et la clé donnés. Même mise en forme que la page
    « Chiffrer un message » : lettres en majuscules, non-lettres rangées dans `layout`."""
    letters, layout = en.split_layout(password)
    cases = en.lower_positions(letters)
    text = en.to_upper(letters)
    fillers: List[int] = []
    jmap: List[int] = []
    if method == "caesar":
        secret = en.caesar_encrypt(text, key["shift"])
    elif method == "playfair":
        secret = en.playfair_encrypt(text, key["key"])
        fillers = en.playfair_fillers(en._playfair_clean(text))
        jmap = en.playfair_jmap(text)
    elif method == "hill":
        secret = en.hill_encrypt(text, key["matrix"])
        fillers = en.hill_fillers(len(en._hill_clean(text)), len(key["matrix"]))
    else:
        raise ValueError("méthode inconnue")
    return {"method": method, "key": key, "secret": secret, "layout": layout,
            "fillers": fillers, "jmap": jmap, "cases": cases}


def decipher(record: Dict[str, Any]) -> str:
    """Retrouve le mot de passe d'un compte (le chiffrement est réversible, contrairement
    à un hachage). Sert aux tests et à la démonstration, pas à la connexion."""
    method, key, text = record["method"], record["key"], record["secret"]
    if method == "caesar":
        result = en.caesar_decrypt(text, key["shift"])
    elif method == "playfair":
        result = en.playfair_decrypt(text, key["key"])
    else:
        result = en.hill_decrypt(text, key["matrix"])
    cleaned = en.strip_fillers(result, record["fillers"])
    cleaned = en.restore_j(cleaned, record["jmap"])
    cleaned = en.restore_case(cleaned, record["cases"])
    return en.merge_layout(cleaned, record["layout"])


def make_record(password: str) -> Dict[str, Any]:
    """Un nouvel enregistrement : algorithme et clé tirés au hasard (un autre tirage pour
    chaque mot de passe)."""
    method = secrets.choice(METHODS)
    return encipher(password, method, random_key(method))


def _fingerprint(rec: Dict[str, Any]) -> bytes:
    return json.dumps([rec["secret"], rec["layout"], rec["fillers"], rec["jmap"], rec["cases"]],
                      separators=(",", ":")).encode()


def verify_password(password: str, record: Dict[str, Any]) -> bool:
    """Chiffre le mot de passe proposé avec l'algorithme et la clé du compte, et compare au
    secret rangé (comparaison à temps constant)."""
    try:
        if not password.isascii():                       # les accents ne sont pas geres par Playfair/Hill
            return False
        mine = encipher(password, record["method"], record["key"])
    except (ValueError, KeyError, TypeError):
        return False
    return hmac.compare_digest(_fingerprint(mine), _fingerprint(record))


# Faux compte : si le nom n'existe pas, on chiffre et on compare quand meme, pour que la
# reponse prenne le meme temps (sinon le delai revelerait quels noms existent).
_DUMMY = encipher("x", "caesar", {"shift": 3})


def password_problem(password: str) -> Optional[str]:
    """Le premier défaut du mot de passe (message en français) ou None s'il convient :
    8 caractères au moins, une majuscule, une minuscule, un chiffre, un symbole ; ASCII
    visible uniquement (ni espace ni accent : Playfair et Hill ne traitent que A–Z)."""
    if not password or not all(33 <= ord(c) <= 126 for c in password):
        return "Le mot de passe ne doit contenir ni espace ni accent."
    if len(password) < PASSWORD_MIN:
        return f"Le mot de passe doit contenir au moins {PASSWORD_MIN} caractères."
    if len(password) > PASSWORD_MAX:
        return f"Le mot de passe ne peut pas dépasser {PASSWORD_MAX} caractères."
    if not any(c.isupper() for c in password):
        return "Le mot de passe doit contenir une majuscule."
    if not any(c.islower() for c in password):
        return "Le mot de passe doit contenir une minuscule."
    if not any(c.isdigit() for c in password):
        return "Le mot de passe doit contenir un chiffre."
    if not any(c in _SYMBOLS for c in password):
        return "Le mot de passe doit contenir un symbole (par ex. ! ? # @)."
    return None


# ------------------------------------------------------------------ comptes ----
USERNAME_MIN = 3


def auth_enabled() -> bool:
    return os.environ.get("TP_AUTH_OFF") != "1"


def has_users() -> bool:
    return db.count() > 0


def register(username: str, password: str) -> Tuple[Optional[str], Optional[str]]:
    """Inscription : (nom, None) si le compte est créé, sinon (None, code) avec code =
    'username' (nom invalide), 'policy' (mot de passe trop faible) ou 'exists' (nom pris)."""
    name = (username or "").strip()
    if not USERNAME_RE.match(name) or len(name) < USERNAME_MIN:
        return None, "username"
    if password_problem(password):
        return None, "policy"
    if not db.create_user(name, make_record(password)):
        return None, "exists"
    return name, None


def set_password(username: str, password: str) -> bool:
    """Crée le compte, ou change son mot de passe (et le débloque). Pour make_user.py : pas
    de règle de composition ici, seulement les caractères que les chiffrements acceptent."""
    name = username.strip()
    if not USERNAME_RE.match(name) or not password.isascii():
        raise ValueError("nom ou mot de passe non valide")
    rec = make_record(password)
    if db.replace_user(name, rec):
        return False
    db.create_user(name, rec)
    return True


# Blocage PAR COUPLE (compte, IP) : 4 echecs de suite depuis une IP bloquent cette IP sur
# CE compte, pas le compte entier — une autre IP (ex. le vrai proprietaire, chez lui)
# peut toujours essayer. Nombre fixe, pas d'attente progressive : a 4 echecs, bloque
# jusqu'a deblocage admin (make_user.py --unlock). Limite assumee : un attaquant qui
# change d'IP repart a zero sur ce compteur.
#
# Noms inconnus : on compte aussi leurs echecs (en memoire, par IP), pour que la reponse
# soit la meme que pour un vrai compte et ne revele pas si le nom existe.
_unknown: Dict[str, int] = {}


def _lc(username: str) -> str:
    return (username or "").strip().lower()


def _unk_key(ip: str, username: str) -> str:
    return f"{ip}|{_lc(username)}"


def is_blocked(username: str, ip: str) -> bool:
    """Ce compte est-il bloqué DEPUIS CETTE IP ?"""
    u = db.get_user(username)
    if u:
        return db.is_attempt_blocked(u["username"], ip)
    return _unknown.get(_unk_key(ip, username), 0) >= MAX_ATTEMPTS


def attempt_login(username: str, password: str, ip: str) -> Tuple[Optional[str], int]:
    """(nom, essais restants). nom = le compte si les identifiants sont bons, sinon None ;
    dans ce cas, les essais restants (pour CETTE IP sur ce compte) descendent de 4 à 0
    (0 = le couple compte/IP vient d'être bloqué)."""
    u = db.get_user(username)
    ok = verify_password(password or "", u or _DUMMY) and u is not None
    if ok:
        db.reset_attempt_failures(u["username"], ip)
        return u["username"], MAX_ATTEMPTS
    if u:
        fails = db.add_attempt_failure(u["username"], ip, MAX_ATTEMPTS)
    else:
        with _lock:
            key = _unk_key(ip, username)
            _unknown[key] = _unknown.get(key, 0) + 1
            fails = _unknown[key]
            if len(_unknown) > 5000:                    # garde-fou memoire
                for k in list(_unknown)[:1000]:
                    _unknown.pop(k, None)
    return None, max(0, MAX_ATTEMPTS - fails)


# ----------------------------------------------------------------- sessions ----
def _b64(s: bytes) -> str:
    return base64.urlsafe_b64encode(s).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload: str) -> str:
    return hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def make_token(user: str, now: Optional[float] = None, ttl: int = SESSION_SECONDS) -> str:
    exp = int((now if now is not None else time.time()) + ttl)
    payload = f"{_b64(user.encode())}.{exp}.{secrets.token_hex(6)}"      # le 3e morceau rend chaque jeton unique
    return f"{payload}.{_sign(payload)}"


def read_token(token: Optional[str], now: Optional[float] = None) -> Optional[str]:
    """Le nom du compte si le jeton est authentique, non expiré et non fermé."""
    if not token:
        return None
    try:
        user_b64, exp, jti, sig = token.split(".")
        payload = f"{user_b64}.{exp}.{jti}"
        if not hmac.compare_digest(_sign(payload), sig):
            return None
        t = now if now is not None else time.time()
        if int(exp) < t:
            return None
        with _lock:
            if sig in _revoked:
                return None
        user = _unb64(user_b64).decode()
        return user if db.get_user(user) is not None else None
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def revoke_token(token: Optional[str]) -> None:
    """Ferme une session côté serveur (le jeton ne marche plus, même s'il est copié)."""
    if not token:
        return
    try:
        _, exp, _, sig = token.split(".")
        with _lock:
            _revoked[sig] = float(exp)
            now = time.time()
            for k in [k for k, v in _revoked.items() if v < now]:
                del _revoked[k]
    except ValueError:
        pass


# ---------------------------------------------- limitation des tentatives ----
# Pas d'attente progressive ni de compte a rebours : le seul blocage qui existe
# est le blocage fixe par couple (compte, IP) ci-dessus (4 echecs -> bloque
# jusqu'a deblocage admin, voir is_blocked / attempt_login). Ce compteur-ci ne
# sert plus qu'a faire monter legerement la difficulte du CAPTCHA apres des
# echecs recents depuis une IP (voir recent_failures, appele par /api/auth/captcha).
_fails: Dict[str, List[float]] = {}
FAIL_WINDOW = 600


def _recent(key: str, now: float) -> List[float]:
    lst = [t for t in _fails.get(key, []) if now - t < FAIL_WINDOW]
    if lst:
        _fails[key] = lst
    else:
        _fails.pop(key, None)
    return lst


def recent_failures(key: str, now: Optional[float] = None) -> List[float]:
    now = now if now is not None else time.time()
    with _lock:
        return list(_recent(key, now))


def record_failure(key: str, now: Optional[float] = None) -> None:
    now = now if now is not None else time.time()
    with _lock:
        _recent(key, now)
        _fails.setdefault(key, []).append(now)
        if len(_fails) > 5000:                          # garde-fou memoire
            for k in list(_fails)[:1000]:
                _fails.pop(k, None)


def record_success(key: str) -> None:
    with _lock:
        _fails.pop(key, None)


def reset_limits() -> None:
    with _lock:
        _fails.clear()
        _revoked.clear()
        _unknown.clear()
