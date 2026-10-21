# -*- coding: utf-8 -*-
"""
Connexion : comptes, mots de passe hachés, sessions, limitation des tentatives.

Rien n'est stocké en clair :
  - un mot de passe est transformé par PBKDF2-HMAC-SHA256 (600 000 tours, sel aléatoire
    propre à chaque compte). Même si le fichier des comptes fuite, on ne retrouve pas
    les mots de passe, et deux comptes au même mot de passe n'ont pas le même hachage ;
  - la session est un jeton signé (HMAC-SHA256) rangé dans un cookie HttpOnly : le
    JavaScript de la page ne peut pas le lire, et toute modification le rend invalide.

Où sont les comptes ? Dans l'ordre :
  1. la variable d'environnement APP_USERS  (sur Render) :  nom:hachage;nom2:hachage2
  2. le fichier  backend/users.json  (ou USERS_FILE)  : {"users": {"nom": "hachage"}}
Pour fabriquer une ligne de compte :  python make_user.py nom

Variables utiles : SECRET_KEY (clé de signature des sessions ; sinon tirée au hasard à
chaque démarrage, ce qui déconnecte tout le monde au redémarrage), TP_AUTH_OFF=1
(DÉVELOPPEMENT UNIQUEMENT : désactive la connexion).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from typing import Dict, List, Optional, Tuple

ITERATIONS = 600_000
SESSION_SECONDS = 12 * 3600
COOKIE = "tp_session"
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,40}$")

_lock = threading.RLock()
_SECRET = (os.environ.get("SECRET_KEY") or "").encode() or secrets.token_bytes(32)
_revoked: Dict[str, float] = {}          # signatures de sessions fermées → expiration


# ----------------------------------------------------------- mots de passe ----
def hash_password(password: str, salt: Optional[bytes] = None, iterations: int = ITERATIONS) -> str:
    salt = salt if salt is not None else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, it, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(it))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# Faux hachage : si le nom n'existe pas, on calcule quand même un hachage, pour que la
# réponse prenne le même temps (sinon le délai révélerait quels noms existent).
_DUMMY = hash_password("x", b"\0" * 16)


# ------------------------------------------------------------------ comptes ----
def users_file() -> str:
    return os.environ.get("USERS_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")


def load_users() -> Dict[str, str]:
    """Les comptes {nom: hachage}. Relus à chaque appel : un nouveau compte (ou les
    tests) n'exige pas de redémarrer."""
    users: Dict[str, str] = {}
    env = os.environ.get("APP_USERS", "").strip()
    if env:
        for item in re.split(r"[;,\s]+", env):
            if ":" in item:
                name, h = item.split(":", 1)
                if USERNAME_RE.match(name) and h.startswith("pbkdf2_sha256$"):
                    users[name] = h
        return users
    try:
        with open(users_file(), encoding="utf-8") as f:
            data = json.load(f)
        for name, h in (data.get("users") or {}).items():
            if USERNAME_RE.match(name) and isinstance(h, str):
                users[name] = h
    except (OSError, ValueError):
        pass
    return users


def auth_enabled() -> bool:
    return os.environ.get("TP_AUTH_OFF") != "1"


def check_credentials(username: str, password: str) -> Optional[str]:
    """Le nom du compte si les identifiants sont bons, sinon None. Les noms sont
    insensibles à la casse (« Master » = « master »)."""
    users = load_users()
    wanted = (username or "").strip().lower()
    match = next((n for n in users if n.lower() == wanted), None)
    stored = users[match] if match else _DUMMY
    ok = verify_password(password or "", stored)
    return match if (match and ok) else None


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
        return user if user in load_users() else None
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
# Trop d'échecs de suite → attente de plus en plus longue (15 s, 30 s, 1 min… 5 min max).
_fails: Dict[str, List[float]] = {}
FAIL_WINDOW = 600
FREE_FAILS = 5


def _recent(key: str, now: float) -> List[float]:
    lst = [t for t in _fails.get(key, []) if now - t < FAIL_WINDOW]
    if lst:
        _fails[key] = lst
    else:
        _fails.pop(key, None)
    return lst


def locked_for(key: str, now: Optional[float] = None) -> int:
    """Secondes restant avant de pouvoir réessayer (0 = autorisé)."""
    now = now if now is not None else time.time()
    with _lock:
        lst = _recent(key, now)
        if len(lst) < FREE_FAILS:
            return 0
        wait = min(300, 15 * 2 ** (len(lst) - FREE_FAILS))
        left = lst[-1] + wait - now
        return int(left) + 1 if left > 0 else 0


def recent_failures(key: str, now: Optional[float] = None) -> List[float]:
    now = now if now is not None else time.time()
    with _lock:
        return list(_recent(key, now))


def record_failure(key: str, now: Optional[float] = None) -> None:
    now = now if now is not None else time.time()
    with _lock:
        _recent(key, now)
        _fails.setdefault(key, []).append(now)
        if len(_fails) > 5000:                          # garde-fou mémoire
            for k in list(_fails)[:1000]:
                _fails.pop(k, None)


def record_success(key: str) -> None:
    with _lock:
        _fails.pop(key, None)


def reset_limits() -> None:
    with _lock:
        _fails.clear()
        _revoked.clear()


def split_user_line(line: str) -> Tuple[str, str]:
    name, h = line.split(":", 1)
    return name, h
