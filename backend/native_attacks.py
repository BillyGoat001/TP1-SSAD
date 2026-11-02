import ctypes
import os
import subprocess
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_DIR = os.path.join(_HERE, "native")
_SRC = os.path.join(_DIR, "attacks.c")
_LIB = os.path.join(_DIR, "libattacks.so")

REPORT_EVERY = 20_000   # frequence de mise a jour du compteur partage / controle d'arret


# (Re)compile la bibliotheque C si besoin (source plus recente, ou .so absent).
# Renvoie (ok, raison_de_l'echec_ou_None) ; la raison est imprimee au demarrage
# pour diagnostiquer un repli silencieux sur Python.
def _build():
    try:
        if os.path.exists(_LIB) and os.path.getmtime(_LIB) >= os.path.getmtime(_SRC):
            return True, None
        proc = subprocess.run(
            ["gcc", "-O3", "-fPIC", "-shared", "-o", _LIB, _SRC],
            capture_output=True, timeout=60, text=True,
        )
        if proc.returncode != 0:
            return False, f"gcc a échoué (code {proc.returncode}) : {proc.stderr.strip()[:300]}"
        return True, None
    except FileNotFoundError:
        return False, "gcc introuvable (pas installé, ou absent du PATH)"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


_lib = None
_available = False
_reason = None

# Chargement de la .so et declaration des signatures ctypes des deux boucles C.
_ok, _reason = _build()
if _ok:
    try:
        _lib = ctypes.CDLL(_LIB)
        _lib.brute_search.argtypes = [
            ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_int,
            ctypes.c_longlong, ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong), ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_longlong),
        ]
        _lib.brute_search.restype = ctypes.c_int

        _lib.dict_search_buffer.argtypes = [
            ctypes.c_char_p, ctypes.c_longlong,
            ctypes.c_char_p, ctypes.c_int,
            ctypes.c_longlong, ctypes.c_longlong, ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong), ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_longlong),
        ]
        _lib.dict_search_buffer.restype = ctypes.c_int
        _available = True
    except OSError as e:
        _lib = None
        _available = False
        _reason = f"chargement de {_LIB} impossible : {e}"

# Diagnostic imprime une fois au demarrage (console uvicorn) : sans ca, un repli
# sur la boucle Python serait invisible.
if _available:
    print(f"[attacks] boucle C active ({_LIB})", file=sys.stderr)
else:
    print(f"[attacks] boucle C indisponible, repli Python actif -- raison : {_reason}", file=sys.stderr)


# Indique si la boucle C est utilisable (sinon attacks.py retombe sur Python).
def available() -> bool:
    return _available


# Raison de l'indisponibilite du C (None si tout va bien).
def reason() -> str:
    return _reason


# Attaque par force brute en C. `pos_cell` / `stop_cell` sont des cellules
# ctypes partagees avec l'appelant, a lire/ecrire depuis un autre thread pendant
# que la boucle tourne. Renvoie (found, interrupted, rank).
def brute_search(charset: str, length: int, target: str, limit, pos_cell, stop_cell):
    cs = charset.encode("latin-1", errors="ignore")
    tg = target.encode("latin-1", errors="ignore")
    out_rank = ctypes.c_longlong(-1)
    rc = _lib.brute_search(
        cs, len(cs), length, tg, len(tg),
        int(limit) if limit else 0, REPORT_EVERY,
        ctypes.byref(pos_cell), ctypes.byref(stop_cell), ctypes.byref(out_rank),
    )
    if rc == 1:
        return True, False, out_rank.value
    if rc == -1:
        return False, True, None
    return False, False, None


# Meme principe que brute_search, sur un buffer de mots separes par '\n' (un
# fichier de dictionnaire deja decompresse). Renvoie
# (found, interrupted, rank_dans_ce_buffer, mots_parcourus_ici).
def dict_search_buffer(buf: bytes, target: str, limit, base: int, pos_cell, stop_cell):
    tg = target.encode("utf-8", errors="ignore")
    out_rank = ctypes.c_longlong(-1)
    rc = _lib.dict_search_buffer(
        buf, len(buf), tg, len(tg),
        int(limit) if limit else 0, int(base), REPORT_EVERY,
        ctypes.byref(pos_cell), ctypes.byref(stop_cell), ctypes.byref(out_rank),
    )
    scanned_here = pos_cell.value - base
    if rc == 1:
        return True, False, out_rank.value, scanned_here
    if rc == -1:
        return False, True, None, scanned_here
    return False, False, None, scanned_here


_CALIBRATED = None


# Mesure la vitesse reelle (essais/s) sur un vrai run de la boucle C (jeu
# complet, longueur 8, cible inatteignable), mise en cache pour tout le process.
# Repli pessimiste (vitesse d'une boucle Python) si le C est indisponible.
def calibrate(duration: float = 0.15) -> float:
    global _CALIBRATED
    if _CALIBRATED is not None:
        return _CALIBRATED
    if not _available:
        _CALIBRATED = 2_000_000.0
        return _CALIBRATED
    charset = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
               "!@#$%^&*()-_=+[]{};:,.?/")
    pos = ctypes.c_longlong(0)
    stop = ctypes.c_int(0)
    timer = threading.Timer(duration, lambda: setattr(stop, "value", 1))
    timer.start()
    t0 = time.time()
    brute_search(charset, 8, "\x7f" * 8, None, pos, stop)
    elapsed = time.time() - t0
    timer.cancel()
    _CALIBRATED = pos.value / elapsed if elapsed > 0 else 2_000_000.0
    return _CALIBRATED
