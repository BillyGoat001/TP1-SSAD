# -*- coding: utf-8 -*-
"""
Captchas fabriqués et vérifiés par le serveur, pensés contre les agents IA qui lisent
des captures d'écran (les modèles de vision actuels lisent sans effort un texte déformé,
comptent des formes ou repèrent un trou de puzzle : ces défis-là sont donc abandonnés).

Ici, la réponse n'existe jamais dans une image fixe :

  motion    QUATRE CARACTÈRES CACHÉS DANS LE MOUVEMENT. Un nuage de points : à
            l'intérieur des caractères les points descendent, à l'extérieur ils
            montent. Une image fixe est du bruit pur ; l'œil humain, lui, sépare
            les deux mouvements. (Principe du « Motion Vision CAPTCHA », 2026.)
  illusion  QUATRE CARACTÈRES FAITS D'UNE ILLUSION DE CONTOUR. Des rayures fines
            dont la phase est décalée à l'intérieur des caractères : leur couleur
            moyenne est la même partout, seule la rupture de phase dessine la
            forme, que l'œil complète. (Principe de DualMirage, CVPR 2026.)
  shuffle   LA CLÉ ET LES CADENAS. Une clé se montre derrière un cadenas, puis les
            cadenas s'échangent de place : il faut suivre l'objet dans le temps.
            (Famille « continuité temporelle » des captchas anti-agents 2026.)

Règles communes :
  - la bonne réponse reste dans la mémoire du serveur, elle n'est JAMAIS envoyée ;
  - un captcha ne sert qu'une fois : bonne ou mauvaise, la réponse le détruit ;
  - il expire au bout de 2 minutes, et une réponse arrivée trop vite pour qu'un
    humain ait pu regarder (ou attendre la fin de l'animation) est refusée ;
  - chaque captcha porte aussi une PREUVE DE TRAVAIL : le navigateur doit trouver un
    nombre dont le hachage SHA-256 commence par `bits` zéros. Quelques dixièmes de
    seconde pour un humain, mais un robot qui enchaîne des milliers d'essais paie ;
    la difficulté monte après chaque échec.

Limite honnête : ces défis gênent surtout les agents qui regardent l'écran. Un
programme qui lit les données envoyées au navigateur, ou une personne payée pour
résoudre, les contourne. Aucun captcha n'est invincible : on empile des obstacles.
"""
import base64
import colorsys
import os
import hashlib
import io
import math
import random
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

TTL = 120
KINDS = ("motion", "illusion", "shuffle")
MAX_PENDING = 800
POW_BASE_BITS = int(os.environ.get("TP_POW_BITS", "19"))      # ≈ 0,5 million d'essais en moyenne (TP_POW_BITS : tests)
POW_MAX_BITS = POW_BASE_BITS + 6

_lock = threading.RLock()
_store: Dict[str, Dict[str, Any]] = {}
_rng = random.SystemRandom()

# pas d'O/0, I/1/L, S/5, Z/2, B/8 : les caractères qui se ressemblent sont retirés
_ALPHABET = "ACDEFGHJKMNPRTUVWXY34679"


# --------------------------------------------------------------- utilitaires ----
def _data_url(im: Image.Image) -> str:
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _font(size: int) -> ImageFont.FreeTypeFont:
    for path in (
        "DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial Black.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "C:\\Windows\\Fonts\\arialbd.ttf", "Arial Bold.ttf", "arialbd.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def _glyph_mask(text: str, w: int, h: int, size: int, tilt: float = 9, jitter: int = 4) -> Image.Image:
    """Les caractères en blanc sur noir, chacun un peu penché et décalé."""
    mask = Image.new("L", (w, h), 0)
    n = len(text)
    cell = w / n
    font = _font(size)
    for i, ch in enumerate(text):
        tile = Image.new("L", (int(cell) + 20, h + 20), 0)
        bbox = font.getbbox(ch)
        gw, gh = bbox[2] - bbox[0], bbox[3] - bbox[1]
        ImageDraw.Draw(tile).text(((tile.width - gw) / 2 - bbox[0], (tile.height - gh) / 2 - bbox[1]),
                                  ch, font=font, fill=255)
        tile = tile.rotate(_rng.uniform(-tilt, tilt), resample=Image.BICUBIC)
        mask.paste(255, (int(i * cell - 10), _rng.randint(-jitter, jitter) - 10), tile)
    return mask


# ------------------------------------------------------------------ mouvement ----
MW, MH = 160, 56            # le masque (le canvas du navigateur l'agrandit ×2)


def _make_motion() -> Tuple[Dict[str, Any], Dict[str, Any], float]:
    text = "".join(_rng.choice(_ALPHABET) for _ in range(4))
    mask = _glyph_mask(text, MW, MH, 52)
    bits = bytearray()
    cur = n = 0
    for v in mask.tobytes():
        cur = (cur << 1) | (1 if v > 127 else 0)
        n += 1
        if n == 8:
            bits.append(cur)
            cur = n = 0
    if n:
        bits.append(cur << (8 - n))
    public = {
        "width": MW * 2, "height": MH * 2, "mask": {"w": MW, "h": MH, "bits": base64.b64encode(bytes(bits)).decode()},
        "fg_dir": _rng.choice((-1, 1)),                         # sens des points DANS les caractères
        "speed": _rng.randint(46, 64),                          # pixels par seconde
        "dots": _rng.randint(2300, 2700), "noise": 0.12,        # part de points qui bougent au hasard
        "prompt": "Quatre caractères se cachent dans le mouvement des points. Recopie-les.",
    }
    return public, {"text": text}, 2.0


# ------------------------------------------------------------ illusion de contour ----
IW, IH = 330, 112
ILLUSION_ANGLE = 26        # écart d'inclinaison des rayures dans les caractères (degrés) : 0 = phase seule (très dur à lire,
                           # même pour un humain) ; 34 = plus facile pour tout le monde, y compris pour un modèle de vision


def _tone(hue: float, luma: float, sat: float = 0.55) -> Tuple[int, int, int]:
    """Une couleur de teinte `hue` dont la luminance perçue vaut `luma` (0..1) : on cherche
    la clarté HLS qui donne cette luminance (le bleu est perçu bien plus sombre que le jaune
    à clarté HLS égale, donc la clarté seule ne garantit pas le contraste entre les bandes)."""
    lo, hi = 0.02, 0.98
    rgb = (0, 0, 0)
    for _ in range(18):
        mid = (lo + hi) / 2
        r, g, b = colorsys.hls_to_rgb(hue, mid, sat)
        rgb = (int(r * 255), int(g * 255), int(b * 255))
        y = 0.299 * r + 0.587 * g + 0.114 * b
        if y < luma:
            lo = mid
        else:
            hi = mid
    return rgb


def _make_illusion() -> Tuple[Dict[str, Any], Dict[str, Any], float]:
    text = "".join(_rng.choice(_ALPHABET) for _ in range(4))
    mask = _glyph_mask(text, IW, IH, 98, tilt=7, jitter=3)
    # quelques taches qui ont le même décalage : elles brouillent la lecture
    dm = ImageDraw.Draw(mask)
    for _ in range(4):
        x, y, r = _rng.randint(0, IW), _rng.randint(0, IH), _rng.randint(7, 15)
        dm.ellipse([x - r, y - r, x + r, y + r], fill=255 if mask.getpixel((min(IW - 1, x), min(IH - 1, y))) == 0 else 0)
    h1 = _rng.random()
    h2 = (h1 + _rng.uniform(0.08, 0.16)) % 1                 # deux teintes voisines : des rayures trop vives
    c1 = _tone(h1, 0.64)                                      # vibrent et masquent le décalage. Les deux
    c2 = _tone(h2, 0.44)                                      # bandes ont une LUMINANCE perçue fixe : sans ça
                                                              # un bleu et un violet se confondent
    period = _rng.choice((6, 7))                    # deux bandes de period/2 pixels
    ang = math.radians(_rng.choice((28, 38, 52, 62)))
    ang2 = ang + math.radians(ILLUSION_ANGLE * _rng.choice((-1, 1)))
    ca, sa, cb, sb = math.cos(ang), math.sin(ang), math.cos(ang2), math.sin(ang2)
    off = _rng.uniform(0, period)
    px: List[Tuple[int, int, int]] = []
    mv = mask.tobytes()
    for y in range(IH):
        for x in range(IW):
            if mv[y * IW + x] > 127:       # dans un caractère : rayures décalées d'une demi-période (et un peu penchées)
                u = (x * cb + y * sb + off + period / 2) % period
            else:
                u = (x * ca + y * sa + off) % period
            px.append(c1 if u < period / 2 else c2)
    im = Image.new("RGB", (IW, IH))
    im.putdata(px)
    public = {"image": _data_url(im), "width": IW, "height": IH,
              "prompt": "Quatre caractères se cachent dans les rayures. Recopie-les."}
    return public, {"text": text}, 2.0


# ----------------------------------------------------------- la clé et les cadenas ----
def _make_shuffle() -> Tuple[Dict[str, Any], Dict[str, Any], float]:
    n = 5
    pos = list(range(n))                      # pos[emplacement] = numéro du cadenas qui s'y trouve
    key_lock = _rng.randrange(n)              # le cadenas qui cache la clé (il la garde en bougeant)
    swaps: List[List[int]] = []
    last: Optional[Tuple[int, int]] = None
    for _ in range(_rng.randint(9, 11)):
        while True:
            a, b = _rng.sample(range(n), 2)
            if (min(a, b), max(a, b)) != last:
                break
        last = (min(a, b), max(a, b))
        pos[a], pos[b] = pos[b], pos[a]
        swaps.append([a, b, _rng.randint(430, 620)])
    start = key_lock                          # au départ, le cadenas k est à l'emplacement k
    final = pos.index(key_lock)
    reveal = 1700
    total = (reveal + sum(s[2] for s in swaps)) / 1000
    public = {"slots": n, "start": start, "swaps": swaps, "reveal_ms": reveal,
              "prompt": "Retiens le cadenas qui cache la clé, puis retrouve-le après le mélange."}
    return public, {"slot": final}, total


_MAKERS = {"motion": _make_motion, "illusion": _make_illusion, "shuffle": _make_shuffle}


# ------------------------------------------------------------ preuve de travail ----
def pow_ok(challenge: str, nonce: Any, bits: int) -> bool:
    """sha256(challenge:nonce) commence-t-il par `bits` zéros ?"""
    try:
        digest = hashlib.sha256(f"{challenge}:{int(nonce)}".encode()).digest()
    except (TypeError, ValueError):
        return False
    val = int.from_bytes(digest, "big")
    return val >> (256 - bits) == 0


# ---------------------------------------------------------- cycle de vie ----
def new_challenge(exclude: Optional[str] = None, extra_bits: int = 0, now: Optional[float] = None) -> Dict[str, Any]:
    """Un nouveau captcha, d'une sorte différente de `exclude` (le précédent) si possible.
    `extra_bits` : difficulté ajoutée à la preuve de travail (échecs récents)."""
    now = now if now is not None else time.time()
    kinds = [k for k in KINDS if k != exclude] or list(KINDS)
    kind = _rng.choice(kinds)
    public, secret, min_s = _MAKERS[kind]()
    cid = secrets.token_urlsafe(18)
    bits = max(POW_BASE_BITS, min(POW_MAX_BITS, POW_BASE_BITS + extra_bits))
    pow_challenge = secrets.token_hex(12)
    with _lock:
        for k in [k for k, v in _store.items() if v["exp"] < now]:
            del _store[k]
        if len(_store) >= MAX_PENDING:                  # garde-fou : on oublie les plus vieux
            for k in sorted(_store, key=lambda k: _store[k]["exp"])[:MAX_PENDING // 4]:
                del _store[k]
        _store[cid] = {"kind": kind, "secret": secret, "exp": now + TTL, "born": now,
                       "min_s": min_s, "pow": (pow_challenge, bits)}
    return {"id": cid, "kind": kind, "ttl": TTL, "pow": {"challenge": pow_challenge, "bits": bits}, **public}


def verify(cid: str, answer: Any, nonce: Any = None, now: Optional[float] = None) -> str:
    """'ok', ou la raison du refus : unknown · expired · pow · fast · wrong.
    Le captcha est détruit quoi qu'il arrive (usage unique)."""
    now = now if now is not None else time.time()
    with _lock:
        ch = _store.pop(str(cid), None)
    if ch is None:
        return "unknown"
    if ch["exp"] < now:
        return "expired"
    if not pow_ok(ch["pow"][0], nonce, ch["pow"][1]):
        return "pow"
    if now - ch["born"] < ch["min_s"]:
        return "fast"                           # plus vite qu'un humain ne peut regarder
    sec = ch["secret"]
    try:
        if ch["kind"] == "shuffle":
            return "ok" if int(str(answer).strip()) == sec["slot"] else "wrong"
        return "ok" if str(answer).strip().upper().replace(" ", "") == sec["text"] else "wrong"
    except (TypeError, ValueError):
        return "wrong"


def discard(cid: str) -> bool:
    """Abandonne un défi (fenêtre fermée, défi remplacé) : il ne pourra plus servir."""
    with _lock:
        return _store.pop(str(cid), None) is not None


def pending() -> int:
    with _lock:
        return len(_store)


def solve_pow(challenge: str, bits: int) -> int:
    """Le travail que le navigateur fait (ici en Python, pour les tests)."""
    n = 0
    while not pow_ok(challenge, n, bits):
        n += 1
    return n


def _answer_for_tests(cid: str) -> Optional[Dict[str, Any]]:
    """RÉSERVÉ AUX TESTS : la réponse d'un captcha en attente (jamais exposée par l'API)."""
    with _lock:
        ch = _store.get(cid)
        if not ch:
            return None
        return dict(ch["secret"], kind=ch["kind"], pow=ch["pow"], born=ch["born"], min_s=ch["min_s"])
