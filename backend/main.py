# -*- coding: utf-8 -*-
"""
FastAPI backend for the TP Security app.

Exposes the Python logic (ciphers + traces, RSA key exchange, password attacks,
HMAC integrity)
as a small JSON API under /api, and — in production — serves the built React
frontend so the whole thing runs with a single command and only Python.

Run (development, with the Vite dev server on :5173):
    uvicorn main:app --reload --port 8000

Run (production, after `npm run build` in ../frontend):
    uvicorn main:app --port 8000
    then open http://localhost:8000
"""

import os
import gc
import time
from typing import Any, Dict, List, Literal, Optional, Union

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

import encryption as en
import traces
import passwords as pw
import attacks
import integrity
import rsa_crypto as rsa
import storage
import auth
import captcha

app = FastAPI(title="TP Security API")

# During development the frontend runs on http://localhost:5173 (Vite) and calls
# the API here on :8000. In production the frontend is served by this same app,
# so there is no cross-origin call. Allowing the Vite origin keeps dev simple.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)



# ------------------------------------------------------------- connexion ----
# Toute l'API (/api/…) exige une session ouverte, sauf /api/auth/* (se connecter) et
# /api/health. Les fichiers de l'appli (la page de connexion elle-même) restent publics.
@app.middleware("http")
async def _guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and auth.auth_enabled() and not path.startswith("/api/auth/") and path != "/api/health":
        if not auth.read_token(request.cookies.get(auth.COOKIE)):
            return JSONResponse({"ok": False, "error": "Connexion requise.", "auth": False},
                                status_code=401, headers={"Cache-Control": "no-store"})
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if path.startswith("/api/auth/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ----------------------------------------------------------------- models ----
class CipherRequest(BaseModel):
    algo: str                     # "caesar" | "playfair" | "hill"
    operation: str                # "encrypt" | "decrypt"
    message: str = ""
    shift: Optional[int] = None           # caesar
    direction: str = "right"              # caesar
    key: Optional[str] = None             # playfair
    matrix: Optional[List[List[int]]] = None  # hill
    # mise en forme (déchiffrement) : masque des espaces + positions des X ajoutés
    layout: Optional[List[List[Any]]] = None
    fillers: Optional[List[int]] = None
    jmap: Optional[List[int]] = None       # Playfair : positions des J d'origine (J→I)
    cases: Optional[List[int]] = None      # positions des lettres écrites en minuscules


class WarningRequest(BaseModel):
    algo: str
    shift: Optional[int] = None
    matrix: Optional[List[List[int]]] = None
    key: Optional[str] = None


class Rules(BaseModel):
    require_lower: bool = False
    require_upper: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    min_length: Optional[int] = None


class BruteRequest(BaseModel):
    case: str
    target: str
    length: Optional[int] = None
    limit: Optional[int] = None         # limite de tentatives (verrouillage)
    rules: Optional[Rules] = None       # politique (cas complexe)
    know_composition: bool = True       # l'attaquant connaît-il la composition ?


class DictRequest(BaseModel):
    target: str
    limit: Optional[int] = None


class AttackStartRequest(BaseModel):
    kind: Literal["brute", "dict"]
    case: Optional[str] = None          # requis pour « brute »
    target: str
    length: Optional[int] = None
    limit: Optional[int] = None
    rules: Optional[Rules] = None
    know_composition: bool = True
    lang: Literal["fr", "en"] = "fr"    # ordre de lecture du dictionnaire (voir passwords._dict_order)


class ValidateRequest(BaseModel):
    case: str
    target: str
    length: Optional[int] = None
    rules: Optional[Rules] = None


class SignRequest(BaseModel):
    key: str
    message: str


class VerifyRequest(BaseModel):
    key: str
    message: str
    tag: str


class IntegrityDemoRequest(BaseModel):
    key: str
    original: str
    received: str


class IntegritySealRequest(BaseModel):
    key: str
    message: str
    encrypt: bool = True     # False = le message voyage en clair (démontre que chiffrement ≠ intégrité)


class IntegrityOpenRequest(BaseModel):
    key: str
    record: Dict[str, Any]       # tel que renvoyé par /api/integrity/seal (son "secret" peut avoir été modifié par C)
    protect: bool
    tag: Optional[str] = None    # l'étiquette envoyée par A (ignorée si protect=False)


class KeygenRequest(BaseModel):
    bits: int = rsa.DEFAULT_BITS


class SealRequest(BaseModel):
    # le mode d'emploi à enfermer (mêmes champs que /api/cipher)…
    algo: str
    shift: Optional[int] = None
    direction: str = "right"
    key: Optional[str] = None
    matrix: Optional[List[List[int]]] = None
    # …et la clé publique du destinataire (grands nombres en texte)
    n: str
    e: str


class OpenRequest(BaseModel):
    # la clé privée du destinataire + les blocs chiffrés du coffre
    n: str
    d: str
    blocks: List[str]


# --- fichiers de stockage : historique des chiffrements + conversation A ↔ B ---
class HistoryEntryIn(BaseModel):
    op: Literal["encrypt", "decrypt"]
    clear: str = Field(max_length=5000)        # message clair
    cipher: str = Field(max_length=5000)       # message chiffré
    algo: Literal["caesar", "playfair", "hill"]
    algoLabel: str = Field(max_length=40)
    key: str = Field(max_length=2000)          # la clé, en texte lisible
    timeUs: Optional[float] = None             # temps de calcul (µs)


class PwHistoryIn(BaseModel):
    attack: Literal["brute", "dict"]                       # type d'attaque
    case: Literal["binaire", "numerique", "complexe"]
    password: str = Field(max_length=200)                   # le mot de passe visé
    protection: str = Field(max_length=300)                 # résumé : « Aucune », « 5 tentatives max »…
    result: Literal["found", "blocked", "resist", "interrupted"]
    tries: float = Field(ge=0, allow_inf_nan=False)         # essais effectués
    timeSec: float = Field(ge=0, allow_inf_nan=False)       # durée de l'attaque (secondes, vitesse de l'attaquant)


class ChatParams(BaseModel):
    algo: Literal["caesar", "playfair", "hill"]
    shift: Optional[Union[int, str]] = None   # un très grand décalage arrive en texte
    direction: Optional[Literal["right", "left"]] = None
    key: Optional[str] = Field(default=None, max_length=2000)
    matrix: Optional[List[List[Union[int, str]]]] = Field(default=None, max_length=5)

    @field_validator("shift")
    @classmethod
    def _shift_court(cls, v):
        if isinstance(v, str) and len(v) > 200:
            raise ValueError("décalage trop long")
        return v

    @field_validator("matrix")
    @classmethod
    def _matrice_bornee(cls, v):
        if v is not None and any(len(row) > 5 or any(isinstance(c, str) and len(c) > 200 for c in row) for row in v):
            raise ValueError("matrice trop grande")
        return v


class ChatMessageIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: int
    sender: Literal["a", "b"] = Field(alias="from")   # « from » est un mot réservé de Python
    plain: str = Field(max_length=5000)
    cipher: str = Field(max_length=20000)
    params: ChatParams


def _ok(**data: Any) -> JSONResponse:
    return JSONResponse({"ok": True, **data})


_JS_MAX = 2 ** 53


def _js_safe(x: Any) -> Any:
    """Les entiers trop grands pour JavaScript (au-delà de 2^53) repartent en
    texte : une très grande case de matrice garde ainsi tous ses chiffres."""
    if isinstance(x, bool):
        return x
    if isinstance(x, int):
        return str(x) if abs(x) >= _JS_MAX else x
    if isinstance(x, list):
        return [_js_safe(v) for v in x]
    if isinstance(x, dict):
        return {k: _js_safe(v) for k, v in x.items()}
    return x


def _err(message: str) -> JSONResponse:
    return JSONResponse({"ok": False, "error": message})


# ---------------------------------------------------------- ciphers (P1) ----
def _bench_us(fn, *args):
    """Temps de calcul de l'algorithme SEUL (sans la trace d'animation, sans le
    réseau), en microsecondes.

    Un calcul de quelques µs est trop court pour être chronométré en un seul appel :
    le moindre événement de la machine (autre programme, cache du processeur,
    ramasse-miettes de Python) pèse autant que le calcul lui-même. On procède donc
    comme `timeit` :
      - on cale un nombre d'appels `n` qui dure environ 1 ms, et on mesure UNE
        fenêtre de `n` appels d'affilée (temps moyen d'un appel) ;
      - on répète des dizaines de fenêtres (dans un budget de ~60 ms) ;
      - on garde la plus rapide : c'est celle où la machine a le moins gêné
        l'algorithme, donc la plus proche de son vrai coût.
    Le ramasse-miettes est suspendu pendant la mesure."""
    window_ns, budget_ns, max_windows = 1_000_000, 60_000_000, 80
    gc_was_on = gc.isenabled()
    gc.disable()
    try:
        start = time.perf_counter_ns()
        n = 1
        while True:                                   # calibrage de la fenêtre
            t0 = time.perf_counter_ns()
            for _ in range(n):
                fn(*args)
            dt = time.perf_counter_ns() - t0
            if dt >= window_ns or n >= 1_000_000:
                break
            n *= 4 if dt < window_ns / 8 else 2
        best = dt / n
        windows = 1
        while windows < max_windows and time.perf_counter_ns() - start < budget_ns:
            t0 = time.perf_counter_ns()
            for _ in range(n):
                fn(*args)
            best = min(best, (time.perf_counter_ns() - t0) / n)
            windows += 1
        return round(best / 1000, 2)
    finally:
        if gc_was_on:
            gc.enable()


@app.post("/api/cipher")
def cipher(req: CipherRequest):
    """Chiffre/déchiffre, en sortant un bloc de lettres (sans espaces) et en
    gérant la mise en forme à part :
      - chiffrement : on sépare les espaces (layout) avant de chiffrer les
        lettres, et on renvoie layout + positions des X ajoutés (fillers) ;
      - déchiffrement : si on reçoit layout + fillers, on retire les X puis on
        remet les espaces, pour retrouver le message d'origine."""
    try:
        encrypting = req.operation == "encrypt"
        # au chiffrement, on retire les non-lettres AVANT de chiffrer (le bloc
        # chiffré est alors « en un seul morceau », comme Playfair et Hill)
        if encrypting:
            letters, layout = en.split_layout(req.message)
            cases = en.lower_positions(letters)   # où étaient les minuscules
            text = en.to_upper(letters)           # on chiffre en majuscules
        else:
            layout, text = None, req.message

        fillers = []
        jmap = []
        if req.algo == "caesar":
            if req.shift is None:
                return _err("Indique un décalage (un entier positif).")
            trace = traces.caesar_trace(text, req.shift, req.direction, req.operation)
            warning = en.caesar_weak_key(req.shift)
        elif req.algo == "playfair":
            if not req.key or not req.key.strip():
                return _err("Indique une clé (des lettres) avant de lancer.")
            trace = traces.playfair_trace(text, req.key, req.operation)
            warning = en.playfair_weak_key(req.key)
            if encrypting:
                fillers = en.playfair_fillers(en._playfair_clean(text))
                jmap = en.playfair_jmap(text)   # où étaient les J (fusionnés en I)
        elif req.algo == "hill":
            if req.matrix is None:
                return _err("Remplis la matrice avant de lancer.")
            matrix = en.validate_matrix(req.matrix)
            trace = traces.hill_trace(text, matrix, req.operation)
            warning = en.hill_weak_key(matrix)
            if encrypting:
                fillers = en.hill_fillers(len(en._hill_clean(text)), len(matrix))
        else:
            return _err(f"Algorithme inconnu « {req.algo} ».")

        result = trace["result"]
        # temps de calcul de l'algorithme (None si la mesure n'est pas possible)
        try:
            if req.algo == "caesar":
                fn = en.caesar_encrypt if encrypting else en.caesar_decrypt
                time_us = _bench_us(fn, text, req.shift, req.direction)
            elif req.algo == "playfair":
                fn = en.playfair_encrypt if encrypting else en.playfair_decrypt
                time_us = _bench_us(fn, text, req.key)
            else:
                fn = en.hill_encrypt if encrypting else en.hill_decrypt
                time_us = _bench_us(fn, text, matrix)
        except Exception:
            time_us = None
        if encrypting:
            # le bloc chiffré + les métadonnées pour retrouver la forme au déchiffrement
            return _ok(result=result, trace=_js_safe(trace), warning=warning,
                       layout=layout, fillers=fillers, jmap=jmap, cases=cases, time_us=time_us)
        # déchiffrement : on remet la forme d'origine si on a les métadonnées
        if req.layout is not None:
            cleaned = en.strip_fillers(result, req.fillers or [])
            cleaned = en.restore_j(cleaned, req.jmap or [])   # I→J aux positions mémorisées
            cleaned = en.restore_case(cleaned, req.cases or [])   # minuscules aux positions mémorisées
            result = en.merge_layout(cleaned, req.layout)
        return _ok(result=result, trace=_js_safe(trace), warning=warning, time_us=time_us)
    except ValueError as e:
        return _err(str(e))


@app.post("/api/cipher/warning")
def cipher_warning(req: WarningRequest):
    try:
        if req.algo == "caesar":
            return _ok(warning=en.caesar_weak_key(req.shift) if req.shift is not None else None)
        if req.algo == "hill":
            if not req.matrix:
                return _ok(warning=None)
            return _ok(warning=en.hill_weak_key(en.validate_matrix(req.matrix)))
        if req.algo == "playfair":
            return _ok(warning=en.playfair_weak_key(req.key) if req.key and req.key.strip() else None)
        return _ok(warning=None)
    except ValueError as e:
        return _ok(warning=str(e))


# ------------------------------------------- key exchange with RSA (P2) ----
# Les grands nombres sont renvoyés en texte : en JavaScript, un nombre au-delà
# de 2^53 perd sa précision.
@app.post("/api/rsa/keygen")
def rsa_keygen(req: KeygenRequest):
    try:
        k = rsa.generate_keypair(req.bits)
    except ValueError as e:
        return _err(str(e))
    return _ok(key={name: (str(v) if name in ("p", "q", "n", "phi", "e", "d") else v)
                    for name, v in k.items()})


@app.post("/api/exchange/seal")
def exchange_seal(req: SealRequest):
    """L'expéditeur enferme {algo, clé} avec la clé publique (e, n) du destinataire."""
    try:
        n, e = rsa.parse_int(req.n, "n"), rsa.parse_int(req.e, "e")
        payload = rsa.params_to_text(req.algo, req.shift, req.direction, req.key, req.matrix)
        sealed = rsa.encrypt_text(payload, e, n)
    except ValueError as ex:
        return _err(str(ex))
    return _ok(
        payload=payload,
        blockBytes=sealed["blockBytes"],
        blocks=[{"text": b["text"], "m": str(b["m"]), "c": str(b["c"])} for b in sealed["blocks"]],
    )


@app.post("/api/exchange/open")
def exchange_open(req: OpenRequest):
    """Le destinataire ouvre le coffre avec SA clé privée (d, n) et relit {algo, clé}."""
    try:
        n, d = rsa.parse_int(req.n, "n"), rsa.parse_int(req.d, "d")
        cipher = [rsa.parse_int(c, "un bloc chiffré") for c in req.blocks]
        opened = rsa.decrypt_blocks(cipher, d, n)
        params = rsa.text_to_params(opened["text"])
    except ValueError as ex:
        return _err(str(ex))
    # les nombres de la clé repartent en texte : un grand décalage ou une grande
    # case de matrice garde ainsi tous ses chiffres côté JavaScript
    if "shift" in params:
        params["shift"] = str(params["shift"])
    if "matrix" in params:
        params["matrix"] = [[str(v) for v in row] for row in params["matrix"]]
    return _ok(
        payload=opened["text"],
        blocks=[{"c": str(b["c"]), "m": str(b["m"]), "text": b["text"]} for b in opened["blocks"]],
        params=params,
    )


# -------------------------------------------------------- passwords (P3) ----
@app.get("/api/passwords/cases")
def password_cases():
    return _ok(
        cases={
            k: {
                "label": v["label"],
                "charset": v["charset"],
                "length": v["length"],
                "keyspace": pw.keyspace(v["charset"], v["length"]),
                "keyspaceText": pw.fmt_count(pw.keyspace(v["charset"], v["length"])),
            }
            for k, v in pw.CASES.items()
        },
        fullCharset=pw.FULL_CHARSET,
        classSizes=pw.CLASS_SIZES,
        dictionarySize=pw.dictionary_size(),
        table=pw.speed_table(),
        assumptions=pw.assumptions(),
    )


def _rules_dict(rules):
    if rules is None:
        return None
    return {
        "require_lower": rules.require_lower,
        "require_upper": rules.require_upper,
        "require_digit": rules.require_digit,
        "require_symbol": rules.require_symbol,
        "min_length": rules.min_length,
    }


@app.post("/api/passwords/validate")
def password_validate(req: ValidateRequest):
    try:
        return _ok(**pw.validate(req.target, req.case, req.length, _rules_dict(req.rules)))
    except ValueError as e:
        return _err(str(e))


@app.post("/api/passwords/bruteforce")
def password_bruteforce(req: BruteRequest):
    try:
        return _ok(**pw.brute_force(req.target, req.case, req.length, req.limit, _rules_dict(req.rules), req.know_composition))
    except ValueError as e:
        return _err(str(e))


@app.post("/api/passwords/dictionary")
def password_dictionary(req: DictRequest):
    return _ok(**pw.dictionary_attack(req.target, req.limit))


# --- attaques en tâche de fond : vraie boucle, vraie progression, vrai arrêt ----
# (remplace, côté frontend, les deux routes ci-dessus pour l'affichage en direct ;
# elles restent utilisables telles quelles pour un résultat instantané/scripté)
@app.post("/api/passwords/attack/start")
def attack_start(req: AttackStartRequest):
    try:
        if req.kind == "brute":
            if not req.case:
                return _err("Cas manquant.")
            run = attacks.start_bruteforce(req.target, req.case, req.length, req.limit,
                                            _rules_dict(req.rules), req.know_composition)
        else:
            run = attacks.start_dictionary(req.target, req.limit, req.lang)
    except ValueError as e:
        return _err(str(e))
    return _ok(**run.snapshot())


@app.get("/api/passwords/attack/progress/{run_id}")
def attack_progress(run_id: str):
    run = attacks.get(run_id)
    if run is None:
        return _err("Attaque introuvable (terminée depuis trop longtemps, ou identifiant invalide).")
    return _ok(**run.snapshot())


@app.post("/api/passwords/attack/stop/{run_id}")
def attack_stop(run_id: str):
    return _ok(stopped=attacks.stop(run_id))


# -------------------------------------------------------- integrity (P4) ----
@app.post("/api/integrity/sign")
def integrity_sign(req: SignRequest):
    return _ok(tag=integrity.sign(req.key, req.message))


@app.post("/api/integrity/verify")
def integrity_verify(req: VerifyRequest):
    return _ok(valid=integrity.verify(req.key, req.message, req.tag))


@app.post("/api/integrity/demo")
def integrity_demo(req: IntegrityDemoRequest):
    return _ok(**integrity.demo(req.key, req.original, req.received))


# canal A -> B réel : le message est vraiment chiffré (algo + clé tirés au
# hasard, voir integrity.seal), et c'est ce chiffré que C peut altérer avant
# que B ne l'ouvre (integrity.open_channel), protection HMAC activable ou non.
@app.post("/api/integrity/seal")
def integrity_seal(req: IntegritySealRequest):
    return _ok(**integrity.seal(req.key, req.message, req.encrypt))


@app.post("/api/integrity/open")
def integrity_open(req: IntegrityOpenRequest):
    try:
        return _ok(**integrity.open_channel(req.key, req.record, req.protect, req.tag))
    except (KeyError, TypeError, ValueError) as e:
        return _err(f"Chiffré ou clé invalide : {e}")


# ------------------------------------------ fichiers : historique + conversation ----
# Voir storage.py : deux fichiers JSON dans backend/data/.
@app.get("/api/history")
def history_list():
    return _ok(entries=storage.history_list())            # la plus récente en premier


@app.post("/api/history")
def history_add(entry: HistoryEntryIn):
    return _ok(entry=storage.history_add(entry.model_dump()))


@app.delete("/api/history/{entry_id}")
def history_delete(entry_id: int):
    """Supprime UNE ligne de l'historique."""
    return _ok(deleted=storage.history_delete(entry_id))


@app.delete("/api/history")
def history_clear():
    return _ok(deleted=storage.history_clear())


@app.get("/api/pw-history")
def pw_history_list():
    return _ok(entries=storage.pw_history_list())


@app.post("/api/pw-history")
def pw_history_add(entry: PwHistoryIn):
    return _ok(entry=storage.pw_history_add(entry.model_dump()))


@app.delete("/api/pw-history/{entry_id}")
def pw_history_delete(entry_id: int):
    return _ok(deleted=storage.pw_history_delete(entry_id))


@app.delete("/api/pw-history")
def pw_history_clear():
    return _ok(deleted=storage.pw_history_clear())


@app.get("/api/conversation")
def conversation_list():
    return _ok(messages=storage.conversation_list())


@app.post("/api/conversation")
def conversation_add(msg: ChatMessageIn):
    saved = storage.conversation_add(msg.model_dump(by_alias=True, exclude_none=True))
    return _ok(message=saved, duplicate=saved is None)


@app.delete("/api/conversation")
def conversation_clear():
    return _ok(deleted=storage.conversation_clear())



# -------------------------------------------------- connexion : routes /api/auth ----
class LoginIn(BaseModel):
    username: str = Field(max_length=60)
    password: str = Field(max_length=200)
    captcha_id: str = Field(max_length=100)
    answer: Any = None                  # texte tapé, ou numéro du cadenas choisi
    nonce: Any = None                   # le nombre trouvé pour la preuve de travail
    human: Optional[dict] = None        # {ms: temps passé sur la page, events: gestes}


_CAPTCHA_MSG = {
    "wrong": "Défi raté. Un nouveau défi t'attend.",
    "expired": "Le défi a expiré. Un nouveau défi t'attend.",
    "unknown": "Le défi a expiré. Un nouveau défi t'attend.",
    "pow": "Preuve de travail invalide. Un nouveau défi t'attend.",
    "fast": "Trop rapide : prends le temps de regarder le défi.",
}
_gen: dict = {}                         # ip → instants des derniers captchas demandés


def _ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else "") or (request.client.host if request.client else "?")


def _cookie_secure(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"


@app.get("/api/health")
def health():
    return {"ok": True, "app": "tp-securite"}


@app.get("/api/auth/status")
def auth_status(request: Request):
    user = auth.read_token(request.cookies.get(auth.COOKIE)) if auth.auth_enabled() else "dev"
    return {"ok": True, "authenticated": bool(user), "user": user, "auth_required": auth.auth_enabled(),
            "configured": auth.has_users()}


@app.get("/api/auth/captcha")
def auth_captcha(request: Request, exclude: Optional[str] = None):
    """Un nouveau défi (jamais deux fois la même sorte de suite). Limité : 40 par minute."""
    ip, now = _ip(request), time.time()
    recent = [t for t in _gen.get(ip, []) if now - t < 60]
    if len(recent) >= 40:
        return JSONResponse({"ok": False, "error": "Trop de demandes. Patiente un instant."}, status_code=429)
    recent.append(now)
    _gen[ip] = recent
    if len(_gen) > 3000:
        _gen.clear()
    extra = len(auth.recent_failures("ip:" + ip))          # chaque échec récent alourdit la preuve de travail
    return {"ok": True, "challenge": captcha.new_challenge(exclude=exclude if exclude in captcha.KINDS else None, extra_bits=extra)}


class DiscardIn(BaseModel):
    id: str = Field(max_length=100)


@app.post("/api/auth/captcha/discard")
def auth_captcha_discard(req: DiscardIn):
    """La fenêtre a été fermée (ou le défi remplacé) : le défi est détruit côté serveur."""
    return {"ok": True, "discarded": captcha.discard(req.id)}


def _blocked_response(wait_captcha: Optional[str] = None):
    if wait_captcha:
        captcha.verify(wait_captcha, None)                         # le défi est détruit quand même
    return JSONResponse({"ok": False, "error": "blocked", "message": _BLOCKED_MSG}, status_code=423)


_BLOCKED_MSG = ("Compte bloqué pour cette adresse après 4 mots de passe erronés. "
                "Depuis une autre adresse, la connexion reste possible. "
                "Un administrateur peut débloquer avec : python make_user.py nom --unlock")


def _gate(req, request: Request):
    """Les protections communes à la connexion et à l'inscription : limite par IP, défi
    anti-robot (usage unique), comportement humain. Renvoie une réponse d'erreur, ou None
    si tout est bon."""
    ip = _ip(request)
    # 1) le défi (usage unique)
    why = captcha.verify(req.captcha_id, req.answer, req.nonce)
    if why != "ok":
        auth.record_failure("ip:" + ip)
        return JSONResponse({"ok": False, "error": "captcha", "reason": why, "message": _CAPTCHA_MSG.get(why, _CAPTCHA_MSG["wrong"])},
                            status_code=400)
    # 2) le comportement : un humain reste un peu sur la page et fait des gestes
    h = req.human or {}
    try:
        ms, events = float(h.get("ms", 0)), int(h.get("events", 0))
    except (TypeError, ValueError):
        ms, events = 0.0, 0
    if ms < 1500 or events < 3:
        auth.record_failure("ip:" + ip)
        return JSONResponse({"ok": False, "error": "captcha", "reason": "robot",
                             "message": "Comportement suspect : réessaie avec la souris ou le clavier."}, status_code=400)
    return None


@app.post("/api/auth/login")
def auth_login(req: LoginIn, request: Request):
    if not auth.auth_enabled():
        return JSONResponse({"ok": True, "user": "dev"})
    ip = _ip(request)
    if auth.is_blocked(req.username, ip):                   # bloqué pour CETTE IP : même avec le bon mot de passe
        return _blocked_response(req.captcha_id)
    gate = _gate(req, request)
    if gate:
        return gate
    # 3) les identifiants (au plus 4 mots de passe erronés de suite depuis cette IP,
    #    puis ce couple compte/IP est bloqué — une autre IP peut toujours essayer)
    user, remaining = auth.attempt_login(req.username, req.password, ip)
    if not user:
        auth.record_failure("ip:" + ip)
        if remaining == 0:
            return _blocked_response()
        return JSONResponse({"ok": False, "error": "credentials", "remaining": remaining,
                             "message": "Identifiant ou mot de passe incorrect."}, status_code=401)
    auth.record_success("ip:" + ip)
    resp = JSONResponse({"ok": True, "user": user})
    resp.set_cookie(auth.COOKIE, auth.make_token(user), max_age=auth.SESSION_SECONDS, httponly=True,
                    samesite="lax", secure=_cookie_secure(request), path="/")
    return resp


_REGISTER_MSG = {
    "username": "Identifiant : 3 à 40 caractères (lettres, chiffres, . _ @ -).",
    "exists": "Cet identifiant existe déjà.",
}


@app.post("/api/auth/register")
def auth_register(req: LoginIn, request: Request):
    """Inscription : mêmes protections que la connexion (défi, preuve de travail, geste
    humain, limite par IP). Le mot de passe est chiffré par l'un des trois algorithmes."""
    if not auth.auth_enabled():
        return JSONResponse({"ok": False, "error": "off", "message": "La connexion est désactivée."}, status_code=400)
    gate = _gate(req, request)
    if gate:
        return gate
    name, err = auth.register(req.username, req.password)
    if err == "policy":
        return JSONResponse({"ok": False, "error": "policy", "message": auth.password_problem(req.password)}, status_code=400)
    if err:
        return JSONResponse({"ok": False, "error": err, "message": _REGISTER_MSG[err]},
                            status_code=409 if err == "exists" else 400)
    return JSONResponse({"ok": True, "user": name}, status_code=201)


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    auth.revoke_token(request.cookies.get(auth.COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


# --------------------------------------------- serve the built frontend ----
# After `npm run build`, the React app lands in ../frontend/dist. If present,
# serve it at the root so the whole app runs from this single Python server.
_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(_DIST):
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="frontend")
