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
from typing import Any, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import encryption as en
import traces
import passwords as pw
import integrity
import rsa_crypto as rsa

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


# ----------------------------------------------------------------- models ----
class CipherRequest(BaseModel):
    algo: str                     # "caesar" | "playfair" | "hill"
    operation: str                # "encrypt" | "decrypt"
    message: str = ""
    shift: Optional[int] = None           # caesar
    direction: str = "right"              # caesar
    key: Optional[str] = None             # playfair
    matrix: Optional[List[List[int]]] = None  # hill


class WarningRequest(BaseModel):
    algo: str
    shift: Optional[int] = None
    matrix: Optional[List[List[int]]] = None


class BruteRequest(BaseModel):
    case: str
    target: str
    length: Optional[int] = None


class DictRequest(BaseModel):
    target: str
    words: Optional[List[str]] = None


class ProtectRequest(BaseModel):
    password: str
    require_lower: bool = False
    require_upper: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    min_length: Optional[int] = None
    limit_attempts: bool = False
    slow_hash: bool = False


class HashRequest(BaseModel):
    password: str


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
@app.post("/api/cipher")
def cipher(req: CipherRequest):
    try:
        if req.algo == "caesar":
            if req.shift is None:
                return _err("Indique un décalage (un entier positif).")
            trace = traces.caesar_trace(req.message, req.shift, req.direction, req.operation)
            warning = en.caesar_weak_key(req.shift)
        elif req.algo == "playfair":
            if not req.key or not req.key.strip():
                return _err("Indique une clé (des lettres) avant de lancer.")
            trace = traces.playfair_trace(req.message, req.key, req.operation)
            warning = None
        elif req.algo == "hill":
            if req.matrix is None:
                return _err("Remplis la matrice avant de lancer.")
            matrix = en.validate_matrix(req.matrix)
            trace = traces.hill_trace(req.message, matrix, req.operation)
            warning = en.hill_weak_key(matrix)
        else:
            return _err(f"Algorithme inconnu « {req.algo} ».")
        return _ok(result=trace["result"], trace=_js_safe(trace), warning=warning)
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
        dictionarySize=len(pw.DEFAULT_DICTIONARY),
        assumptions={
            "fastRate": pw.FAST_RATE,
            "slowHashRate": pw.SLOW_HASH_RATE,
            "lockoutAttempts": pw.LOCKOUT_ATTEMPTS,
            "lockoutWindow": pw.LOCKOUT_WINDOW,
            "maxAttempts": pw.MAX_ATTEMPTS,
        },
    )


@app.post("/api/passwords/bruteforce")
def password_bruteforce(req: BruteRequest):
    try:
        return _ok(**pw.brute_force(req.target, req.case, req.length))
    except ValueError as e:
        return _err(str(e))


@app.post("/api/passwords/dictionary")
def password_dictionary(req: DictRequest):
    return _ok(**pw.dictionary_attack(req.target, req.words))


@app.post("/api/passwords/protect")
def password_protect(req: ProtectRequest):
    return _ok(**pw.analyze(req.password, {
        "require_lower": req.require_lower,
        "require_upper": req.require_upper,
        "require_digit": req.require_digit,
        "require_symbol": req.require_symbol,
        "min_length": req.min_length,
        "limit_attempts": req.limit_attempts,
        "slow_hash": req.slow_hash,
    }))


@app.post("/api/passwords/hash")
def password_hash(req: HashRequest):
    return _ok(**pw.hash_password(req.password))


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


# --------------------------------------------- serve the built frontend ----
# After `npm run build`, the React app lands in ../frontend/dist. If present,
# serve it at the root so the whole app runs from this single Python server.
_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(_DIST):
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="frontend")
