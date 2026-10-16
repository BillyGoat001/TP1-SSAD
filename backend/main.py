# -*- coding: utf-8 -*-
"""
FastAPI backend for the TP Security app.

Exposes the Python logic (ciphers + traces, password attacks, HMAC integrity)
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


class EstimateRequest(BaseModel):
    case: str
    length: Optional[int] = None


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


def _ok(**data: Any) -> JSONResponse:
    return JSONResponse({"ok": True, **data})


def _err(message: str) -> JSONResponse:
    return JSONResponse({"ok": False, "error": message})


# ---------------------------------------------------------- ciphers (P1) ----
@app.post("/api/cipher")
def cipher(req: CipherRequest):
    try:
        if req.algo == "caesar":
            if req.shift is None:
                return _err("Enter a shift (a positive integer).")
            trace = traces.caesar_trace(req.message, req.shift, req.direction, req.operation)
            warning = en.caesar_weak_key(req.shift)
        elif req.algo == "playfair":
            if not req.key or not req.key.strip():
                return _err("Enter a keyword before running.")
            trace = traces.playfair_trace(req.message, req.key, req.operation)
            warning = None
        elif req.algo == "hill":
            if req.matrix is None:
                return _err("Fill the matrix before running.")
            matrix = en.validate_matrix(req.matrix)
            trace = traces.hill_trace(req.message, matrix, req.operation)
            warning = en.hill_weak_key(matrix)
        else:
            return _err(f"Unknown algorithm '{req.algo}'.")
        return _ok(result=trace["result"], trace=trace, warning=warning)
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


# -------------------------------------------------------- passwords (P3) ----
@app.get("/api/passwords/cases")
def password_cases():
    return _ok(cases={
        k: {"label": v["label"], "charset": v["charset"], "length": v["length"],
            "keyspace": pw.keyspace(v["charset"], v["length"])}
        for k, v in pw.CASES.items()
    }, dictionary=pw.DEFAULT_DICTIONARY, fullCharset=pw.FULL_CHARSET)


@app.post("/api/passwords/bruteforce")
def password_bruteforce(req: BruteRequest):
    try:
        return _ok(**pw.brute_force(req.target, req.case, req.length))
    except ValueError as e:
        return _err(str(e))


@app.post("/api/passwords/dictionary")
def password_dictionary(req: DictRequest):
    return _ok(**pw.dictionary_attack(req.target, req.words))


@app.post("/api/passwords/estimate")
def password_estimate(req: EstimateRequest):
    try:
        return _ok(**pw.estimate(req.case, req.length))
    except ValueError as e:
        return _err(str(e))


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
