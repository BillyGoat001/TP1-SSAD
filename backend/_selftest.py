# -*- coding: utf-8 -*-
"""Backend self-test: logic + all API endpoints. Run: python _selftest.py"""
import encryption as en
import traces
import passwords as pw
import integrity

def section(t): print("\n=== " + t + " ===")

# ---- ciphers logic + traces ----
section("Ciphers")
assert en.caesar_decrypt(en.caesar_encrypt("Hello, World!", 3), 3) == "Hello, World!"
ct = traces.caesar_trace("HELLO", 3, "right", "encrypt")
assert ct["result"] == "KHOOR", ct["result"]
rebuilt = "".join(s.get("out", s.get("char")) for s in ct["steps"])
assert rebuilt == "KHOOR", rebuilt
print("Caesar trace OK:", ct["result"])

pt = traces.playfair_trace("HELLO", "MONARCHY", "encrypt")
assert pt["result"] == en.playfair_encrypt("HELLO", "MONARCHY")
rebuilt = "".join(st["outA"] + st["outB"] for st in pt["steps"])
assert rebuilt == pt["result"], (rebuilt, pt["result"])
print("Playfair trace OK:", pt["result"])

M = [[3, 3], [2, 5]]
ht = traces.hill_trace("HELP", M, "encrypt")
assert ht["result"] == en.hill_encrypt("HELP", M)
rebuilt = "".join(s["outChar"] for s in ht["steps"])
assert rebuilt == ht["result"], (rebuilt, ht["result"])
assert en.hill_decrypt(ht["result"], M) == "HELP"
print("Hill 2x2 trace OK:", ht["result"])
M3 = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
assert en.hill_decrypt(en.hill_encrypt("ATTACK", M3), M3) == "ATTACK"
print("Hill 3x3 round trip OK")

# ---- passwords ----
section("Passwords")
b = pw.brute_force("101", "bin3")
assert b["found"] and b["keyspace"] == 8, b
print(f"bin3 brute force: found in {b['attempts']} attempts / keyspace {b['keyspace']}")
b = pw.brute_force("3142", "num4")
assert b["found"] and b["keyspace"] == 256, b
print(f"num4 brute force: found in {b['attempts']} attempts / keyspace {b['keyspace']}")
d = pw.dictionary_attack("password")
assert d["found"], d
print(f"dictionary 'password': found in {d['attempts']} tries")
h = pw.hash_password("secret")
assert pw.verify_password("secret", h["salt"], h["iterations"], h["hash"])
assert not pw.verify_password("wrong", h["salt"], h["iterations"], h["hash"])
print(f"PBKDF2 hash+verify OK ({h['secondsPerGuess']*1000:.1f} ms/guess)")

# ---- integrity ----
section("Integrity")
tag = integrity.sign("sharedkey", "Transfer 100")
assert integrity.verify("sharedkey", "Transfer 100", tag)
assert not integrity.verify("sharedkey", "Transfer 900", tag)
dm = integrity.demo("sharedkey", "Transfer 100", "Transfer 900")
assert dm["tampered"] and not dm["valid"]
print("HMAC sign/verify + tamper detection OK")

# ---- API endpoints ----
section("API endpoints")
from fastapi.testclient import TestClient
from main import app
c = TestClient(app)
r = c.post("/api/cipher", json={"algo":"caesar","operation":"encrypt","message":"HELLO","shift":3,"direction":"right"}).json()
assert r["ok"] and r["result"] == "KHOOR", r
r = c.post("/api/cipher", json={"algo":"hill","operation":"encrypt","message":"HELP","matrix":[[3,3],[2,5]]}).json()
assert r["ok"] and r["result"] == "HIAT", r
r = c.post("/api/integrity/demo", json={"key":"k","original":"hi","received":"hiX"}).json()
assert r["ok"] and r["tampered"] and not r["valid"], r
print("All endpoints OK")

print("\nALL BACKEND TESTS PASSED")
