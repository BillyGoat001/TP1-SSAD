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

# ---- RSA key exchange ----
section("RSA")
import rsa_crypto as rsa
# exemple de manuel : p = 61, q = 53, n = 3233, φ = 3120, e = 17, d = 2753
assert rsa.mod_inverse(17, 3120) == 2753
assert pow(65, 17, 3233) == 2790 and pow(2790, 2753, 3233) == 65
assert rsa.is_probable_prime(2**61 - 1) and rsa.is_probable_prime(65537)
assert not rsa.is_probable_prime(561) and not rsa.is_probable_prime(2**61 + 1)  # 561 = Carmichael
print("Textbook example + Miller-Rabin OK")
PARAMS = [("caesar", 3, "right", None, None), ("caesar", 25, "left", None, None),
          ("playfair", None, "right", "monarchy", None),
          ("hill", None, "right", None, [[3, 3], [2, 5]]),
          ("hill", None, "right", None, [[6, 24, 1], [13, 16, 10], [20, 17, 15]])]
for bits in (32, 64, 512, 2048):
    k = rsa.generate_keypair(bits)
    assert k["n"].bit_length() == bits and k["p"] * k["q"] == k["n"], bits
    assert k["phi"] == (k["p"] - 1) * (k["q"] - 1) and (k["e"] * k["d"]) % k["phi"] == 1
    for params in PARAMS:
        text = rsa.params_to_text(*params)
        sealed = rsa.encrypt_text(text, k["e"], k["n"])
        assert all(b["m"] < k["n"] for b in sealed["blocks"])
        opened = rsa.decrypt_blocks([b["c"] for b in sealed["blocks"]], k["d"], k["n"])
        assert opened["text"] == text and rsa.text_to_params(text)["algo"] == params[0], (bits, text)
    print(f"RSA {bits:>4} bits: keygen {k['ms']} ms, {len(sealed['blocks'])} bloc(s) pour '{text}'")
try:
    rsa.params_to_text("hill", matrix=[[2, 4], [6, 8]])
    raise AssertionError("une matrice non inversible doit être refusée")
except ValueError:
    pass
kA, kB = rsa.generate_keypair(512), rsa.generate_keypair(512)
sealed = rsa.encrypt_text("caesar|3|right", kB["e"], kB["n"])
try:   # l'espion (ou A) avec une autre clé privée ne relit pas le mode d'emploi
    wrong = rsa.decrypt_blocks([b["c"] % kA["n"] for b in sealed["blocks"]], kA["d"], kA["n"])
    assert wrong["text"] != "caesar|3|right"
except ValueError:
    pass
print("Wrong private key cannot open the box OK")

# ---- passwords ----
section("Passwords")
b = pw.brute_force("101", "binaire")
assert b["found"] and b["keyspace"] == 8, b
print(f"binaire brute force: found in {b['attempts']} attempts / keyspace {b['keyspace']}")
b = pw.brute_force("3142", "numerique")
assert b["found"] and b["keyspace"] == 256, b
print(f"numerique brute force: found in {b['attempts']} attempts / keyspace {b['keyspace']}")
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
# échange complet A -> B : chiffrement César, coffre RSA, ouverture, déchiffrement
A = c.post("/api/rsa/keygen", json={"bits": 1024}).json()["key"]
B = c.post("/api/rsa/keygen", json={"bits": 1024}).json()["key"]
enc = c.post("/api/cipher", json={"algo":"caesar","operation":"encrypt","message":"BONJOUR","shift":3,"direction":"right"}).json()
seal = c.post("/api/exchange/seal", json={"algo":"caesar","shift":3,"direction":"right","n":B["n"],"e":B["e"]}).json()
assert seal["ok"] and seal["payload"] == "caesar|3|right", seal
opened = c.post("/api/exchange/open", json={"n":B["n"],"d":B["d"],"blocks":[b["c"] for b in seal["blocks"]]}).json()
assert opened["ok"] and opened["params"] == {"algo":"caesar","shift":"3","direction":"right"}, opened
dec = c.post("/api/cipher", json={"operation":"decrypt","message":enc["result"],**opened["params"]}).json()
assert dec["ok"] and dec["result"] == "BONJOUR", dec
bad = c.post("/api/exchange/open", json={"n":A["n"],"d":A["d"],"blocks":[b["c"] for b in seal["blocks"]]}).json()
assert not bad.get("ok") or bad.get("params") != opened["params"], bad
print("RSA exchange endpoints OK (A -> B, wrong key rejected)")
print("All endpoints OK")

print("\nALL BACKEND TESTS PASSED")
