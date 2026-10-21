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

# force brute : petits espaces parcourus pour de vrai, rang = numero d'essai
b = pw.brute_force("101", "binaire")
assert b["valid"] and b["cracked"] and b["keyspace"] == 8 and b["reallyLooped"], b
assert b["rank"] == 6, b                       # 000,001,010,011,100,101 -> 6e
print(f"binaire force brute: trouve a l'essai {b['rank']} / {b['keyspaceText']}")
b = pw.brute_force("2413", "numerique")
assert b["valid"] and b["cracked"] and b["keyspace"] == 256 and b["reallyLooped"], b
assert b["rank"] == pw.rank_of("2413", "1234", 4), b
print(f"numerique force brute: trouve a l'essai {b['rank']} / {b['keyspaceText']}")

# espace complexe : pas de boucle (figerait), rang calcule, estimation pire-cas
b = pw.brute_force("mW3Wz&DY", "complexe", length=8)
assert b["valid"] and not b["reallyLooped"] and b["cracked"], b
assert b["rank"] == pw.rank_of("mW3Wz&DY", pw.FULL_CHARSET, 8), b
assert b["worstCaseHuman"] == "3 jours" and b["strength"] == "moyen", b
print(f"complexe force brute: pire cas {b['worstCaseHuman']}, {b['keyspaceText']} combinaisons")

# limite de tentatives : l'attaque s'arrete, le petit espace n'est pas craque
b = pw.brute_force("111", "binaire", limit=3)
assert b["valid"] and not b["cracked"] and b["limit"] == 3, b   # 111 est le 8e, > 3
b = pw.brute_force("000", "binaire", limit=3)
assert b["cracked"] and b["rank"] == 1, b                       # 000 est le 1er, <= 3
print("limite de tentatives: binaire non craque a 3 essais sauf si rang <= 3 OK")

# cible invalide : caracteres hors du cas -> refus
b = pw.brute_force("abc", "binaire")
assert not b["valid"] and b["rank"] is None and not b["cracked"], b
print("cible invalide (hors charset) refusee OK")

# dictionnaire : vrai fichier rockyou, mots FR en tete, 2413 desormais trouve
size = pw.dictionary_size()
assert size > 14_000_000, size
d = pw.dictionary_attack("azerty")
assert d["found"] and d["position"] == 1, d
d = pw.dictionary_attack("2413")
assert d["found"] and d["position"] > 1, d                      # resolu par le nouveau dico
print(f"dictionnaire {size} mots: 'azerty' #1, '2413' #{d['position']}")
d = pw.dictionary_attack("zZ9#qK2!vL7@xR4$")
assert not d["found"] and d["scanned"] == size, d               # mot absent -> scan complet
d = pw.dictionary_attack("2413", limit=50)   # 2413 est au-dela de la position 50
assert not d["found"] and d["stopped"] and d["scanned"] == 50, d  # arrete par la limite
print("dictionnaire: mot absent -> non trouve ; limite -> arret OK")

# validation de la politique (cas complexe)
v = pw.validate("abcdefgh", "complexe", 8, {"require_upper": True, "require_digit": True})
assert not v["valid"] and len(v["reasons"]) == 2, v
v = pw.validate("Abcdef1!", "complexe", 8, {"require_lower": True, "require_upper": True,
                                            "require_digit": True, "require_symbol": True})
assert v["valid"], v
v = pw.validate("ab", "complexe", 2, {"min_length": 8})
assert not v["valid"], v
print("validation de la politique complexe OK")

# une seule echelle de temps (phrases des cartes + libelles courts du tableau)
Y = pw.YEAR
NB = " "
for secs, full, short in [
    (0.0005, "instantane", "instantane"),
    (0.5, "moins d'une seconde", "< 1 s"),
    (240, "4 min", "4 min"),
    (7680, "2 h", "2 h"),
    (3 * 86400, "3 jours", "3 j"),
    (42 * Y, "42 ans", "42 ans"),
    (350 * Y, "4 siecles", "4 siecles"),
    (45678 * Y, "46 millenaires", "46 millenaires"),
    (15.4e6 * Y, "10^7 ans", "10^7 ans"),
    (2.46e9 * Y, "10^9 ans", "10^9 ans"),
    (1e30, "10^22 ans", "10^22 ans"),
]:
    norm = lambda x: x.replace("é", "e").replace("è", "e").replace("â", "a")
    got_full = norm(pw.human_time(secs)[0])
    got_short = norm(pw.human_time(secs, compact=True)[0])
    assert got_full == full, (secs, repr(pw.human_time(secs)))
    assert got_short == short, (secs, repr(pw.human_time(secs, compact=True)))
assert pw.human_time(float("inf"))[1] == "inviolable" and pw.human_time(None)[1] == "inviolable"
assert pw.fmt_rate(1e10) == "10 milliards d'essais/s"
print("echelle de temps unique OK")

# tableau des durees : memes mots que les cartes
t = pw.speed_table(pw.FAST_RATE)
assert t["rows"][2]["length"] == 8 and t["rows"][2]["cells"][-1]["human"] == "3 j", t["rows"][2]
assert t["rows"][-1]["cells"][-1]["human"] == "10^13 ans", t["rows"][-1]
print("tableau des durees OK")

# force brute : le jeu de caracteres est celui REELLEMENT present (pas le pire cas)
bb = pw.brute_force("abcdefgh", "complexe", length=8)
assert bb["charsetSize"] == 26 and bb["worstCaseHuman"] == "21 s", bb      # minuscules seules
bb = pw.brute_force("Abcdef12", "complexe", length=8)
assert bb["charsetSize"] == 62, bb                                         # min+maj+chiffres
bb = pw.brute_force("mW3Wz&DY", "complexe", length=8)
assert bb["charsetSize"] == 86 and bb["findHuman"] is not None, bb         # les 4 classes
print("force brute sur le charset detecte OK")

# le hachage a bien disparu
for gone in ("hash_password", "verify_password", "analyze", "speeds", "ATTACKERS"):
    assert not hasattr(pw, gone), gone + " devrait etre supprime"
print("aucune trace de hachage / comparaison / attaquants OK")

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
# temps de calcul : un nombre positif au chiffrement ET au déchiffrement (les 3 algos)
for algo, kw in (("caesar", {"shift": 3}), ("playfair", {"key": "MONARCHY"}), ("hill", {"matrix": [[3, 3], [2, 5]]})):
    e = c.post("/api/cipher", json={"algo": algo, "operation": "encrypt", "message": "BONJOUR LE MONDE", **kw}).json()
    d = c.post("/api/cipher", json={"algo": algo, "operation": "decrypt", "message": e["result"], **kw}).json()
    for resp in (e, d):
        assert isinstance(resp["time_us"], (int, float)) and 0 <= resp["time_us"] < 1_000_000, (algo, resp.get("time_us"))
print("temps de calcul (time_us) renvoyé au chiffrement et au déchiffrement OK")

# espaces : le chiffré sort en un seul bloc, le déchiffrement les retrouve (les 3 algos)
def _roundtrip(algo, msg, **kw):
    e = c.post("/api/cipher", json={"algo":algo,"operation":"encrypt","message":msg,**kw}).json()
    assert e["ok"] and " " not in e["result"], e                 # bloc sans espaces
    d = c.post("/api/cipher", json={"algo":algo,"operation":"decrypt","message":e["result"],
               "layout":e["layout"],"fillers":e["fillers"],"jmap":e["jmap"],**kw}).json()
    return e, d
e, d = _roundtrip("caesar", "BONJOUR B", shift=3)
assert e["result"] == "ERQMRXUE" and e["layout"] == [[7, " "]] and e["fillers"] == [], e
assert d["result"] == "BONJOUR B", d
e, d = _roundtrip("hill", "ABCDE FG", matrix=[[3,3],[2,5]])
assert e["fillers"] == [7] and d["result"] == "ABCDE FG", (e, d)   # bourrage X retiré
e, d = _roundtrip("playfair", "HELLO WORLD", key="PLAYFAIR")
assert e["fillers"] == [3, 11] and d["result"] == "HELLO WORLD", (e, d)  # X insérés retirés
# Playfair : les J (fusionnés en I au chiffrement) sont restitués au déchiffrement
e, d = _roundtrip("playfair", "JE JOUE AU JEU", key="MONARCHY")
assert e["jmap"] == [0, 2, 8] and d["result"] == "JE JOUE AU JEU", (e, d)
e, d = _roundtrip("playfair", "BONJOUR LE JURY", key="MONARCHY")
assert d["result"] == "BONJOUR LE JURY", (e, d)
# sans métadonnées : rétro-compatible (déchiffrement brut, sans espaces restitués)
d0 = c.post("/api/cipher", json={"algo":"caesar","operation":"decrypt","message":"ERQMRXUE","shift":3}).json()
assert d0["ok"] and d0["result"] == "BONJOURB", d0
print("espaces: bloc chiffré sans espaces + déchiffrement qui les retrouve (César/Hill/Playfair) OK")
# minuscules : on chiffre en majuscules, la casse est mémorisée et remise au déchiffrement
def _roundtrip_case(algo, msg, **kw):
    e = c.post("/api/cipher", json={"algo":algo,"operation":"encrypt","message":msg,**kw}).json()
    assert e["ok"] and e["result"] == e["result"].upper(), e      # le chiffré reste en majuscules
    d = c.post("/api/cipher", json={"algo":algo,"operation":"decrypt","message":e["result"],
               "layout":e["layout"],"fillers":e["fillers"],"jmap":e["jmap"],"cases":e["cases"],**kw}).json()
    return e, d
for algo, kw in (("caesar", {"shift": 3}), ("playfair", {"key": "MONARCHY"}), ("hill", {"matrix": [[3,3],[2,5]]})):
    e, d = _roundtrip_case(algo, "Bonjour Le Monde", **kw)
    assert d["result"] == "Bonjour Le Monde", (algo, e, d)
    assert e["cases"] == [1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13], (algo, e["cases"])
e, d = _roundtrip_case("playfair", "Je joue au Jeu", key="PLAYFAIR")            # casse + J + X + espaces ensemble
assert d["result"] == "Je joue au Jeu", (e, d)
e, d = _roundtrip_case("hill", "Hello World", matrix=[[3,3],[2,5]])             # casse + bourrage X
assert d["result"] == "Hello World", (e, d)
# le chiffré d'un message en minuscules = celui du même message en majuscules
a = c.post("/api/cipher", json={"algo":"caesar","operation":"encrypt","message":"bonjour","shift":3}).json()
b = c.post("/api/cipher", json={"algo":"caesar","operation":"encrypt","message":"BONJOUR","shift":3}).json()
assert a["result"] == b["result"] == "ERQMRXU" and a["cases"] == list(range(7)) and b["cases"] == [], (a, b)
# sans la casse (chiffré collé à la main) : déchiffrement en majuscules, rien ne plante
d0 = c.post("/api/cipher", json={"algo":"caesar","operation":"decrypt","message":"ERQMRXU","shift":3,"layout":[],"fillers":[]}).json()
assert d0["result"] == "BONJOUR", d0
print("minuscules: chiffré en majuscules + casse restituée au déchiffrement (César/Playfair/Hill) OK")
print("Playfair: les J d'origine sont conservés au déchiffrement (J→I inversé) OK")
r = c.post("/api/integrity/demo", json={"key":"k","original":"hi","received":"hiX"}).json()
assert r["ok"] and r["tampered"] and not r["valid"], r
r = c.get("/api/passwords/cases").json()
assert r["ok"] and r["dictionarySize"] > 14_000_000 and r["table"]["rows"][2]["cells"][-1]["human"] == "3 j", r
assert r["assumptions"]["fastRateText"] == "10 milliards d'essais/s", r
r = c.post("/api/passwords/bruteforce", json={"case": "binaire", "target": "101"}).json()
assert r["ok"] and r["cracked"] and r["rank"] == 6 and r["reallyLooped"], r
r = c.post("/api/passwords/bruteforce", json={"case": "binaire", "target": "111", "limit": 3}).json()
assert r["ok"] and not r["cracked"] and r["limit"] == 3, r
r = c.post("/api/passwords/bruteforce", json={"case": "complexe", "target": "abcdefgh", "length": 8,
            "rules": {"require_upper": True}}).json()
assert r["ok"] and not r["valid"] and r["rank"] is None, r   # politique non respectée
r = c.post("/api/passwords/validate", json={"case": "complexe", "target": "Abcdef1!", "length": 8,
            "rules": {"require_lower": True, "require_upper": True, "require_digit": True, "require_symbol": True}}).json()
assert r["ok"] and r["valid"], r
r = c.post("/api/passwords/dictionary", json={"target": "azerty"}).json()
assert r["ok"] and r["found"] and r["position"] == 1, r
r = c.post("/api/passwords/dictionary", json={"target": "azerty", "limit": 0}).json()
assert r["ok"] and not r["found"] and r["stopped"], r
assert not c.post("/api/passwords/bruteforce", json={"case": "zzz", "target": "1"}).json()["ok"]
assert c.post("/api/passwords/hash", json={"password": "x"}).status_code in (404, 405)  # endpoint supprimé
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

# ---- fichiers : historique des chiffrements + conversation A <-> B ----
section("Fichiers (historique + conversation)")
import json, os, tempfile
import storage
_tmp = tempfile.TemporaryDirectory()
os.environ["DATA_DIR"] = _tmp.name          # on n'écrit jamais dans backend/data/ pendant les tests
H = os.path.join(_tmp.name, storage.HISTORY_FILE)
V = os.path.join(_tmp.name, storage.CONVERSATION_FILE)

def _entry(clear, **kw):
    return {"op": "encrypt", "clear": clear, "cipher": "KHOOR", "algo": "caesar", "algoLabel": "César",
            "key": "3 (droite)", "timeUs": 2.5, **kw}

assert c.get("/api/history").json() == {"ok": True, "entries": []}          # rien au départ, et aucun fichier créé
assert not os.path.exists(H)
ids = [c.post("/api/history", json=_entry(m)).json()["entry"]["id"] for m in ("UN", "DEUX", "TROIS")]
assert ids == [1, 2, 3], ids
lst = c.get("/api/history").json()["entries"]
assert [e["clear"] for e in lst] == ["TROIS", "DEUX", "UN"] and lst[0]["at"], lst   # la plus récente en premier
disk = json.load(open(H, encoding="utf-8"))                                 # le fichier existe et contient bien tout
assert disk["version"] == 1 and disk["next_id"] == 4 and [e["id"] for e in disk["entries"]] == [1, 2, 3], disk
assert set(disk["entries"][0]) >= {"id", "at", "op", "clear", "cipher", "algo", "algoLabel", "key", "timeUs"}
# suppression individuelle : seule la ligne visée disparaît, du fichier aussi
assert c.delete("/api/history/2").json() == {"ok": True, "deleted": True}
assert [e["id"] for e in c.get("/api/history").json()["entries"]] == [3, 1]
assert [e["id"] for e in json.load(open(H, encoding="utf-8"))["entries"]] == [1, 3]
assert c.delete("/api/history/2").json() == {"ok": True, "deleted": False}  # déjà supprimée : sans effet
assert c.delete("/api/history/999").json()["deleted"] is False
assert c.post("/api/history", json=_entry("QUATRE")).json()["entry"]["id"] == 4   # un numéro supprimé n'est pas réattribué
assert c.delete("/api/history").json() == {"ok": True, "deleted": 3}
assert c.get("/api/history").json()["entries"] == []
assert c.post("/api/history", json=_entry("CINQ")).json()["entry"]["id"] == 5     # le compteur continue après « Vider »
# entrées invalides refusées
assert c.post("/api/history", json=_entry("X", op="hack")).status_code == 422
assert c.post("/api/history", json=_entry("X" * 6000)).status_code == 422
assert c.post("/api/history", json=_entry("X", algo="rot13")).status_code == 422
# plafond : on garde les 200 plus récentes
for i in range(205):
    storage.history_add(_entry("N%d" % i))
assert len(c.get("/api/history").json()["entries"]) == storage.MAX_HISTORY == 200
assert c.get("/api/history").json()["entries"][0]["clear"] == "N204"
# écriture atomique : aucun fichier temporaire oublié
assert not [f for f in os.listdir(_tmp.name) if f.startswith(".tmp-")], os.listdir(_tmp.name)
# fichier abîmé : on repart propre, sans planter, et l'original est gardé de côté
open(H, "w", encoding="utf-8").write("{pas du json")
assert c.get("/api/history").json()["entries"] == [] and os.path.exists(H + ".illisible")
print("historique : fichier JSON, ajout, suppression d'UNE ligne, vidage, plafond, fichier abîmé OK")

msg = {"id": 1001, "from": "a", "plain": "BONJOUR", "cipher": "ERQMRXU",
       "params": {"algo": "caesar", "shift": "3", "direction": "right"}}
assert c.get("/api/conversation").json() == {"ok": True, "messages": []} and not os.path.exists(V)
r = c.post("/api/conversation", json=msg).json()
assert r["ok"] and not r["duplicate"] and r["message"]["from"] == "a" and r["message"]["at"], r
r = c.post("/api/conversation", json={**msg, "id": 1002, "from": "b", "plain": "COUCOU",
           "params": {"algo": "hill", "matrix": [["3", "3"], ["2", "5"]]}}).json()
assert r["ok"]
assert c.post("/api/conversation", json=msg).json()["duplicate"] is True      # même numéro : pas de doublon
conv = c.get("/api/conversation").json()["messages"]
assert [m["id"] for m in conv] == [1001, 1002] and [m["from"] for m in conv] == ["a", "b"], conv   # ordre d'envoi
assert conv[1]["params"]["matrix"] == [["3", "3"], ["2", "5"]] and conv[0]["params"]["shift"] == "3"
disk = json.load(open(V, encoding="utf-8"))
assert disk["version"] == 1 and [m["id"] for m in disk["messages"]] == [1001, 1002]
assert c.post("/api/conversation", json={**msg, "id": 1003, "from": "z"}).status_code == 422
assert c.post("/api/conversation", json={**msg, "id": 1003, "params": {"algo": "rot13"}}).status_code == 422
assert c.post("/api/conversation", json={**msg, "id": 1003, "params": {"algo": "hill", "matrix": [["1"] * 9]}}).status_code == 422
assert c.delete("/api/conversation").json() == {"ok": True, "deleted": 2} and c.get("/api/conversation").json()["messages"] == []
print("conversation A<->B : fichier JSON, ordre d'envoi, pas de doublon, validation OK")

# ---- historique des attaques sur mots de passe ----
P = os.path.join(_tmp.name, storage.PW_HISTORY_FILE)
def _pw(pwd, **kw):
    return {"attack": "brute", "case": "binaire", "password": pwd, "protection": "Aucune",
            "result": "found", "tries": 5, "timeSec": 5e-10, **kw}
assert c.get("/api/pw-history").json() == {"ok": True, "entries": []} and not os.path.exists(P)
i1 = c.post("/api/pw-history", json=_pw("101")).json()["entry"]
i2 = c.post("/api/pw-history", json=_pw("2413", attack="dict", case="numerique", result="interrupted", tries=1.5e12, timeSec=150.0)).json()["entry"]
assert (i1["id"], i2["id"]) == (1, 2) and i1["at"]
assert [e["id"] for e in c.get("/api/pw-history").json()["entries"]] == [2, 1]
assert c.get("/api/history").json()["entries"] == []        # indépendant de l'historique des chiffrements
assert c.delete("/api/pw-history/1").json() == {"ok": True, "deleted": True}
assert c.delete("/api/pw-history/1").json() == {"ok": True, "deleted": False}
assert c.post("/api/pw-history", json=_pw("x")).json()["entry"]["id"] == 3     # numéro jamais réattribué
assert c.delete("/api/pw-history").json() == {"ok": True, "deleted": 2}
assert c.post("/api/pw-history", json=_pw("x", result="hack")).status_code == 422
assert c.post("/api/pw-history", json=_pw("x", tries=-1)).status_code == 422
assert c.post("/api/pw-history", json=_pw("x" * 300)).status_code == 422
assert json.load(open(P, encoding="utf-8"))["version"] == 1
print("historique des attaques : ajout, suppression d'UNE ligne, vidage, validation, fichier à part OK")
_tmp.cleanup()
del os.environ["DATA_DIR"]


section("Avertissements de clés faibles (limites et failles)")
# Hill : matrice de permutation = mêmes lettres, ordre changé
for M in ([[0, 1], [1, 0]], [[0, 0, 1], [0, 1, 0], [1, 0, 0]], [[0, 1, 0], [0, 0, 1], [1, 0, 0]],
          [[0, 0, 0, 1], [0, 0, 1, 0], [0, 1, 0, 0], [1, 0, 0, 0]], [[0, 27], [1, 0]]):
    w = en.hill_weak_key(M)
    assert w and "permutation" in w, (M, w)
assert en.hill_encrypt("ABCDEF", [[0, 0, 1], [0, 1, 0], [1, 0, 0]]) == "CBAFED"       # ABC -> CBA
assert sorted(en.hill_encrypt("BONJOUR", [[0, 1], [1, 0]])) == sorted("BONJOURX")
# les autres matrices gardent leur avertissement d'origine (ou n'en ont pas)
assert "identité" in en.hill_weak_key([[1, 0], [0, 1]])
assert "diagonale" in en.hill_weak_key([[3, 0], [0, 3]])
assert "PAS déchiffrer" in en.hill_weak_key([[2, 4], [1, 2]])
assert en.hill_weak_key([[3, 3], [2, 5]]) is None
assert en.hill_weak_key([[1, 1], [0, 1]]) is None            # un 1 par ligne mais pas par colonne : pas une permutation
# Playfair : clés qui laissent la grille de l'alphabet (26 : vide, A, AB, ... alphabet complet, + J compté pour I)
alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
for k in [alpha[:i] for i in range(26)] + ["ABCDEFGHJ", "abc", "A B C"]:
    w = en.playfair_weak_key(k)
    assert w and "alphabet" in w, (k, w)
for k in ("MONARCHY", "ACB", "ABD", "BCDEF", "Z", "I", "J", "PLAYFAIR"):
    assert en.playfair_weak_key(k) is None, k
assert en.playfair_encrypt("ABCD", "ABC") == "BCDE"             # même ligne : décalage d'une place
# via l'API : l'avertissement accompagne le résultat (chiffrement ET déchiffrement)
r = c.post("/api/cipher", json={"algo": "playfair", "operation": "encrypt", "message": "ABCD", "key": "ABCDE"}).json()
assert r["ok"] and r["result"] == "BCDE" and "alphabet" in r["warning"], r
r = c.post("/api/cipher", json={"algo": "playfair", "operation": "encrypt", "message": "ABCD", "key": "MONARCHY"}).json()
assert r["ok"] and r["warning"] is None, r
r = c.post("/api/cipher", json={"algo": "hill", "operation": "encrypt", "message": "ABCDEF", "matrix": [[0, 0, 1], [0, 1, 0], [1, 0, 0]]}).json()
assert r["ok"] and r["result"] == "CBAFED" and "permutation" in r["warning"], r
r = c.post("/api/cipher", json={"algo": "hill", "operation": "decrypt", "message": "CBAFED", "matrix": [[0, 0, 1], [0, 1, 0], [1, 0, 0]]}).json()
assert r["ok"] and r["result"] == "ABCDEF" and "permutation" in r["warning"], r
r = c.post("/api/cipher/warning", json={"algo": "playfair", "key": "ABC"}).json()
assert r["ok"] and "alphabet" in r["warning"], r
assert c.post("/api/cipher/warning", json={"algo": "playfair", "key": "MONARCHY"}).json()["warning"] is None
assert c.post("/api/cipher/warning", json={"algo": "playfair"}).json()["warning"] is None
print("Hill : permutation ; Playfair : grille de l'alphabet (26 clés) ; autres clés inchangées OK")

print("\nALL BACKEND TESTS PASSED")
