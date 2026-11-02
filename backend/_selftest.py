# Auto-test du backend : logique + tous les endpoints de l'API. Lancer : python _selftest.py
import os
os.environ["TP_POW_BITS"] = "12"        # preuve de travail légère pour les tests
os.environ["TP_AUTH_OFF"] = "1"        # les tests de l'API ci-dessous tournent sans connexion
import encryption as en
import traces
import passwords as pw
import attacks
import integrity
import auth

# Imprime un titre de section dans la sortie des tests.
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

# PIN a 4 chiffres (cas "numerique") : les 256 combinaisons sont TOUTES dans le
# dictionnaire desormais (dictionnaire_extra.txt complete les 32 qui manquaient),
# comme les 8/8 du cas "binaire" -- un seul passage dans le dictionnaire pour les 256
import itertools
pins = {"".join(c) for c in itertools.product("1234", repeat=4)}
found_pins = set()
for w in pw._iter_words():
    if w in pins:
        found_pins.add(w)
        if len(found_pins) == len(pins):
            break
assert found_pins == pins, sorted(pins - found_pins)
bins = {"".join(c) for c in itertools.product("01", repeat=3)}
found_bins = set()
for w in pw._iter_words():
    if w in bins:
        found_bins.add(w)
        if len(found_bins) == len(bins):
            break
assert found_bins == bins, sorted(bins - found_bins)
print("PIN numerique (256/256) et mot de passe binaire (8/8) : toutes les combinaisons sont dans le dictionnaire OK")

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

# ---- attaques en tache de fond (vraie boucle, vraie progression, vrai arret) ----
section("Attacks (tache de fond)")
import time as _time2

# cas instantane (binaire) : termine quasi immediatement, meme resultat que pw.brute_force
# (le thread tourne reellement en arriere-plan -- meme pour un cas minuscule, on attend
# qu'il se termine plutot que de supposer qu'il l'est deja au retour de l'appel)
r = attacks.start_bruteforce("101", "binaire")
for _ in range(200):
    if r.snapshot()["done"]:
        break
    _time2.sleep(0.005)
assert r.done and r.result["cracked"] and r.result["rank"] == 6, r.result
print("force brute instantanee (binaire) : meme resultat qu'en synchrone OK")

# dictionnaire : vraie boucle reelle (pas de saut), meme resultat que pw.dictionary_attack
r = attacks.start_dictionary("azerty", lang="fr")
for _ in range(100):
    s = r.snapshot()
    if s["done"]:
        break
    _time2.sleep(0.02)
assert s["done"] and s["result"]["found"] and s["result"]["position"] == 1, s
assert s["pos"] > 0 and s["elapsed"] >= 0, s                    # la progression a vraiment avance
print("dictionnaire en tache de fond : trouve 'azerty' #1, memes chiffres qu'en synchrone OK")

# grand espace complexe : ca boucle reellement (pos augmente), et "Interrompre" arrete
# VRAIMENT le thread (pas seulement l'affichage) -- la cible est hors de portee en
# un instant donc l'attaque est encore en cours quand on va regarder
r = attacks.start_bruteforce("Zz9!Zz9!Zz9!", "complexe", length=12)
_time2.sleep(0.2)
s1 = r.snapshot()
assert not s1["done"] and s1["pos"] > 0, s1
assert attacks.stop(r.id)
_time2.sleep(0.3)
s2 = r.snapshot()
assert s2["done"], s2                                            # le thread s'est bien arrete
pos_apres_stop = s2["pos"]
_time2.sleep(0.2)
assert r.snapshot()["pos"] == pos_apres_stop                     # et ne continue pas en arriere-plan
print("force brute complexe : boucle reelle + Interrompre coupe vraiment le thread OK")

# identifiant inconnu -> None (traduit par l'API en erreur "introuvable")
assert attacks.get("xxx") is None and not attacks.stop("xxx")
print("identifiant d'attaque inconnu gere proprement OK")

# l'ordre de lecture change avec la langue de l'interface, pas le total parcouru
assert pw._dict_order("fr")[:2] == ["francais", "anglais"]
assert pw._dict_order("en")[:2] == ["anglais", "francais"]
assert set(pw._dict_order("fr")) == set(pw._dict_order("en")) == set(pw._LANG_FILES)
print("ordre du dictionnaire selon la langue de l'interface (meme total parcouru) OK")

# ---- boucles natives (C) : disponibles ici, et memes resultats que le repli Python ----
import native_attacks as native
assert native.available(), "gcc indisponible dans cet environnement de test"
rate = native.calibrate()
assert rate > 0
print(f"boucle C compilee et calibree ({rate:,.0f} essais/s) OK".replace(",", " "))

# force brute : meme rang trouve par le C (via attacks.py) et par rank_of (formule exacte)
r = attacks.start_bruteforce("tst9", "complexe", length=4, know_composition=True)
for _ in range(200):
    if r.snapshot()["done"]:
        break
    _time2.sleep(0.01)
assert r.done and r.result["native"] is True
cs = pw.detected_charset("tst9")
assert r.result["rank"] == pw.rank_of("tst9", cs, 4)
print("force brute (C) : rang identique a la formule exacte OK")

# dictionnaire : meme resultat (position, trouve) que l'ancienne boucle Python pure
r_native = attacks.start_dictionary("bonjour", lang="fr")
for _ in range(200):
    if r_native.snapshot()["done"]:
        break
    _time2.sleep(0.01)
assert r_native.done and r_native.result["native"] is True

pos_py = 0
found_py = False
for w in pw._iter_words("fr"):
    pos_py += 1
    if w == "bonjour":
        found_py = True
        break
assert r_native.result["found"] == found_py
assert r_native.result["position"] == pos_py
print("dictionnaire (C) : meme position que la boucle Python de reference OK")

# interruption : fonctionne aussi pour la boucle C du dictionnaire (gros dictionnaire,
# cible absente -> on l'arrete en plein vol)
r_stop = attacks.start_dictionary("mot-de-passe-qui-nexiste-vraiment-pas-xyz", lang="fr")
_time2.sleep(0.05)
assert attacks.stop(r_stop.id)
for _ in range(200):
    if r_stop.snapshot()["done"]:
        break
    _time2.sleep(0.01)
assert r_stop.done
print("dictionnaire (C) : Interrompre coupe vraiment le thread OK")

# ---- integrity ----
section("Integrity")
tag = integrity.sign("sharedkey", "Transfer 100")
assert integrity.verify("sharedkey", "Transfer 100", tag)
assert not integrity.verify("sharedkey", "Transfer 900", tag)
dm = integrity.demo("sharedkey", "Transfer 100", "Transfer 900")
assert dm["tampered"] and not dm["valid"]
print("HMAC sign/verify + tamper detection OK")

# ---- canal A -> B reel (chiffre + etiquette sur le clair) ----
msg = "Transfer 100 to B"
sealed = integrity.seal("sharedkey", msg)
assert sealed["record"]["method"] in ("caesar", "playfair", "hill")
assert sealed["record"]["secret"] != msg                      # vraiment chiffre

# non altere, protection ON -> intact
r = integrity.open_channel("sharedkey", sealed["record"], True, sealed["tag"])
assert r["decrypted"] == msg and r["valid"] is True and not r["broken"]

# non altere, protection OFF -> affiche quand meme, mais pas de verdict
r = integrity.open_channel("sharedkey", sealed["record"], False, sealed["tag"])
assert r["decrypted"] == msg and r["valid"] is None and not r["broken"]

# C altere un caractere du chiffre : le dechiffre change forcement
# (premier caractere, jamais un filler de bourrage Playfair/Hill ajoute en fin de
# bloc -- sinon l'alteration serait parfois strip_fillers()-ee sans effet visible,
# un faux negatif aleatoire selon l'algo tire au hasard)
tampered = dict(sealed["record"])
s = tampered["secret"]
tampered["secret"] = ("A" if s[0] != "A" else "B") + s[1:]

r_on = integrity.open_channel("sharedkey", tampered, True, sealed["tag"])
assert r_on["decrypted"] != msg and r_on["valid"] is False and not r_on["broken"]

r_off = integrity.open_channel("sharedkey", tampered, False, sealed["tag"])
assert r_off["decrypted"] == r_on["decrypted"] and r_off["valid"] is None   # affiche sans verification -> la faille

# chiffre Hill tronque (longueur qui n'est plus un multiple du bloc) -> echec propre, pas de crash
hrecord = auth.encipher(msg, "hill", auth.random_key("hill"))
htag = integrity.sign("sharedkey", msg)
broken = dict(hrecord)
broken["secret"] = broken["secret"][:-1]
r_broken = integrity.open_channel("sharedkey", broken, True, htag)
assert r_broken["broken"] and r_broken["decrypted"] is None
print("canal A->B reel : chiffre+etiquette sur le clair, alteration detectee, protection off = faille demontree OK")

# chiffrement DESACTIVE (encrypt=False) : le message voyage en clair, mais l'etiquette
# HMAC protege quand meme l'integrite independamment du chiffrement
s_clair = integrity.seal("sharedkey", msg, encrypt=False)
assert s_clair["record"]["method"] is None and s_clair["record"]["secret"] == msg
r_clair = integrity.open_channel("sharedkey", s_clair["record"], True, s_clair["tag"])
assert r_clair["decrypted"] == msg and r_clair["valid"] is True
tampered_clair = dict(s_clair["record"])
tampered_clair["secret"] = msg.replace("100", "900")
assert integrity.open_channel("sharedkey", tampered_clair, True, s_clair["tag"])["valid"] is False
print("canal A->B : chiffrement desactivable independamment de la protection HMAC OK")

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
# Chiffre puis déchiffre `msg` via l'API et renvoie les deux réponses JSON.
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
# Comme _roundtrip mais en transmettant aussi la casse (`cases`) au déchiffrement.
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

# attaques en tache de fond, par l'API : start -> progress (polling) -> stop
r = c.post("/api/passwords/attack/start", json={"kind": "brute", "case": "binaire", "target": "101"}).json()
rid = r["id"]
for _ in range(200):
    r = c.get(f"/api/passwords/attack/progress/{rid}").json()
    if r["done"]:
        break
    _time2.sleep(0.005)
assert r["ok"] and r["done"] and r["result"]["cracked"] and r["result"]["rank"] == 6, r

r = c.post("/api/passwords/attack/start", json={"kind": "dict", "target": "azerty", "lang": "fr"}).json()
assert r["ok"] and r["id"], r
rid = r["id"]
for _ in range(100):
    p = c.get(f"/api/passwords/attack/progress/{rid}").json()
    if p["done"]:
        break
    _time2.sleep(0.02)
assert p["ok"] and p["done"] and p["result"]["found"] and p["result"]["position"] == 1, p

r = c.post("/api/passwords/attack/start",
           json={"kind": "brute", "case": "complexe", "target": "Qw8!Qw8!Qw8!", "length": 12}).json()
rid = r["id"]
_time2.sleep(0.2)
p = c.get(f"/api/passwords/attack/progress/{rid}").json()
assert p["ok"] and not p["done"] and p["pos"] > 0, p                 # bien en cours, vraie progression
st = c.post(f"/api/passwords/attack/stop/{rid}").json()
assert st["ok"] and st["stopped"], st
_time2.sleep(0.2)
assert c.get(f"/api/passwords/attack/progress/{rid}").json()["done"]  # le thread s'est vraiment arrete

assert not c.get("/api/passwords/attack/progress/xxx").json()["ok"]   # identifiant inconnu
print("attaques en tache de fond (start/progress/stop) : vraie progression, vrai arret OK")

# integrite (P4) : canal reel seal/open, par l'API
sl = c.post("/api/integrity/seal", json={"key": "sharedkey", "message": "Transfer 100"}).json()
assert sl["ok"] and sl["record"]["secret"] != "Transfer 100"

op = c.post("/api/integrity/open",
            json={"key": "sharedkey", "record": sl["record"], "protect": True, "tag": sl["tag"]}).json()
assert op["ok"] and op["decrypted"] == "Transfer 100" and op["valid"] is True

rec2 = dict(sl["record"])
sec = rec2["secret"]
rec2["secret"] = sec[:-1] + ("A" if sec[-1] != "A" else "B")
op_on = c.post("/api/integrity/open",
               json={"key": "sharedkey", "record": rec2, "protect": True, "tag": sl["tag"]}).json()
assert op_on["ok"] and op_on["valid"] is False
op_off = c.post("/api/integrity/open",
                json={"key": "sharedkey", "record": rec2, "protect": False, "tag": sl["tag"]}).json()
assert op_off["ok"] and op_off["valid"] is None and op_off["decrypted"] == op_on["decrypted"]
print("integrite (P4) : seal/open par l'API, chiffre altere detecte avec protection, invisible sans OK")

print("All endpoints OK")

# ---- fichiers : historique des chiffrements + conversation A <-> B ----
section("Fichiers (historique + conversation)")
import json, os, tempfile
import storage
_tmp = tempfile.TemporaryDirectory()
os.environ["DATA_DIR"] = _tmp.name          # on n'écrit jamais dans backend/data/ pendant les tests
H = os.path.join(_tmp.name, storage.HISTORY_FILE)
V = os.path.join(_tmp.name, storage.CONVERSATION_FILE)

# Fabrique une entrée d'historique de chiffrement pour les tests.
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
# Fabrique une entrée d'historique d'attaque de mot de passe pour les tests.
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

# ---- connexion : comptes, sessions, captchas, protection de l'API ----
section("Connexion")
import time as _time
import auth, captcha, db
os.environ.pop("TP_AUTH_OFF", None)
os.environ["USERS_DB"] = os.path.join(tempfile.mkdtemp(), "users.db")         # base de test, pas la vraie
auth.reset_limits()
PW = "Mot-de-passe-de-test-42"
auth.set_password("alice", PW)
# chiffrement des mots de passe : réversible, un algorithme et une clé au hasard, jamais de hachage
import random as _random
_rnd = _random.Random(7)
_alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?#@$%&*-_."
for method in auth.METHODS:
    for _ in range(300):
        pwd = "".join(_rnd.choice(_alpha) for _ in range(_rnd.randint(1, 24)))
        key = auth.random_key(method)
        rec = auth.encipher(pwd, method, key)
        rec["method"] = method
        assert auth.decipher(rec) == pwd, (method, pwd, key)                                # aller-retour exact (J, X, minuscules, symboles)
        assert auth.verify_password(pwd, rec) and not auth.verify_password(pwd + "a", rec)
        assert rec["secret"] == "" or (rec["secret"].isalpha() and rec["secret"].isupper())  # le secret : lettres majuscules seulement
for pwd in ("Jaja-XXQ-jj1!", "xx", "ZZ9", "Ab1!Ab1!"):                                      # cas piégeux : J, X, doubles lettres
    for method in auth.METHODS:
        rec = auth.encipher(pwd, method, auth.random_key(method))
        assert auth.decipher(rec) == pwd, (method, pwd)
seen_methods = {auth.make_record("Abcdef1!")["method"] for _ in range(80)}
assert seen_methods == set(auth.METHODS), seen_methods                                       # le tirage utilise bien les trois
r1, r2 = auth.make_record(PW), auth.make_record(PW)
assert r1["secret"] != PW.upper() and auth.decipher(r1) == PW
row = db.get_user("ALICE")                                                                  # base : nom insensible à la casse
assert row["username"] == "alice" and row["method"] in auth.METHODS and row["secret"].isalpha()
assert auth.decipher(row) == PW and not auth.verify_password("faux", row)
assert not auth.verify_password("Mot-de-passe-de-test-é2", row)                              # accents refusés sans erreur
if db.PG:                                                                                     # base Postgres (DATABASE_URL) : même vérif, dans la table
    with db.closing(db._connect()) as _con:
        raw = repr(_con.execute(db._q("SELECT * FROM users")).fetchall()).encode()
else:
    raw = open(os.environ["USERS_DB"], "rb").read()                                          # base SQLite : le fichier
assert PW.encode() not in raw and b"Motdepassedetest" not in raw                             # le mot de passe n'est pas en clair dans la base
assert "pbkdf2" not in open("auth.py", encoding="utf-8").read().lower()                  # aucun hachage de mot de passe
# tentatives : au plus 4 mots de passe erronés de suite, PAR COUPLE (compte, IP)
IP1, IP2 = "1.2.3.4", "9.9.9.9"
assert auth.attempt_login("Alice", PW, IP1) == ("alice", auth.MAX_ATTEMPTS)
assert auth.attempt_login("alice", "x1", IP1)[1] == 3 and auth.attempt_login("alice", "x2", IP1)[1] == 2
assert auth.attempt_login("alice", PW, IP1)[0] == "alice"                      # une réussite remet à zéro
assert [auth.attempt_login("alice", "x", IP1)[1] for _ in range(4)] == [3, 2, 1, 0]
assert auth.is_blocked("alice", IP1) and db.unlock("alice") and not auth.is_blocked("alice", IP1)
assert [auth.attempt_login("inconnu", "x", IP1)[1] for _ in range(4)] == [3, 2, 1, 0] and auth.is_blocked("inconnu", IP1)   # mêmes réponses pour un nom inconnu
auth.reset_limits()
# le blocage est scopé par IP : une autre IP sur le MÊME compte n'est pas affectée
assert [auth.attempt_login("alice", "x", IP1)[1] for _ in range(4)] == [3, 2, 1, 0]
assert auth.is_blocked("alice", IP1) and not auth.is_blocked("alice", IP2)                        # IP2 jamais essayée : pas bloquée
assert auth.attempt_login("alice", PW, IP2)[0] == "alice"                                          # ... et peut se connecter avec le bon mot de passe
assert db.unlock("alice") and not auth.is_blocked("alice", IP1)                                    # --unlock débloque toutes les IP d'un coup
auth.reset_limits()
print("blocage par couple (compte, IP) : une IP bloquée n'affecte pas les autres OK")
# inscription : nom, règles du mot de passe, doublon
assert auth.password_problem("Abcdef1!") is None and auth.password_problem("A1!aaaaa") is None
for bad in ("Abc1!", "abcdefg1!", "ABCDEFG1!", "Abcdefgh!", "Abcdefg12", "Abcdé1!x", "Abc def1!", "A" * 70 + "a1!"):
    assert auth.password_problem(bad), bad
assert auth.register("ab", "Abcdef1!") == (None, "username") and auth.register("bad name", "Abcdef1!") == (None, "username")
assert auth.register("carol", "faible") == (None, "policy")
assert auth.register("Carol", "Abcdef1!") == ("Carol", None) and auth.register("CAROL", "Abcdef1!") == (None, "exists")
assert auth.attempt_login("carol", "Abcdef1!", IP1)[0] == "Carol"
print(f"chiffrement des mots de passe (3 algos, tirage aléatoire, aller-retour) · base {'PostgreSQL' if db.PG else 'SQLite'} · 4 tentatives par IP · inscription OK")

# jeton de session : signé, expirant, falsifiable impossible, fermable
tok = auth.make_token("alice")
assert auth.read_token(tok) == "alice"
assert auth.read_token(tok + "0") is None and auth.read_token("a.b.c") is None and auth.read_token("") is None
u64, exp, jti, sig = tok.split(".")
assert auth.read_token(f"{u64}.{int(exp) + 999999}.{jti}.{sig}") is None                              # date prolongée à la main
assert auth.read_token(tok, now=_time.time() + auth.SESSION_SECONDS + 5) is None               # expiré
assert auth.read_token(auth.make_token("bob")) is None                                          # compte inexistant
auth.revoke_token(tok)
assert auth.read_token(tok) is None
print("jeton signé, expirant, révocable OK")

# captchas : chaque sorte, usage unique, expiration, preuve de travail, trop rapide
seen = set()
for _ in range(40):
    ch = captcha.new_challenge()
    seen.add(ch["kind"])
    assert "answer" not in ch and "text" not in ch and "slot" not in ch and "secret" not in ch, ch.keys()
assert seen == set(captcha.KINDS), seen
last = captcha.new_challenge()["kind"]
assert all(captcha.new_challenge(exclude=last)["kind"] != last for _ in range(30))              # jamais deux fois la même sorte
# Donne la bonne réponse d'un captcha (via le back-door de test) et, si wait=True,
# vieillit artificiellement le défi pour passer le contrôle « trop rapide ».
def solved(ch, answer=None, wait=True):
    a = captcha._answer_for_tests(ch["id"])
    if wait:
        captcha._store[ch["id"]]["born"] -= 60                                                # « le temps a passé »
    return answer if answer is not None else (a["slot"] if a["kind"] == "shuffle" else a["text"])
for k in captcha.KINDS:
    while True:
        ch = captcha.new_challenge()
        if ch["kind"] == k:
            break
    nonce = captcha.solve_pow(ch["pow"]["challenge"], ch["pow"]["bits"])
    assert captcha.verify(ch["id"], solved(ch), nonce) == "ok", k
    assert captcha.verify(ch["id"], "x", nonce) == "unknown"                                      # usage unique
    ch = captcha.new_challenge(); nonce = captcha.solve_pow(ch["pow"]["challenge"], ch["pow"]["bits"])
    bad = solved(ch, "ZZZZ" if captcha._answer_for_tests(ch["id"])["kind"] != "shuffle" else 99)
    assert captcha.verify(ch["id"], bad, nonce) == "wrong"                                        # mauvaise réponse : détruit aussi
    assert captcha.verify(ch["id"], bad, nonce) == "unknown"
ch = captcha.new_challenge(); good = solved(ch)
assert captcha.verify(ch["id"], good, 0) == "pow"                                               # sans travail
ch = captcha.new_challenge(); good = solved(ch, wait=False); nonce = captcha.solve_pow(ch["pow"]["challenge"], ch["pow"]["bits"])
assert captcha.verify(ch["id"], good, nonce) == "fast"                                         # plus vite qu'un humain
ch = captcha.new_challenge(); good = solved(ch)
assert captcha.verify(ch["id"], good, 0, now=_time.time() + captcha.TTL + 5) == "expired"
ch = captcha.new_challenge(); assert captcha.discard(ch["id"]) and not captcha.discard(ch["id"]) and captcha.verify(ch["id"], "x", 0) == "unknown"   # abandonné = détruit
assert captcha.new_challenge(extra_bits=3)["pow"]["bits"] == captcha.POW_BASE_BITS + 3
assert captcha.new_challenge(extra_bits=99)["pow"]["bits"] == captcha.POW_MAX_BITS == captcha.POW_BASE_BITS + 6
print("3 captchas : réponse jamais envoyée · usage unique · expiration · preuve de travail · trop rapide OK")

# l'API : fermée sans session, ouverte avec
anon = TestClient(app)
assert anon.get("/api/history").status_code == 401 and anon.post("/api/cipher", json={}).status_code == 401
assert anon.get("/api/health").status_code == 200
st = anon.get("/api/auth/status").json()
assert st["authenticated"] is False and st["auth_required"] is True and st["configured"] is True
# Effectue une connexion complète via l'API : récupère un captcha, résout sa preuve
# de travail, puis poste /api/auth/login. Renvoie la réponse HTTP.
def login(cl, user=PW and "alice", pwd=PW, answer=None, human=None, nonce_ok=True, wait=True):
    chj = cl.get("/api/auth/captcha").json()["challenge"]
    nonce = captcha.solve_pow(chj["pow"]["challenge"], chj["pow"]["bits"]) if nonce_ok else 0
    ans = solved(chj, answer, wait)
    return cl.post("/api/auth/login", json={"username": user, "password": pwd, "captcha_id": chj["id"], "answer": ans,
                                            "nonce": nonce, "human": human or {"ms": 4000, "events": 9}})
r = login(anon, answer="ZZZZ" if False else None, pwd="mauvais")
assert r.status_code == 401 and r.json()["error"] == "credentials" and "incorrect" in r.json()["message"]
r2 = login(anon, user="inconnu")
assert r2.status_code == 401 and r2.json()["message"] == r.json()["message"]                  # même message : pas d'indice sur les noms
r = anon.post("/api/auth/login", json={"username": "alice", "password": PW, "captcha_id": "nimporte", "answer": "x", "nonce": 1,
                                       "human": {"ms": 4000, "events": 9}})
assert r.status_code == 400 and r.json()["reason"] == "unknown"
r = login(anon, human={"ms": 200, "events": 0})
assert r.status_code == 400 and r.json()["reason"] == "robot"                                   # aucun geste, aucun temps
auth.reset_limits()
r = login(anon)
assert r.status_code == 200 and r.json()["user"] == "alice", r.text
ck = r.headers["set-cookie"]
assert "HttpOnly" in ck and "SameSite=lax" in ck and "tp_session=" in ck, ck
assert anon.get("/api/history").status_code == 200
assert anon.get("/api/auth/status").json()["user"] == "alice"
anon.post("/api/auth/logout")
assert anon.get("/api/history").status_code == 401                                              # session fermée
stolen = TestClient(app); stolen.cookies.set("tp_session", tok := auth.make_token("alice"))
assert stolen.get("/api/history").status_code == 200
auth.revoke_token(tok)
assert stolen.get("/api/history").status_code == 401                                            # jeton révoqué
forged = TestClient(app); forged.cookies.set("tp_session", "YWxpY2U.9999999999.aabbcc.deadbeef")
assert forged.get("/api/history").status_code == 401
print("API fermée sans session · cookie HttpOnly · déconnexion · jeton révoqué/falsifié refusés OK")

# trop d'essais : 4 mots de passe erronés → compte bloqué, même avec le bon mot de passe
auth.reset_limits()
bf = TestClient(app)
got = []
for i in range(3):
    r = login(bf, pwd="faux" + str(i))
    assert r.status_code == 401 and r.json()["error"] == "credentials", r.text
    got.append(r.json()["remaining"])
assert got == [3, 2, 1], got
r = login(bf, pwd="faux4")                                                                     # la 4e erreur bloque
assert r.status_code == 423 and r.json()["error"] == "blocked", r.text
r = login(bf, pwd=PW)                                                                          # même avec le BON mot de passe
assert r.status_code == 423 and r.json()["error"] == "blocked", r.text
assert db.is_attempt_blocked("alice", "testclient")                                             # bloqué pour l'IP du TestClient
r = login(bf, user="inconnu", pwd="x")                                                          # nom inconnu : même parcours
assert r.status_code == 401 and r.json()["remaining"] == 3
auth.reset_limits()                                                                            # (la limite par IP est un autre garde-fou)
# une AUTRE adresse (X-Forwarded-For) n'est pas bloquée : elle peut se connecter avec le bon mot de passe
other = TestClient(app, headers={"X-Forwarded-For": "5.6.7.8"})
assert login(other).status_code == 200
other.post("/api/auth/logout")
assert db.unlock("alice") and login(bf).status_code == 200                                      # --unlock débloque TOUTES les IP : la connexion marche aussi pour bf
print("blocage après", auth.MAX_ATTEMPTS, "mots de passe erronés, PAR IP (une autre IP n'est pas affectée) OK")

# inscription par l'API : défi + règles du mot de passe + doublon, puis connexion
auth.reset_limits()
rc = TestClient(app)
# Même principe que login(), mais poste /api/auth/register (inscription).
def register(cl, user, pwd, human=None):
    chj = cl.get("/api/auth/captcha").json()["challenge"]
    nonce = captcha.solve_pow(chj["pow"]["challenge"], chj["pow"]["bits"])
    ans = solved(chj, None, True)
    return cl.post("/api/auth/register", json={"username": user, "password": pwd, "captcha_id": chj["id"], "answer": ans,
                                               "nonce": nonce, "human": human or {"ms": 4000, "events": 9}})
r = register(rc, "bob", "faible")
assert r.status_code == 400 and r.json()["error"] == "policy" and "au moins" in r.json()["message"], r.text
r = register(rc, "bob", "Abcdef1!", human={"ms": 100, "events": 0})
assert r.status_code == 400 and r.json()["reason"] == "robot"                                   # même garde-fou que la connexion
r = register(rc, "bo", "Abcdef1!")
assert r.status_code == 400 and r.json()["error"] == "username"
r = register(rc, "bob", "Abcdef1!")
assert r.status_code == 201 and r.json()["user"] == "bob" and "set-cookie" not in r.headers, r.text
assert register(rc, "BOB", "Abcdef1!").status_code == 409                                       # doublon (casse ignorée)
assert rc.get("/api/history").status_code == 401                                                # s'inscrire ne connecte pas
assert login(rc, user="bob", pwd="Abcdef1!").status_code == 200 and rc.get("/api/history").status_code == 200
assert auth.decipher(db.get_user("bob")) == "Abcdef1!"
print("inscription (API) : défi, règles du mot de passe, doublon, connexion ensuite OK")
os.environ["TP_AUTH_OFF"] = "1"
auth.reset_limits()

print("\nALL BACKEND TESTS PASSED")
