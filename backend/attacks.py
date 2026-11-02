"""
Exécution RÉELLE des attaques, en tâche de fond.

Avant ce module, la force brute « cas complexe » et le dictionnaire étaient
calculés d'un coup (rang exact par formule, ou boucle Python qui finit en une
poignée de secondes) : le serveur répondait tout de suite, et la barre de
progression du frontend n'était qu'une ANIMATION rejouée après coup, à la
vitesse fictive d'un attaquant (10 milliards d'essais/s).

Ici, un clic démarre un vrai thread qui boucle à la vitesse RÉELLE de cette
machine : la boucle tourne en C compilé (native_attacks.py) quand gcc est
disponible, avec repli automatique sur une boucle Python ; la progression est un
compteur partagé relu par polling ; « Interrompre » coupe vraiment la boucle.

passwords.py garde tout le calcul « pur » (espace, rang, dictionnaire,
estimations théoriques) ; ce module ne fait que le faire tourner pour de vrai.
"""
import ctypes
import itertools
import threading
import time
import uuid
from typing import Any, Dict, Optional

import passwords as pw
import native_attacks as native

_lock = threading.Lock()
_runs: Dict[str, "Run"] = {}
_MAX_AGE = 600           # une attaque terminée est oubliée 10 min après sa fin
_CHECK_EVERY = 4000       # fréquence de mise à jour du compteur / contrôle d'arrêt (repli Python)


# Une attaque en cours (ou terminée) : son état partagé entre le thread qui
# calcule et les requêtes de progression.
class Run:

    # Initialise un identifiant unique et l'état de départ de l'attaque.
    def __init__(self):
        self.id = uuid.uuid4().hex
        self.pos = 0
        self.total = 1
        self.done = False
        self.result: Optional[Dict[str, Any]] = None
        self.started = time.time()
        self.finished_at: Optional[float] = None
        self.stop_event = threading.Event()
        self.native_stop = None     # ctypes.c_int() si la boucle C est en cours (voir stop())

    # Photographie de l'état courant pour la réponse HTTP (position, vitesse, résultat).
    def snapshot(self) -> Dict[str, Any]:
        elapsed = (self.finished_at or time.time()) - self.started
        rate = self.pos / elapsed if elapsed > 0 else 0.0
        return {
            "ok": True, "id": self.id, "pos": self.pos, "total": self.total,
            "done": self.done, "elapsed": elapsed, "rate": rate, "result": self.result,
        }


# Oublie les attaques terminées depuis plus de _MAX_AGE (à appeler sous _lock).
def _prune_locked():
    now = time.time()
    dead = [rid for rid, r in _runs.items() if r.done and r.finished_at and now - r.finished_at > _MAX_AGE]
    for rid in dead:
        _runs.pop(rid, None)


# Enregistre une attaque dans le registre global après un nettoyage des anciennes.
def _register(run: Run) -> None:
    with _lock:
        _prune_locked()
        _runs[run.id] = run


# Retrouve une attaque par son identifiant (None si inconnue ou oubliée).
def get(run_id: str) -> Optional[Run]:
    return _runs.get(run_id)


_POLL_NATIVE = 0.05   # fréquence à laquelle on recopie le compteur C -> run.pos


# Lance `fn` (un appel C bloquant) en recopiant pos_cell.value -> run.pos
# pendant ce temps. L'appel C relâche le GIL, donc ce thread tourne vraiment en
# même temps que la boucle C et la progression reste visible par polling HTTP.
def _run_native(run: Run, pos_cell, fn):
    stop_poll = threading.Event()

    def poller():
        while not stop_poll.wait(_POLL_NATIVE):
            run.pos = pos_cell.value

    t = threading.Thread(target=poller, daemon=True)
    t.start()
    try:
        return fn()
    finally:
        stop_poll.set()
        t.join()
        run.pos = pos_cell.value


# Coupe vraiment le thread de calcul (pas seulement l'affichage), que la boucle
# tourne en C ou, en repli, en pur Python.
def stop(run_id: str) -> bool:
    run = _runs.get(run_id)
    if run is None:
        return False
    run.stop_event.set()
    if run.native_stop is not None:
        run.native_stop.value = 1
    return True


# Remplit run.result à la fin d'une force brute : construit le verdict (trouvé /
# cassé), la durée RÉELLE écoulée et les estimations théoriques de passwords.py.
def _finish_brute(run: Run, rank, limit, charset, length, label, space, check, really_looped):
    run.finished_at = time.time()
    cracked = check["valid"] and rank is not None and (limit is None or rank <= int(limit))
    rate_ref = native.calibrate()
    est = pw.estimate_for(len(charset), length, rate_ref)
    elapsed = run.finished_at - run.started
    if rank is not None:
        find_human, find_strength = pw.human_time(elapsed)
    else:
        find_human, find_strength = None, None
    run.result = {
        "valid": check["valid"], "reasons": check["reasons"],
        "charset": charset, "charsetSize": len(charset), "length": length, "label": label,
        "keyspace": float(space) if space < 1e300 else None, "keyspaceText": pw.fmt_count(space),
        "rate": rate_ref, "rateText": pw.fmt_rate(rate_ref),
        "worstCaseSeconds": est["seconds"], "worstCaseHuman": est["human"], "strength": est["strength"],
        "rank": rank, "findSeconds": elapsed if rank is not None else None,
        "findHuman": find_human, "findStrength": find_strength,
        "reallyLooped": really_looped, "limit": int(limit) if limit is not None else None,
        "cracked": cracked, "native": native.available(), "nativeReason": native.reason(),
    }
    run.done = True


# Démarre une attaque par force brute dans un thread de fond et renvoie son Run.
# Si l'attaquant connaît la composition du mot de passe (cas complexe), il
# restreint son jeu de caractères au jeu détecté ; sinon il garde le jeu complet.
def start_bruteforce(target, case, length=None, limit=None, rules=None, know_composition=True) -> Run:
    run = Run()
    charset, length_r, label = pw._resolve_case(case, length)
    check = pw.validate(target, case, length_r, rules)

    if case == "complexe" and know_composition:
        detected = pw.detected_charset(target)
        if detected:
            charset = detected

    space = pw.keyspace(charset, length_r)
    run.total = space
    _register(run)

    if not check["valid"]:
        _finish_brute(run, None, limit, charset, length_r, label, space, check, really_looped=False)
        return run

    # Corps du thread : boucle C quand elle est dispo (et longueur gérable),
    # sinon repli sur itertools.product en pur Python ; les deux remontent le
    # rang du mot de passe trouvé (ou None).
    def work():
        rank = None
        if native.available() and 0 < length_r <= 64:
            pos_cell = ctypes.c_longlong(0)
            stop_cell = ctypes.c_int(0)
            run.native_stop = stop_cell
            found, _interrupted, rank_val = _run_native(
                run, pos_cell, lambda: native.brute_search(charset, length_r, target, limit, pos_cell, stop_cell)
            )
            rank = rank_val if found else None
        else:
            attempts = 0
            for combo in itertools.product(charset, repeat=length_r):
                attempts += 1
                if attempts % _CHECK_EVERY == 0:
                    run.pos = attempts
                    if run.stop_event.is_set():
                        break
                if limit is not None and attempts > int(limit):
                    attempts -= 1
                    break
                if "".join(combo) == target:
                    rank = attempts
                    break
            run.pos = attempts
        _finish_brute(run, rank, limit, charset, length_r, label, space, check, really_looped=True)

    threading.Thread(target=work, daemon=True).start()
    return run


# Démarre une attaque par dictionnaire dans un thread de fond et renvoie son Run.
def start_dictionary(target, limit=None, lang="fr") -> Run:
    run = Run()
    run.total = pw.dictionary_size()
    _register(run)

    # Corps du thread : trois chemins possibles — scan en C fichier par fichier,
    # repli sur la petite liste codée en dur, ou boucle Python mot à mot.
    def work():
        pos = 0
        found = False
        stopped = False
        paths = pw._dict_paths(lang)

        if native.available() and paths:
            # Chaque fichier est décompressé en mémoire (un seul à la fois) puis
            # scanné en C. Le buffer est normalisé en UTF-8 car le C compare des
            # octets et `target` est en UTF-8.
            stop_cell = ctypes.c_int(0)
            run.native_stop = stop_cell
            pos_cell = ctypes.c_longlong(0)
            for path, enc in paths:
                opener = pw.gzip.open if path.endswith(".gz") else open
                with opener(path, "rb") as f:
                    raw = f.read()
                if enc != "utf-8":
                    raw = raw.decode(enc, errors="replace").encode("utf-8")
                found_here, interrupted, rank_here, scanned_here = _run_native(
                    run, pos_cell, lambda: native.dict_search_buffer(raw, target, limit, pos, pos_cell, stop_cell)
                )
                pos += scanned_here
                if found_here:
                    found = True
                    break
                if interrupted:
                    break
                if limit is not None and pos >= int(limit):
                    stopped = True
                    break
            else:
                # for..else : tous les fichiers parcourus sans "break" -> on scanne
                # le complément ajouté à la main (dictionnaire_extra.txt), TOUJOURS
                # en dernier, même ordre que pw._iter_words() / pw.dictionary_size().
                extra_words = list(pw._extra_words())
                if extra_words:
                    raw = ("\n".join(extra_words) + "\n").encode("utf-8")
                    found_here, interrupted, rank_here, scanned_here = _run_native(
                        run, pos_cell, lambda: native.dict_search_buffer(raw, target, limit, pos, pos_cell, stop_cell)
                    )
                    pos += scanned_here
                    if found_here:
                        found = True
                    elif limit is not None and pos >= int(limit):
                        stopped = True
        elif not paths:
            # repli ultime : la petite liste codée en dur (voir pw._FALLBACK)
            for w in pw._FALLBACK:
                pos += 1
                if w == target:
                    found = True
                    break
                if limit is not None and pos >= int(limit):
                    stopped = True
                    break
        else:
            # repli : boucle pure Python (si gcc est indisponible)
            for w in pw._iter_words(lang):
                pos += 1
                if limit is not None and pos > int(limit):
                    pos -= 1
                    stopped = True
                    break
                if pos % _CHECK_EVERY == 0:
                    run.pos = pos
                    if run.stop_event.is_set():
                        break
                if w == target:
                    found = True
                    break

        run.pos = pos
        run.finished_at = time.time()
        run.result = {
            "found": found, "stopped": stopped,
            "password": target if found else None,
            "position": pos if found else None,
            "scanned": pos, "size": run.total,
            "limit": int(limit) if limit is not None else None,
            "native": native.available(), "nativeReason": native.reason(),
        }
        run.done = True

    threading.Thread(target=work, daemon=True).start()
    return run
