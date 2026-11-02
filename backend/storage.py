# -*- coding: utf-8 -*-
"""
Stockage dans des fichiers (pas de base de données).

Quatre fichiers JSON, rangés dans le dossier `backend/data/` (ou dans celui donné
par la variable d'environnement DATA_DIR) :

  historique_chiffrements.json   l'historique des chiffrements / déchiffrements
                                 de la partie « Chiffrer un message »
  historique_mots_de_passe.json  l'historique des attaques (force brute, dictionnaire)
                                 de la partie « Mots de passe »
  historique_integrite.json      l'historique des envois A -> B de la partie « Intégrité »
                                 (dont le taux de changement de l'étiquette)
  conversation_ab.json           la conversation entre A et B (partie « Échange »)

Les fichiers sont créés au premier enregistrement. Chaque écriture est atomique
(fichier temporaire puis remplacement) et protégée par un verrou : un plantage
ou deux requêtes simultanées ne peuvent pas laisser un fichier à moitié écrit.
"""
import datetime
import json
import os
import tempfile
import threading
from typing import Any, Dict, List, Optional

MAX_HISTORY = 200        # au-delà, les plus anciennes lignes sont oubliées
MAX_CONVERSATION = 500

HISTORY_FILE = "historique_chiffrements.json"
PW_HISTORY_FILE = "historique_mots_de_passe.json"
INTEGRITY_HISTORY_FILE = "historique_integrite.json"
CONVERSATION_FILE = "conversation_ab.json"

_lock = threading.RLock()


def data_dir() -> str:
    """Le dossier des fichiers (créé au besoin). Relu à chaque appel : les tests
    peuvent le rediriger avec DATA_DIR."""
    d = os.environ.get("DATA_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(d, exist_ok=True)
    return d


def _path(filename: str) -> str:
    return os.path.join(data_dir(), filename)


def _read(filename: str, default: Dict[str, Any]) -> Dict[str, Any]:
    path = _path(filename)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        return default
    except (OSError, ValueError):
        pass
    # fichier illisible : on le met de côté (jamais écrasé en silence) et on repart d'un fichier neuf
    try:
        os.replace(path, path + ".illisible")
    except OSError:
        pass
    return default


def _write(filename: str, data: Dict[str, Any]) -> None:
    path = _path(filename)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)   # atomique : l'ancien fichier reste intact jusqu'au dernier instant
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------ historique des chiffrements ----
# Format : {"version": 1, "next_id": 4, "entries": [ {id, at, op, clear, cipher, ...}, ... ]}
# `entries` est rangé du plus ancien au plus récent ; `next_id` ne revient jamais en
# arrière : un numéro supprimé n'est pas réattribué.

def _history_default() -> Dict[str, Any]:
    return {"version": 1, "next_id": 1, "entries": []}


def _entries_list(filename: str) -> List[Dict[str, Any]]:
    """Les lignes d'un fichier d'historique, la plus récente en premier."""
    with _lock:
        data = _read(filename, _history_default())
        return list(reversed(data.get("entries", [])))


def _entries_add(filename: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    with _lock:
        data = _read(filename, _history_default())
        entries = data.get("entries", [])
        next_id = max(int(data.get("next_id", 1)), max((e.get("id", 0) for e in entries), default=0) + 1)
        saved = {**entry, "id": next_id, "at": _now()}
        entries.append(saved)
        data.update(version=1, next_id=next_id + 1, entries=entries[-MAX_HISTORY:])
        _write(filename, data)
        return saved


def _entries_delete(filename: str, entry_id: int) -> bool:
    """Supprime UNE ligne. False si elle n'existe pas (déjà supprimée)."""
    with _lock:
        data = _read(filename, _history_default())
        entries = data.get("entries", [])
        kept = [e for e in entries if e.get("id") != entry_id]
        if len(kept) == len(entries):
            return False
        data["entries"] = kept
        _write(filename, data)
        return True


def _entries_clear(filename: str) -> int:
    """Supprime toutes les lignes (le compteur de numéros continue). Renvoie combien."""
    with _lock:
        data = _read(filename, _history_default())
        n = len(data.get("entries", []))
        data["entries"] = []
        _write(filename, data)
        return n


# historique des chiffrements
def history_list() -> List[Dict[str, Any]]:
    return _entries_list(HISTORY_FILE)


def history_add(entry: Dict[str, Any]) -> Dict[str, Any]:
    return _entries_add(HISTORY_FILE, entry)


def history_delete(entry_id: int) -> bool:
    return _entries_delete(HISTORY_FILE, entry_id)


def history_clear() -> int:
    return _entries_clear(HISTORY_FILE)


# historique des attaques sur mots de passe (même format, autre fichier)
def pw_history_list() -> List[Dict[str, Any]]:
    return _entries_list(PW_HISTORY_FILE)


def pw_history_add(entry: Dict[str, Any]) -> Dict[str, Any]:
    return _entries_add(PW_HISTORY_FILE, entry)


def pw_history_delete(entry_id: int) -> bool:
    return _entries_delete(PW_HISTORY_FILE, entry_id)


def pw_history_clear() -> int:
    return _entries_clear(PW_HISTORY_FILE)


# historique de la partie Intégrité : un envoi A -> B par ligne (même format, autre fichier)
def integrity_history_list() -> List[Dict[str, Any]]:
    return _entries_list(INTEGRITY_HISTORY_FILE)


def integrity_history_add(entry: Dict[str, Any]) -> Dict[str, Any]:
    return _entries_add(INTEGRITY_HISTORY_FILE, entry)


def integrity_history_delete(entry_id: int) -> bool:
    return _entries_delete(INTEGRITY_HISTORY_FILE, entry_id)


def integrity_history_clear() -> int:
    return _entries_clear(INTEGRITY_HISTORY_FILE)


# ----------------------------------------------------- conversation A ↔ B ----
# Format : {"version": 1, "messages": [ {id, at, from, plain, cipher, params}, ... ]}
# rangé dans l'ordre d'envoi.

def _conversation_default() -> Dict[str, Any]:
    return {"version": 1, "messages": []}


def conversation_list() -> List[Dict[str, Any]]:
    with _lock:
        return list(_read(CONVERSATION_FILE, _conversation_default()).get("messages", []))


def conversation_add(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Ajoute un message à la fin. Renvoie None si ce numéro est déjà enregistré
    (un envoi répété ne crée pas de doublon)."""
    with _lock:
        data = _read(CONVERSATION_FILE, _conversation_default())
        messages = data.get("messages", [])
        if any(m.get("id") == message.get("id") for m in messages):
            return None
        saved = {"id": message["id"], "at": _now(), **{k: v for k, v in message.items() if k != "id"}}
        messages.append(saved)
        data.update(version=1, messages=messages[-MAX_CONVERSATION:])
        _write(CONVERSATION_FILE, data)
        return saved


def conversation_clear() -> int:
    with _lock:
        data = _read(CONVERSATION_FILE, _conversation_default())
        n = len(data.get("messages", []))
        data["messages"] = []
        _write(CONVERSATION_FILE, data)
        return n
