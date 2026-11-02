"""
Stockage dans des fichiers (pas de base de données).

Trois fichiers JSON, rangés dans le dossier `backend/data/` (ou dans celui donné
par la variable d'environnement DATA_DIR) :

  historique_chiffrements.json   l'historique des chiffrements / déchiffrements
                                 de la partie « Chiffrer un message »
  historique_mots_de_passe.json  l'historique des attaques (force brute, dictionnaire)
                                 de la partie « Mots de passe »
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

MAX_HISTORY = 200        # au-dela, les plus anciennes lignes sont oubliees
MAX_CONVERSATION = 500

HISTORY_FILE = "historique_chiffrements.json"
PW_HISTORY_FILE = "historique_mots_de_passe.json"
CONVERSATION_FILE = "conversation_ab.json"

_lock = threading.RLock()


# Le dossier des fichiers (cree au besoin). Relu a chaque appel : les tests
# peuvent le rediriger avec la variable d'environnement DATA_DIR.
def data_dir() -> str:
    d = os.environ.get("DATA_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(d, exist_ok=True)
    return d


# Chemin absolu d'un fichier de donnees a partir de son nom.
def _path(filename: str) -> str:
    return os.path.join(data_dir(), filename)


# Lit un fichier JSON et renvoie son dict, ou `default` s'il est absent. Un
# fichier illisible est mis de cote (renomme .illisible, jamais ecrase en
# silence) avant de repartir sur `default`.
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
    try:
        os.replace(path, path + ".illisible")
    except OSError:
        pass
    return default


# Ecriture atomique : ecrit dans un fichier temporaire du meme dossier puis le
# renomme sur la cible, de sorte que l'ancien fichier reste intact jusqu'au
# dernier instant (jamais de fichier a moitie ecrit).
def _write(filename: str, data: Dict[str, Any]) -> None:
    path = _path(filename)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


# Horodatage UTC ISO 8601 a la seconde, utilise pour dater chaque enregistrement.
def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# Dict initial d'un fichier d'historique vide. Format :
# {"version": 1, "next_id": N, "entries": [...]} ; `entries` va du plus ancien au
# plus recent, `next_id` ne recule jamais (un numero supprime n'est pas reattribue).
def _history_default() -> Dict[str, Any]:
    return {"version": 1, "next_id": 1, "entries": []}


# Les lignes d'un fichier d'historique, la plus recente en premier.
def _entries_list(filename: str) -> List[Dict[str, Any]]:
    with _lock:
        data = _read(filename, _history_default())
        return list(reversed(data.get("entries", [])))


# Ajoute une ligne a un historique en lui attribuant un `id` qui ne recule
# jamais et un horodatage, puis tronque a MAX_HISTORY lignes.
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


# Supprime UNE ligne par son id. Renvoie False si elle n'existe pas (deja supprimee).
def _entries_delete(filename: str, entry_id: int) -> bool:
    with _lock:
        data = _read(filename, _history_default())
        entries = data.get("entries", [])
        kept = [e for e in entries if e.get("id") != entry_id]
        if len(kept) == len(entries):
            return False
        data["entries"] = kept
        _write(filename, data)
        return True


# Supprime toutes les lignes (le compteur de numeros continue). Renvoie combien.
def _entries_clear(filename: str) -> int:
    with _lock:
        data = _read(filename, _history_default())
        n = len(data.get("entries", []))
        data["entries"] = []
        _write(filename, data)
        return n


# Historique des chiffrements : liste les lignes, la plus recente en premier.
def history_list() -> List[Dict[str, Any]]:
    return _entries_list(HISTORY_FILE)


# Historique des chiffrements : ajoute une ligne.
def history_add(entry: Dict[str, Any]) -> Dict[str, Any]:
    return _entries_add(HISTORY_FILE, entry)


# Historique des chiffrements : supprime une ligne par son id.
def history_delete(entry_id: int) -> bool:
    return _entries_delete(HISTORY_FILE, entry_id)


# Historique des chiffrements : vide tout et renvoie le nombre supprime.
def history_clear() -> int:
    return _entries_clear(HISTORY_FILE)


# Historique des attaques sur mots de passe : liste les lignes (meme format, autre fichier).
def pw_history_list() -> List[Dict[str, Any]]:
    return _entries_list(PW_HISTORY_FILE)


# Historique des attaques sur mots de passe : ajoute une ligne.
def pw_history_add(entry: Dict[str, Any]) -> Dict[str, Any]:
    return _entries_add(PW_HISTORY_FILE, entry)


# Historique des attaques sur mots de passe : supprime une ligne par son id.
def pw_history_delete(entry_id: int) -> bool:
    return _entries_delete(PW_HISTORY_FILE, entry_id)


# Historique des attaques sur mots de passe : vide tout et renvoie le nombre supprime.
def pw_history_clear() -> int:
    return _entries_clear(PW_HISTORY_FILE)


# Dict initial d'une conversation vide. Format :
# {"version": 1, "messages": [...]}, range dans l'ordre d'envoi.
def _conversation_default() -> Dict[str, Any]:
    return {"version": 1, "messages": []}


# Liste les messages de la conversation A <-> B, dans l'ordre d'envoi.
def conversation_list() -> List[Dict[str, Any]]:
    with _lock:
        return list(_read(CONVERSATION_FILE, _conversation_default()).get("messages", []))


# Ajoute un message a la fin de la conversation. Renvoie None si ce numero est
# deja enregistre (un envoi repete ne cree pas de doublon).
def conversation_add(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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


# Vide la conversation et renvoie le nombre de messages supprimes.
def conversation_clear() -> int:
    with _lock:
        data = _read(CONVERSATION_FILE, _conversation_default())
        n = len(data.get("messages", []))
        data["messages"] = []
        _write(CONVERSATION_FILE, data)
        return n
