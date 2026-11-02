# -*- coding: utf-8 -*-
"""
Base de données des comptes et des tentatives de connexion.

Deux moteurs possibles, choisis automatiquement au démarrage :
  - SQLite (par défaut) : un seul fichier, backend/data/users.db. Rien à installer,
    rien à lancer ; les comptes restent sur le disque entre deux lancements. On peut
    changer son emplacement avec USERS_DB.
  - PostgreSQL, si la variable DATABASE_URL est définie (ex. une base Neon) : utilisé
    en production (Render), où le disque du service est effacé à chaque redémarrage —
    une base SQLite locale y perdrait tous les comptes à chaque déploiement. Le reste
    du code (auth.py, main.py) ne voit aucune différence : les fonctions ci-dessous
    ont exactement le même nom et le même comportement quel que soit le moteur.

Deux tables :
  users           un compte par ligne (voir le détail des colonnes plus bas).
  login_attempts  les échecs de connexion, PAR COUPLE (compte, adresse IP) : un couple
                   est bloqué après `limit` échecs DE SUITE depuis CETTE IP. Une autre
                   IP peut donc toujours essayer ce compte (voir auth.is_blocked) ;
                   `python make_user.py nom --unlock` débloque toutes les IP à la fois.

users :
  username    le nom tel que saisi à l'inscription (« Master »)
  username_lc le même en minuscules, UNIQUE : « Master » et « master » sont le même compte
  method      l'algorithme qui a chiffré le mot de passe : caesar | playfair | hill
  key         sa clé (JSON) : {"shift": 7} | {"key": "MONARCHY"} | {"matrix": [[3, 3], [2, 5]]}
  secret      le mot de passe CHIFFRÉ (lettres majuscules seulement)
  layout, fillers, jmap, cases
              la mise en forme (voir encryption.py) : non-lettres et leur position, lettres
              ajoutées par l'algorithme, positions des J et des minuscules (JSON)
  failed, blocked
              ANCIEN compteur global (toutes IP confondues). Conservé tel quel pour ne
              pas modifier le schéma d'une base existante, mais plus mis à jour par la
              connexion depuis le passage au blocage par IP : voir login_attempts et
              list_users() / make_user.py --list pour l'état réellement affiché.
  created_at  date de création (UTC)

login_attempts :
  username_lc, ip   la clé : un couple (compte, IP)
  failed            échecs de connexion de suite depuis cette IP, sur ce compte
  blocked           1 = ce couple (compte, IP) est bloqué
  updated_at        dernière écriture (UTC)

Ce module ne connaît pas les chiffrements : il range et relit des lignes. Tout le calcul
est dans auth.py et encryption.py.
"""
import datetime
import json
import os
import sqlite3
import threading
from contextlib import closing
from typing import Any, Dict, List, Optional

import storage

_lock = threading.RLock()

# DATABASE_URL vide ou absent -> SQLite (comportement inchangé). Définie (ex. une
# chaîne postgresql://... fournie par Neon) -> PostgreSQL, choisi une fois au démarrage.
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()
PG = bool(DATABASE_URL)

if PG:
    import psycopg                      # voir requirements.txt — psycopg[binary]
    from psycopg.rows import dict_row
    _INTEGRITY_ERRORS = (sqlite3.IntegrityError, psycopg.errors.IntegrityError)
else:
    _INTEGRITY_ERRORS = (sqlite3.IntegrityError,)

_SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL,
    username_lc TEXT    NOT NULL UNIQUE,
    method      TEXT    NOT NULL CHECK (method IN ('caesar', 'playfair', 'hill')),
    key         TEXT    NOT NULL,
    secret      TEXT    NOT NULL,
    layout      TEXT    NOT NULL DEFAULT '[]',
    fillers     TEXT    NOT NULL DEFAULT '[]',
    jmap        TEXT    NOT NULL DEFAULT '[]',
    cases       TEXT    NOT NULL DEFAULT '[]',
    failed      INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL
)
"""
_SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL  PRIMARY KEY,
    username    TEXT    NOT NULL,
    username_lc TEXT    NOT NULL UNIQUE,
    method      TEXT    NOT NULL CHECK (method IN ('caesar', 'playfair', 'hill')),
    key         TEXT    NOT NULL,
    secret      TEXT    NOT NULL,
    layout      TEXT    NOT NULL DEFAULT '[]',
    fillers     TEXT    NOT NULL DEFAULT '[]',
    jmap        TEXT    NOT NULL DEFAULT '[]',
    cases       TEXT    NOT NULL DEFAULT '[]',
    failed      INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL
)
"""
# Même texte dans les deux moteurs : SQLite a repris la syntaxe UPSERT de PostgreSQL
# (ON CONFLICT ... DO UPDATE ... excluded.colonne), donc rien à adapter ici.
_ATTEMPTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS login_attempts (
    username_lc TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    failed      INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT    NOT NULL,
    PRIMARY KEY (username_lc, ip)
)
"""
_JSON_FIELDS = ("key", "layout", "fillers", "jmap", "cases")


def db_path() -> str:
    """SQLite uniquement. Relu à chaque appel : les tests peuvent rediriger la base
    avec USERS_DB."""
    p = os.environ.get("USERS_DB")
    if p:
        os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
        return p
    return os.path.join(storage.data_dir(), "users.db")


def _q(sql: str) -> str:
    """Les requêtes sont écrites avec `?` (style SQLite) ; converties en `%s` pour
    PostgreSQL. Aucun `?` n'apparaît ailleurs que comme paramètre dans ce fichier."""
    return sql.replace("?", "%s") if PG else sql


def _connect():
    if PG:
        con = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        con.execute(_SCHEMA_PG)
        con.execute(_ATTEMPTS_SCHEMA)
        con.commit()
        return con
    con = sqlite3.connect(db_path(), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute(_SCHEMA_SQLITE)
    con.execute(_ATTEMPTS_SCHEMA)
    return con


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _row(r) -> Optional[Dict[str, Any]]:
    if r is None:
        return None
    d = dict(r)
    for f in _JSON_FIELDS:
        d[f] = json.loads(d[f])
    return d


def _values(record: Dict[str, Any]) -> tuple:
    return (record["method"], json.dumps(record["key"]), record["secret"],
            json.dumps(record["layout"]), json.dumps(record["fillers"]),
            json.dumps(record["jmap"]), json.dumps(record["cases"]))


# --------------------------------------------------------------------- comptes ----
def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Le compte (champs JSON déjà décodés) ou None. Insensible à la casse."""
    with _lock, closing(_connect()) as con:
        return _row(con.execute(_q("SELECT * FROM users WHERE username_lc = ?"),
                                ((username or "").strip().lower(),)).fetchone())


def create_user(username: str, record: Dict[str, Any]) -> bool:
    """Ajoute un compte. False si le nom est déjà pris."""
    with _lock, closing(_connect()) as con:
        try:
            con.execute(_q(
                "INSERT INTO users (username, username_lc, method, key, secret, layout, fillers, jmap, cases, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                (username, username.lower(), *_values(record), _now()))
            con.commit()
            return True
        except _INTEGRITY_ERRORS:
            con.rollback()
            return False


def replace_user(username: str, record: Dict[str, Any]) -> bool:
    """Change le mot de passe d'un compte existant (et le débloque, toutes IP
    comprises). False s'il n'existe pas."""
    with _lock, closing(_connect()) as con:
        cur = con.execute(_q(
            "UPDATE users SET method=?, key=?, secret=?, layout=?, fillers=?, jmap=?, cases=?, failed=0, blocked=0 "
            "WHERE username_lc = ?"), (*_values(record), username.lower()))
        con.execute(_q("DELETE FROM login_attempts WHERE username_lc = ?"), (username.lower(),))
        con.commit()
        return cur.rowcount > 0


def delete_user(username: str) -> bool:
    with _lock, closing(_connect()) as con:
        cur = con.execute(_q("DELETE FROM users WHERE username_lc = ?"), (username.lower(),))
        con.execute(_q("DELETE FROM login_attempts WHERE username_lc = ?"), (username.lower(),))  # ménage
        con.commit()
        return cur.rowcount > 0


def list_users() -> List[Dict[str, Any]]:
    """Un compte par ligne, avec l'état de blocage réellement actif : le nombre d'IP
    bloquées sur ce compte et le plus grand compteur d'échecs de suite parmi elles
    (voir login_attempts — remplace l'ancien `blocked`/`failed` globaux, inertes)."""
    with _lock, closing(_connect()) as con:
        rows = con.execute(_q(
            "SELECT u.username AS username, u.method AS method, u.created_at AS created_at, "
            "COALESCE(SUM(CASE WHEN a.blocked = 1 THEN 1 ELSE 0 END), 0) AS blocked_ips, "
            "COALESCE(MAX(a.failed), 0) AS max_failed "
            "FROM users u LEFT JOIN login_attempts a ON a.username_lc = u.username_lc "
            "GROUP BY u.id, u.username, u.method, u.created_at "
            "ORDER BY u.id")).fetchall()
        return [dict(r) for r in rows]


def count() -> int:
    with _lock, closing(_connect()) as con:
        return con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


def unlock(username: str) -> bool:
    """Débloque le compte : toutes les IP à la fois (make_user.py nom --unlock)."""
    u = username.lower()
    with _lock, closing(_connect()) as con:
        cur = con.execute(_q("UPDATE users SET failed = 0, blocked = 0 WHERE username_lc = ?"), (u,))
        con.execute(_q("DELETE FROM login_attempts WHERE username_lc = ?"), (u,))
        con.commit()
        return cur.rowcount > 0


# --------------------------------------------- tentatives de connexion (par IP) ----
def add_attempt_failure(username: str, ip: str, limit: int) -> int:
    """Un échec de connexion de plus DEPUIS CETTE IP sur ce compte. Le couple
    (compte, IP) est bloqué dès `limit` échecs de suite — une autre IP n'est pas
    affectée (voir is_attempt_blocked). Renvoie le nombre d'échecs de suite pour
    ce couple."""
    u, now = (username or "").strip().lower(), _now()
    with _lock, closing(_connect()) as con:
        con.execute(_q(
            "INSERT INTO login_attempts (username_lc, ip, failed, blocked, updated_at) "
            "VALUES (?, ?, 1, 0, ?) "
            "ON CONFLICT (username_lc, ip) DO UPDATE SET "
            "failed = login_attempts.failed + 1, updated_at = excluded.updated_at"),
            (u, ip, now))
        con.execute(_q(
            "UPDATE login_attempts SET blocked = 1 WHERE username_lc = ? AND ip = ? AND failed >= ?"),
            (u, ip, limit))
        r = con.execute(_q(
            "SELECT failed FROM login_attempts WHERE username_lc = ? AND ip = ?"), (u, ip)).fetchone()
        con.commit()
        return r["failed"] if r else 0


def reset_attempt_failures(username: str, ip: str) -> None:
    """Connexion réussie depuis cette IP : son compteur sur ce compte repart de zéro."""
    u = (username or "").strip().lower()
    with _lock, closing(_connect()) as con:
        con.execute(_q(
            "UPDATE login_attempts SET failed = 0 WHERE username_lc = ? AND ip = ? AND blocked = 0"), (u, ip))
        con.commit()


def is_attempt_blocked(username: str, ip: str) -> bool:
    """Ce couple (compte, IP) est-il bloqué ?"""
    u = (username or "").strip().lower()
    with _lock, closing(_connect()) as con:
        r = con.execute(_q(
            "SELECT blocked FROM login_attempts WHERE username_lc = ? AND ip = ?"), (u, ip)).fetchone()
        return bool(r and r["blocked"])
