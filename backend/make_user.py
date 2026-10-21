# -*- coding: utf-8 -*-
"""
Crée ou change un compte de connexion.

    python make_user.py Master             demande le mot de passe (caché) et l'enregistre
                                           dans users.json (haché : jamais en clair)
    python make_user.py Master --print     n'écrit rien, affiche seulement la ligne à coller
                                           dans la variable APP_USERS (sur Render)
    python make_user.py --list             liste les comptes de users.json
    python make_user.py Master --delete    supprime le compte

Sur Render, les fichiers du dépôt sont recréés à chaque déploiement : donne plutôt les
comptes par la variable d'environnement APP_USERS (voir --print), plusieurs comptes se
séparent par un point-virgule :   Master:pbkdf2_sha256$…;prof:pbkdf2_sha256$…
"""
import getpass
import json
import os
import sys

import auth


def _load() -> dict:
    try:
        with open(auth.users_file(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"users": {}}


def _save(data: dict) -> None:
    with open(auth.users_file(), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main(argv: list) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if "--list" in flags:
        for name in _load().get("users", {}):
            print(name)
        return 0
    if not args:
        print(__doc__)
        return 1
    name = args[0]
    if not auth.USERNAME_RE.match(name):
        print("Nom invalide : 1 à 40 caractères parmi lettres, chiffres, . _ @ -")
        return 1
    if "--delete" in flags:
        data = _load()
        if data.get("users", {}).pop(name, None) is None:
            print(f"Le compte « {name} » n'existe pas.")
            return 1
        _save(data)
        print(f"Compte « {name} » supprimé.")
        return 0
    pw1 = getpass.getpass(f"Mot de passe de « {name} » : ")
    if len(pw1) < 8:
        print("Trop court : 8 caractères au minimum.")
        return 1
    if getpass.getpass("Encore une fois : ") != pw1:
        print("Les deux mots de passe sont différents.")
        return 1
    h = auth.hash_password(pw1)
    if "--print" not in flags:
        data = _load()
        data.setdefault("users", {})[name] = h
        _save(data)
        print(f"Compte « {name} » enregistré dans {os.path.basename(auth.users_file())}.")
    print("\nPour Render (variable d'environnement APP_USERS) :")
    print(f"{name}:{h}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
