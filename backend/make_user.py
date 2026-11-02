"""
Crée ou change un compte de connexion (base SQLite backend/data/users.db).

    python make_user.py Master             demande le mot de passe (caché) et l'enregistre :
                                           chiffré par César, Playfair ou Hill (tiré au hasard)
    python make_user.py --list             liste les comptes (algorithme, état)
    python make_user.py Master --unlock    débloque un compte sur TOUTES les IP (4 mots de
                                           passe erronés de suite depuis une même IP bloquent
                                           ce compte pour cette IP, pas pour les autres)
    python make_user.py Master --delete    supprime le compte

Si le compte existe déjà, son mot de passe est remplacé (et le compte est débloqué).
Ici, seule la longueur minimale (8) est exigée ; l'inscription depuis la page de connexion
impose en plus une majuscule, une minuscule, un chiffre et un symbole.
"""
import getpass
import sys

import auth
import db


# Point d'entree CLI : aiguille selon les drapeaux (--list, --delete, --unlock)
# ou, par defaut, demande deux fois le mot de passe et enregistre le compte.
# Renvoie le code de sortie du processus (0 = succes). Le docstring du module
# ci-dessus sert de texte d'aide, il est affiche quand aucun nom n'est donne.
def main(argv: list) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if "--list" in flags:
        users = db.list_users()
        if not users:
            print("Aucun compte.")
        for u in users:
            if u["blocked_ips"]:
                state = f"{u['blocked_ips']} IP bloquée(s)"
            elif u["max_failed"]:
                state = f"{u['max_failed']} erreur(s) de suite (pire IP)"
            else:
                state = "OK"
            print(f"{u['username']:<20} {u['method']:<9} {state:<28} créé le {u['created_at']}")
        return 0
    if not args:
        print(__doc__)
        return 1
    name = args[0]
    if not auth.USERNAME_RE.match(name):
        print("Nom invalide : 1 à 40 caractères parmi lettres, chiffres, . _ @ -")
        return 1
    if "--delete" in flags:
        if not db.delete_user(name):
            print(f"Le compte « {name} » n'existe pas.")
            return 1
        print(f"Compte « {name} » supprimé.")
        return 0
    if "--unlock" in flags:
        if not db.unlock(name):
            print(f"Le compte « {name} » n'existe pas.")
            return 1
        print(f"Compte « {name} » débloqué.")
        return 0
    pw1 = getpass.getpass(f"Mot de passe de « {name} » : ")
    if len(pw1) < auth.PASSWORD_MIN:
        print(f"Trop court : {auth.PASSWORD_MIN} caractères au minimum.")
        return 1
    if not pw1.isascii():
        print("Les accents ne sont pas acceptés (Playfair et Hill ne traitent que A–Z).")
        return 1
    if getpass.getpass("Encore une fois : ") != pw1:
        print("Les deux mots de passe sont différents.")
        return 1
    created = auth.set_password(name, pw1)
    method = db.get_user(name)["method"]
    print(f"Compte « {name} » {'créé' if created else 'mis à jour'} (mot de passe chiffré avec {method}).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
