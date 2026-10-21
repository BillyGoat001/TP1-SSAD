# TP Sécurité — Application full-stack

Démonstrateur de sécurité : **chiffrements animés** (César, Playfair, Hill),
**échange entre deux personnes avec RSA** (l'algo et la clé voyagent dans la
boîte publique du destinataire), **attaques sur mots de passe** (force brute +
dictionnaire) avec la protection, et **intégrité / authenticité** par HMAC-SHA256.

L'onglet *Chiffrement* a deux parties : **Chiffrer un message** (un seul
utilisateur, étapes animées) et **Échange entre deux personnes** : A et B
génèrent chacun une vraie paire de clés RSA (32 à 2048 bits), échangent leurs
clés publiques, puis s'envoient des messages. L'algo, la clé et le message
chiffré sont enfermés avec la clé publique du destinataire ; lui seul les
relit avec sa clé privée, puis déchiffre.

- **Backend : Python (FastAPI)** — toute la logique (algorithmes, attaques,
  HMAC) est en Python, lisible par toute l'équipe. Le backend renvoie aussi la
  *trace des étapes*, que le front anime.
- **Frontend : React + TypeScript (Vite)** — l'interface et les animations.

```
tp_app/
├── backend/
│   ├── encryption.py     # César, Playfair, Hill (Partie 1)
│   ├── traces.py         # étapes d'animation (dérivées des chiffrements)
│   ├── rsa_crypto.py     # RSA complet : Miller-Rabin, n, φ(n), e, d (Partie 2)
│   ├── passwords.py      # attaques + protection (Partie 3)
│   ├── integrity.py      # HMAC-SHA256 (Partie 4)
│   ├── auth.py           # comptes (PBKDF2), sessions signées, limitation des essais
│   ├── captcha.py        # les 3 défis anti-robot + preuve de travail
│   ├── make_user.py      # créer / lister / supprimer un compte
│   ├── users.json        # les comptes (mots de passe hachés, jamais en clair)
│   ├── main.py           # API FastAPI + service du front buildé
│   ├── _selftest.py      # tests du backend (python _selftest.py)
│   └── requirements.txt
├── frontend/
│   ├── src/…             # React/TypeScript (src/components/auth = page de connexion)
│   └── dist/             # build de production (déjà inclus)
└── launcher/             # installateur + raccourci « appli de bureau » (Windows / Mac)
```

## Lancer l'application

### Option A — Démo rapide (seulement Python)

Le build React est déjà inclus dans `frontend/dist`, donc le serveur Python
sert l'application entière. Rien à installer à part Python.

```bash
cd backend
python3 -m pip install -r requirements.txt
uvicorn main:app --port 8000
```

Puis ouvre **http://localhost:8000**.

### Option B — Développement (rechargement à chaud, nécessite Node)

Deux terminaux :

```bash
# Terminal 1 — backend
cd backend
uvicorn main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Puis ouvre **http://localhost:5173** (le serveur Vite appelle l'API sur :8000
automatiquement).

### Reconstruire le build de production

Après une modification du front :

```bash
cd frontend
npm run build      # régénère frontend/dist
```

## Connexion et comptes

L'application est protégée par une **page de connexion** : identifiant + mot de
passe, puis un **défi anti-robot** (un cadenas qui se déverrouille à la fin).
Il n'y a pas d'inscription : les comptes sont créés par toi.

```bash
cd backend
python make_user.py billy            # crée / change le mot de passe (demandé sans affichage)
python make_user.py --list           # liste les comptes
python make_user.py billy --delete   # supprime un compte
python make_user.py billy --print    # affiche seulement la ligne à copier dans APP_USERS
```

- Les mots de passe sont **hachés** (PBKDF2-HMAC-SHA256, 600 000 itérations, sel
  aléatoire) dans `backend/users.json`. Le clair n'est écrit nulle part.
- La session est un **cookie signé** (HttpOnly, SameSite=Lax, Secure en https),
  valable 12 h, révocable à la déconnexion.
- **Limitation des essais** : 5 échecs, puis attente de 15 s qui double jusqu'à 5 min.
- **Trois défis qui changent à chaque ouverture, à chaque erreur et à chaque
  fermeture**, jamais deux fois le même type de suite :
  *Mouvement* (des caractères visibles seulement dans le déplacement de points),
  *Illusion* (des caractères cachés dans l'inclinaison de rayures) et
  *Mémoire* (suivre le cadenas qui cache la clé pendant un mélange).
  La réponse attendue n'est jamais envoyée au navigateur. Chaque défi est à usage
  unique, expire en 2 minutes, impose un temps de réponse minimal et une
  **preuve de travail** (SHA-256) calculée par le navigateur, plus difficile après
  des échecs. Aucun captcha n'est invincible : ils arrêtent les agents qui
  « lisent » des captures d'écran, pas un humain payé pour les résoudre.

### Sur Render (ou tout hébergeur)

| Variable | Rôle |
|---|---|
| `SECRET_KEY` | clé qui signe les sessions. **À définir** (longue, aléatoire) : sans elle, tout le monde est déconnecté à chaque redémarrage. |
| `APP_USERS` | comptes au format `nom:hash;nom2:hash2` (hash obtenu avec `python make_user.py nom --print`). Prioritaire sur `users.json`. |
| `TP_POW_BITS` | difficulté de base de la preuve de travail (19 par défaut). |
| `TP_AUTH_OFF=1` | **développement seulement** : désactive la connexion. |

`Pillow` est ajouté aux dépendances (`requirements.txt`) : il dessine les défis.

## Installer comme une appli de bureau (Windows / Mac)

Dans le dossier `launcher/` :

- **Windows** : double-clique **`Installer.bat`**.
- **macOS** : double-clique **`Installer.command`** (si macOS refuse : clic droit → Ouvrir).

L'installateur crée un environnement Python privé (`.venv`), installe les
dépendances, propose de créer ton compte, puis crée un raccourci **« TP Sécurité »**
(bureau + menu Démarrer sous Windows ; Applications + bureau sous macOS). Le raccourci
ouvre l'appli dans **sa propre fenêtre** (mode appli de Brave, Chrome ou Edge,
sans barre d'adresse, avec un profil séparé) ; fermer la fenêtre arrête le serveur,
qui n'écoute que sur ton ordinateur (127.0.0.1). Il faut Python 3.9+ (l'installateur
propose de l'installer s'il manque). Détails : `launcher/LISEZ-MOI.txt`.

## Versions

- **React 18.3.1** (avec react-dom 18.3.1)
- **Vite 5.4.11**, **TypeScript 5.6.3**, `@vitejs/plugin-react 4.3.4`
- **Python 3.10+**, FastAPI 0.115.5, uvicorn 0.32.1, Pillow 10.1+

Pour installer React dans un projet neuf : `npm install react@18.3.1 react-dom@18.3.1`.
Ici, un simple `npm install` dans `frontend/` installe tout (versions figées
dans `package.json`).

## Tester le backend

```bash
cd backend
python3 _selftest.py
```

Vérifie les 3 chiffrements (aller-retour + traces), RSA (exemple de manuel,
Miller-Rabin, génération de 32 à 2048 bits, coffre fermé / ouvert, mauvaise clé
privée refusée, échange complet A → B par l'API), les attaques mots de passe, le
hachage PBKDF2 et la détection d'altération HMAC, puis la connexion (sessions,
jeton révoqué, 3 captchas, preuve de travail, verrouillage après 5 échecs).
