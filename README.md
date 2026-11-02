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
  HMAC) est en Python, lisible par toute l'équipe ; seules les deux boucles
  d'attaque sont en C pour la vitesse (voir plus bas). Le backend renvoie aussi
  la *trace des étapes*, que le front anime.
- **Frontend : React + TypeScript (Vite)** — l'interface et les animations.

```
tp_app/
├── backend/
│   ├── encryption.py     # César, Playfair, Hill (Partie 1)
│   ├── traces.py         # étapes d'animation (dérivées des chiffrements)
│   ├── rsa_crypto.py     # RSA complet : Miller-Rabin, n, φ(n), e, d (Partie 2)
│   ├── passwords.py      # protection des mots de passe (Partie 3)
│   ├── attacks.py        # lance / arrête / suit les attaques (force brute, dictionnaire)
│   ├── native_attacks.py # pont ctypes vers native/attacks.c (les deux boucles d'attaque en C)
│   ├── native/           # attacks.c (+ libattacks.so compilée)
│   ├── dictionnaires/    # listes de mots pour l'attaque par dictionnaire
│   ├── integrity.py      # HMAC-SHA256 + chiffrement de A → B (Partie 4)
│   ├── auth.py           # comptes (mots de passe chiffrés), sessions signées, blocage
│   ├── captcha.py        # les 3 défis anti-robot + preuve de travail
│   ├── db.py             # base des comptes : SQLite en local, PostgreSQL (Neon) en production
│   ├── storage.py        # historiques et conversation A↔B (fichiers JSON dans backend/data/)
│   ├── make_user.py      # créer / lister / débloquer / supprimer un compte
│   ├── main.py           # API FastAPI + service du front buildé
│   ├── _selftest.py      # tests du backend (python _selftest.py)
│   └── requirements.txt
├── frontend/
│   ├── src/…             # React/TypeScript (src/components/auth = page de connexion)
│   └── dist/             # build de production (déjà inclus)
└── Dockerfile            # recette utilisée par Render (build du front + backend)
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

## Partie 3 — Attaques sur mots de passe

La force brute (000 → zzz, en incrémentant de droite à gauche) et l'attaque par
dictionnaire passent par `attacks.py`, qui démarre un fil de travail et publie la
progression. Les deux boucles de recherche tournent en **C** (`native/attacks.c`,
appelé par `native_attacks.py` via ctypes) : bien plus rapides, et interruptibles
(le bouton Stop fonctionne vraiment). Si le C n'est pas disponible (ni `gcc`, ni
`libattacks.so` compatible), le backend retombe automatiquement sur des boucles
Python — plus lentes, mais tout fonctionne — et il affiche la raison au démarrage.

## Partie 4 — Intégrité (HMAC-SHA256)

Le chiffrement cache un message mais ne détecte pas qu'on l'a modifié en route.
Un **HMAC** ajoute une étiquette calculée avec le message *et* une clé secrète
partagée.

- **A** écrit un message. Avec l'option *Chiffrement*, il le chiffre vraiment
  (César, Playfair ou Hill : **au hasard par défaut**, ou l'algorithme et la clé
  qu'il choisit dans sa carte), puis calcule l'étiquette sur ce qui voyage :
  **le chiffré** (ou le message lui-même s'il voyage en clair).
- Sur le canal voyage un **paquet** : le chiffré, l'algorithme, la clé et
  l'étiquette. **C**, l'attaquant, peut tout lire et modifier le chiffré, mais il
  n'a jamais la clé HMAC : il ne peut pas fabriquer une étiquette valide pour son
  message modifié.
- **B** recalcule l'étiquette sur le chiffré reçu *avant* de déchiffrer et la
  compare à celle de A. Sans la protection, B affiche tout sans rien vérifier.
- Le **taux de changement de l'étiquette** (part des 64 caractères qui diffèrent
  entre l'étiquette de A et celle recalculée par B) est le chiffre clé : 0 % si le
  message est intact, environ 94 % dès qu'on le modifie (effet d'avalanche de
  SHA-256 : le taux ne grandit pas avec la taille de la modification, et c'est voulu).

Pourquoi l'étiquette est calculée sur le chiffré et non sur le clair : avec
Playfair, une lettre ajoutée en fin de chiffré est ignorée au déchiffrement, donc
B retrouvait le même clair et ne voyait rien. Signé sur le chiffré, le moindre
caractère modifié change l'étiquette.

## Historiques

Chaque partie garde un historique (chiffrements, attaques sur mots de passe,
envois A → B avec leur taux de changement) ainsi que la conversation A↔B, dans
des fichiers JSON de `backend/data/` (ou du dossier `DATA_DIR`). Sur Render, le
disque est effacé à chaque redémarrage : ces historiques repartent de zéro, alors
que les comptes (en base) sont conservés.

## Connexion et comptes

L'application est protégée par une **page de connexion** : identifiant + mot de
passe, puis un **défi anti-robot** (un cadenas qui se déverrouille à la fin).
On peut créer un compte depuis la page de connexion (8 caractères au moins, une
majuscule, une minuscule, un chiffre et un symbole) ou en ligne de commande :

```bash
cd backend
python make_user.py billy            # crée / change le mot de passe (demandé sans affichage)
python make_user.py --list           # liste les comptes (algorithme, état)
python make_user.py billy --unlock   # débloque un compte sur toutes les IP
python make_user.py billy --delete   # supprime un compte
```

- Règle du TP : le mot de passe n'est **ni stocké en clair, ni haché** — il est
  **chiffré** avec l'un des trois chiffrements du projet (César, Playfair ou Hill,
  tiré au hasard, avec une clé aléatoire). Les comptes sont dans une base : SQLite
  (`backend/data/users.db`) en local, PostgreSQL (ex. Neon) si `DATABASE_URL` est
  définie. Ce choix a des limites (la clé est stockée avec le mot de passe) : voir
  l'en-tête de `auth.py`.
- La session est un **cookie signé** (HttpOnly, SameSite=Lax, Secure en https),
  valable 12 h, révocable à la déconnexion.
- **Blocage** : après 4 mots de passe erronés de suite depuis une même IP, ce
  couple (compte, IP) est bloqué jusqu'à `make_user.py nom --unlock`. Une autre IP
  n'est pas affectée (sinon on pourrait bloquer le vrai propriétaire à distance).
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
| `DATABASE_URL` | base PostgreSQL (ex. Neon) pour les comptes. **À définir sur Render** : le disque y est effacé à chaque redémarrage, une base SQLite perdrait tous les comptes. Sans elle, SQLite est utilisé. |
| `USERS_DB` | emplacement du fichier SQLite (par défaut `backend/data/users.db`). |
| `DATA_DIR` | dossier des historiques JSON (par défaut `backend/data/`). |
| `TP_POW_BITS` | difficulté de base de la preuve de travail (19 par défaut). |
| `TP_AUTH_OFF=1` | **développement seulement** : désactive la connexion. |

`Pillow` (qui dessine les défis) et `psycopg` (PostgreSQL) sont dans `requirements.txt`.

Render construit l'application avec le `Dockerfile` : `npm ci` + `npm run build` pour le front, puis le backend Python.

## Versions

- **React 18.3.1** (avec react-dom 18.3.1)
- **Vite 5.4.11**, **TypeScript 5.6.3**, `@vitejs/plugin-react 4.3.4`
- **Python 3.10+**, FastAPI 0.115.5, uvicorn 0.32.1, Pillow 10.1+, psycopg 3.2.3

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
privée refusée, échange complet A → B par l'API), les attaques mots de passe
(Python et C), l'intégrité HMAC (détection d'altération, y compris une lettre
ajoutée à un chiffré Playfair, algorithme et clé choisis par A, taux de changement
de l'étiquette, historique), puis la connexion (comptes, sessions, jeton révoqué,
3 captchas, preuve de travail, blocage après 4 échecs par IP).
