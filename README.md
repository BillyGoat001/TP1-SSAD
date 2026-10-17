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
│   ├── main.py           # API FastAPI + service du front buildé
│   ├── _selftest.py      # tests du backend (python _selftest.py)
│   └── requirements.txt
└── frontend/
    ├── src/…             # React/TypeScript
    └── dist/             # build de production (déjà inclus)
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

## Versions

- **React 18.3.1** (avec react-dom 18.3.1)
- **Vite 5.4.11**, **TypeScript 5.6.3**, `@vitejs/plugin-react 4.3.4`
- **Python 3.10+**, FastAPI 0.115.5, uvicorn 0.32.1

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
hachage PBKDF2 et la détection d'altération HMAC.
