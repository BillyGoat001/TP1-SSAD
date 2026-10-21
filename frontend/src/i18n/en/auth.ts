// Page de connexion, captchas, déconnexion (components/auth/*) et messages du serveur
// d'authentification (backend/main.py, captcha.py).
const auth: Record<string, string> = {
  // ---- page de connexion
  'Identifiant': 'Username',
  'Afficher le mot de passe': 'Show password',
  'Masquer le mot de passe': 'Hide password',
  'Verr. Maj. est activé.': 'Caps Lock is on.',
  'Renseigne ton identifiant.': 'Enter your username.',
  'Renseigne ton mot de passe.': 'Enter your password.',
  'Patiente {n} s': 'Wait {n} s',
  'Se connecter': 'Sign in',
  'Accès autorisé': 'Access granted',
  'Bienvenue, {u}': 'Welcome, {u}',
  'Connexion impossible.': 'Sign-in failed.',
  'Déconnexion': 'Sign out',
  "Aucun compte n'est configuré sur ce serveur.": 'No account is set up on this server.',

  // ---- fenêtre de vérification
  'Vérification de sécurité': 'Security check',
  'Fermer': 'Close',
  "Préparation d'un nouveau défi…": 'Preparing a new challenge…',
  'Les 4 caractères': 'The 4 characters',
  'Vérification…': 'Checking…',
  'Valider': 'Submit',
  'Vérifié': 'Verified',
  'Preuve de travail prête': 'Proof of work ready',
  'Preuve de travail…': 'Proof of work…',
  'Preuve de travail : SHA-256 sur {n} bits': 'Proof of work: SHA-256 on {n} bits',
  'Autre défi': 'Another challenge',
  'Temps restant : {n} s': 'Time left: {n} s',
  'Mouvement': 'Motion',
  'Illusion': 'Illusion',
  'Mémoire': 'Memory',
  'Astuce : cherche la zone où les points vont à contre-sens des autres.': 'Tip: look for the area where the dots move against the others.',
  "Astuce : cherche où les rayures changent d'inclinaison.": 'Tip: look for where the stripes change their tilt.',
  'Impossible de charger le défi. Le serveur est-il lancé ?': 'Could not load the challenge. Is the server running?',
  'Le serveur est injoignable. Réessaie dans un instant.': 'The server is unreachable. Try again in a moment.',

  // ---- consignes (envoyées par le serveur) et animation des cadenas
  'Quatre caractères se cachent dans le mouvement des points. Recopie-les.': 'Four characters hide in the motion of the dots. Type them.',
  'Quatre caractères se cachent dans les rayures. Recopie-les.': 'Four characters hide in the stripes. Type them.',
  'Retiens le cadenas qui cache la clé, puis retrouve-le après le mélange.': 'Remember the padlock that hides the key, then find it again after the shuffle.',
  'Prépare-toi…': 'Get ready…',
  'Mémorise le cadenas qui reçoit la clé.': 'Memorize the padlock that receives the key.',
  'La clé est rangée.': 'The key is stored.',
  'Suis-le des yeux…': 'Follow it with your eyes…',
  'Où est la clé ? Clique sur le bon cadenas.': 'Where is the key? Click the right padlock.',
  'Cadenas {n}': 'Padlock {n}',

  // ---- réponses du serveur
  "Défi raté. Un nouveau défi t'attend.": 'Challenge failed. A new challenge is waiting.',
  "Le défi a expiré. Un nouveau défi t'attend.": 'The challenge has expired. A new challenge is waiting.',
  "Preuve de travail invalide. Un nouveau défi t'attend.": 'Invalid proof of work. A new challenge is waiting.',
  'Trop rapide : prends le temps de regarder le défi.': 'Too fast: take the time to look at the challenge.',
  'Comportement suspect : réessaie avec la souris ou le clavier.': 'Suspicious behaviour: try again using the mouse or keyboard.',
  'Identifiant ou mot de passe incorrect.': 'Incorrect username or password.',
  'Trop de tentatives. Réessaie dans {n} s.': 'Too many attempts. Try again in {n} s.',
  'Connexion requise.': 'Sign-in required.',
  'Trop de demandes. Patiente un instant.': 'Too many requests. Please wait a moment.',
}
export default auth
