// Partie « Échange entre deux personnes » (ExchangePanel, parts, Chat)
const exchange: Record<string, string> = {
  'Utilisateur {u}': 'User {u}',
  'Messagerie de {u}': "{u}'s messaging",
  'Clé publique de {u}': "{u}'s public key",
  'Clé privée de {u}': "{u}'s private key",
  '1 · Message clair (écrit par {u})': '1 · Plaintext (written by {u})',
  'Écris ton message, une phrase ou un paragraphe…': 'Write your message, a sentence or a paragraph…',
  '2 · Chiffré à envoyer': '2 · Ciphertext to send',
  'Envoyer à {u}': 'Send to {u}',
  '3 · Reçu de {u} (déchiffré)': '3 · Received from {u} (decrypted)',
  '4 · Reçu de {u} (chiffré)': '4 · Received from {u} (encrypted)',
  'Algo reçu': 'Algorithm received',
  'Clé reçue': 'Key received',
  'Boîte de chiffrement de {u}': "{u}'s encryption box",
  'Boîte de déchiffrement de {u}': "{u}'s decryption box",
  'Boîte de chiffrement / déchiffrement de {u}': "{u}'s encryption / decryption box",
  'En attente : écris un message puis clique « Chiffrer ».': 'Waiting: write a message then click "Encrypt".',
  'Clés RSA': 'RSA keys',
  '{n} bits': '{n} bits',
  'Génération…': 'Generating…',
  'Générer les clés': 'Generate the keys',
  'Génération impossible.': 'Key generation failed.',
  'Remplis toutes les cases de la matrice avec des nombres entiers.': 'Fill every cell of the matrix with whole numbers.',
  'Impossible de fermer le coffre.': 'Could not lock the chest.',
  "Impossible d'ouvrir le coffre.": 'Could not open the chest.',
  'Déchiffrement impossible.': 'Decryption failed.',
  'Chiffrement {algo} · clé {key}': '{algo} encryption · key {key}',
  'Déchiffrement {algo} · clé {key}': '{algo} decryption · key {key}',
  'droite': 'right',
  'gauche': 'left',

  // ---- protocole RSA
  'Protocole RSA': 'RSA protocol',
  'Génération des clés': 'Key generation',
  'Deux nombres premiers p et q (test de Miller-Rabin), n = p × q, φ(n) = (p − 1)(q − 1), e = 65537 et d = e⁻¹ mod φ(n). Clé publique : (e, n). Clé privée : (d, n).':
    'Two prime numbers p and q (Miller-Rabin test), n = p × q, φ(n) = (p − 1)(q − 1), e = 65537 and d = e⁻¹ mod φ(n). Public key: (e, n). Private key: (d, n).',
  'Échange des clés publiques': 'Public key exchange',
  "A et B s'envoient leurs clés publiques. Les clés privées ne quittent jamais leur propriétaire.":
    'A and B send each other their public keys. Private keys never leave their owner.',
  'Envoi': 'Sending',
  "L'expéditeur chiffre son message (César, Playfair ou Hill), puis enferme l'algo, la clé et le chiffré avec la clé publique du destinataire :":
    "The sender encrypts their message (Caesar, Playfair or Hill), then locks the algorithm, the key and the ciphertext with the recipient's public key:",
  'Réception': 'Receiving',
  'Le destinataire ouvre le coffre avec sa clé privée': 'The recipient opens the chest with their private key',
  ", relit l'algo et la clé, puis déchiffre le message.": ', reads the algorithm and the key, then decrypts the message.',
  'Tout est calculé par le backend Python': 'Everything is computed by the Python backend',
  "C'est le RSA « de manuel », sans remplissage : en pratique, on ajoute un remplissage aléatoire (OAEP) pour qu'un même message ne donne jamais le même chiffré. Pour générer de nouvelles clés, rafraîchis la page.":
    'This is "textbook" RSA, without padding: in practice, random padding (OAEP) is added so that the same message never gives the same ciphertext. To generate new keys, refresh the page.',
  "Au dernier envoi, quelqu'un qui écoute le canal n'aurait vu passer qu'un coffre verrouillé":
    'During the last sending, someone listening on the channel would only have seen a locked chest go by',
  'bloc': 'block',
  'blocs': 'blocks',
  'et le message chiffré': 'and the ciphertext',
  "Sans la clé privée de {u}, impossible de lire l'algo ou la clé.": "Without {u}'s private key, there is no way to read the algorithm or the key.",
  'Voir les clés complètes de A et B': 'Show the full keys of A and B',

  // ---- chat
  'Conversation entre A et B': 'Conversation between A and B',
  'Chat entre A et B': 'Chat between A and B',
  'Supprimer le chat': 'Delete the chat',
  'Supprimer toute la conversation': 'Delete the whole conversation',
  'Voir chiffré': 'Show encrypted',
  'Voir en clair': 'Show plaintext',
  '{algo} · clé {key}': '{algo} · key {key}',
  'clé {key}': 'key {key}',
}
export default exchange
