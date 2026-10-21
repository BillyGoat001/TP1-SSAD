// Messages envoyés par le backend Python (toujours en français) et textes rangés en
// français dans les fichiers (historiques) : traduits ici, au moment de l'affichage.
const backend: Record<string, string> = {
  // ---- avertissements de clés faibles (encryption.py)
  'Décalage nul (clé = 0 ou un multiple de 26) : le message ressortirait identique, il ne serait pas chiffré.':
    'Zero shift (key = 0 or a multiple of 26): the message would come out unchanged, it would not be encrypted.',
  "La clé 13 (ROT13) est faible : l'appliquer deux fois redonne le message d'origine, et c'est une convention très connue.":
    'Key 13 (ROT13) is weak: applying it twice gives back the original message, and it is a very well-known convention.',
  "Cette clé laisse la grille de l'alphabet (A B C D E / F G H I K…) : c'est la première grille qu'un attaquant essaie. Sur une même ligne, une lettre est simplement décalée d'une place, comme un César de clé 1.":
    'This key leaves the alphabet grid (A B C D E / F G H I K…): it is the first grid an attacker tries. On the same row, a letter is simply shifted by one place, like a Caesar with key 1.',
  'Matrice identité : le message ressortirait identique, il ne serait pas chiffré.':
    'Identity matrix: the message would come out unchanged, it would not be encrypted.',
  'Matrice diagonale : chaque lettre serait chiffrée seule, ce qui revient à une substitution monoalphabétique très faible.':
    'Diagonal matrix: each letter would be encrypted on its own, which amounts to a very weak monoalphabetic substitution.',
  'Matrice de permutation : les lettres du message sont seulement déplacées dans chaque bloc, pas remplacées. On reconnaît tout de suite les mêmes lettres dans un autre ordre.':
    'Permutation matrix: the letters of the message are only moved within each block, not replaced. You immediately recognise the same letters in another order.',

  // ---- erreurs (main.py, encryption.py, rsa_crypto.py)
  'Indique un décalage (un entier positif).': 'Enter a shift (a positive whole number).',
  'Indique une clé (des lettres) avant de lancer.': 'Enter a key (letters) before starting.',
  'Remplis la matrice avant de lancer.': 'Fill in the matrix before starting.',
  'La matrice est vide.': 'The matrix is empty.',
  'La matrice doit être carrée (autant de lignes que de colonnes).': 'The matrix must be square (as many rows as columns).',
  'La matrice ne doit contenir que des nombres entiers.': 'The matrix must only contain whole numbers.',
  'Clé trop petite pour chiffrer un texte.': 'Key too small to encrypt a text.',
  "Un bloc chiffré est hors de l'intervalle [0, n).": 'An encrypted block is outside the range [0, n).',
  "Coffre illisible : ce n'est pas la bonne clé privée.": 'Unreadable chest: this is not the right private key.',
  'Le décalage César doit être un entier positif.': 'The Caesar shift must be a positive whole number.',
  'Direction César inconnue.': 'Unknown Caesar direction.',
  'La clé Playfair doit contenir au moins une lettre.': 'The Playfair key must contain at least one letter.',
  'Matrice non inversible modulo 26 : le destinataire ne pourrait pas déchiffrer. Choisis une autre matrice.':
    'Matrix not invertible modulo 26: the recipient could not decrypt. Choose another matrix.',
  "Mode d'emploi illisible : le coffre n'a pas été ouvert avec la bonne clé privée.":
    'Unreadable instructions: the chest was not opened with the right private key.',

  // ---- page Mots de passe : tableau des durées (passwords.py)
  'Chiffres': 'Digits',
  'Minuscules': 'Lowercase',
  '+ Majusc.': '+ Uppercase',
  '+ Chiffres': '+ Digits',
  '+ Symboles': '+ Symbols',
  'complet': 'full set',
  'instantané': 'instant',
  "moins d'une seconde": 'less than a second',

  // ---- protections rangées dans l'historique des attaques
  'Aucune': 'None',
  'symboles': 'symbols',
  'sans indice': 'no hint',
}

// unités de durée (passwords.py → human_time) : « 3 jours », « 6 mois », « 1 millénaire »…
const UNIT: Record<string, [string, string]> = {
  s: ['s', 's'], min: ['min', 'min'], h: ['h', 'h'], j: ['d', 'd'],
  jour: ['day', 'days'], jours: ['day', 'days'], mois: ['month', 'months'],
  an: ['year', 'years'], ans: ['year', 'years'],
  'siècle': ['century', 'centuries'], 'siècles': ['century', 'centuries'],
  'millénaire': ['millennium', 'millennia'], 'millénaires': ['millennium', 'millennia'],
}
// « 500 000 000 000 » (espaces français) → « 500,000,000,000 »
const enNumber = (s: string) => s.replace(/[\s  ]/g, ',').replace(/,(?=\d{1,2}$)/, '.')

export const BACKEND_PATTERNS: [RegExp, (m: RegExpMatchArray) => string][] = [
  // verrouillage de la connexion : « Trop de tentatives. Réessaie dans 15 s. »
  [/^Trop de tentatives\. Réessaie dans (\d+) s\.$/, (m) => `Too many attempts. Try again in ${m[1]} s.`],
  // durées
  [/^(\d+(?:,\d+)?) (s|min|h|j|jours?|mois|ans?|siècles?|millénaires?)$/, (m) => {
    const n = m[1].replace(',', '.')
    const [one, many] = UNIT[m[2]]
    return `${n} ${Number(n) === 1 ? one : many}`
  }],
  [/^10\^(\d+) ans$/, (m) => `10^${m[1]} years`],
  // erreurs avec une valeur
  [/^Clé invalide : son déterminant \((-?\d+)\) a un facteur commun avec (\d+), la matrice n'a donc pas d'inverse modulo \2\.( Tu peux chiffrer, mais PAS déchiffrer\.)?$/,
    (m) => `Invalid key: its determinant (${m[1]}) shares a factor with ${m[2]}, so the matrix has no inverse modulo ${m[2]}.` + (m[3] ? ' You can encrypt, but NOT decrypt.' : '')],
  [/^Algorithme inconnu « (.*) »\.$/, (m) => `Unknown algorithm "${m[1]}".`],
  [/^La lettre « (.*) » n'existe pas dans la grille\.$/, (m) => `The letter "${m[1]}" does not exist in the grid.`],
  [/^Taille de clé non prise en charge \((\d+) bits\)\.$/, (m) => `Key size not supported (${m[1]} bits).`],
  [/^(.+) n'a pas d'inverse modulo (.+)\.$/, (m) => `${m[1]} has no inverse modulo ${m[2]}.`],
  [/^Valeur invalide pour (.+)\.$/, (m) => `Invalid value for ${m[1]}.`],
  // clés César rangées dans l'historique / l'échange : « 3 (droite) », « 3 · gauche »
  [/^(.+) \((droite|gauche)\)$/, (m) => `${m[1]} (${m[2] === 'droite' ? 'right' : 'left'})`],
  [/^(.+) · (droite|gauche)$/, (m) => `${m[1]} · ${m[2] === 'droite' ? 'right' : 'left'}`],
  // protections de l'historique des attaques
  [/^([\d\s  ]+) tentatives? max$/, (m) => `${enNumber(m[1].trim())} attempt${m[1].trim() === '1' ? '' : 's'} max`],
  [/^long\. min (\d+)$/, (m) => `min. length ${m[1]}`],
  [/^exige (.+)$/, (m) => `requires ${m[1].replace('symboles', 'symbols')}`],
]
export default backend
