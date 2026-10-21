// Import de fichiers (fileImport.ts, FilePick.tsx)
const files: Record<string, string> = {
  'Une ligne par rangée de la matrice, les nombres séparés par un espace (la virgule, le point-virgule et la tabulation sont aussi acceptés). Entiers positifs ou négatifs, sans crochets ni lettres. La matrice doit être carrée, de {min}×{min} à {max}×{max}. Exemple en 2×2 :':
    'One line per row of the matrix, numbers separated by a space (commas, semicolons and tabs are also accepted). Positive or negative integers, no brackets or letters. The matrix must be square, from {min}×{min} to {max}×{max}. Example for 2×2:',
  "Ce n'est pas un fichier texte lisible en UTF-8. C'est soit un fichier binaire (image, PDF, Word, archive…), soit un texte enregistré en ANSI / Latin-1 avec des accents : réenregistre-le en UTF-8.":
    "This is not a text file readable as UTF-8. It is either a binary file (image, PDF, Word, archive…) or a text saved as ANSI / Latin-1 with accents: save it again as UTF-8.",
  "Ce n'est pas un fichier texte : il contient des octets binaires (image, PDF, Word, archive… ?).":
    'This is not a text file: it contains binary bytes (image, PDF, Word, archive…?).',
  'Le fichier est trop gros ({size} Ko) : au plus {max} Ko.': 'The file is too big ({size} KB): {max} KB at most.',
  "Le fichier n'a pas pu être lu.": 'The file could not be read.',
  'Le fichier est vide : il doit contenir le décalage, par exemple 3.': 'The file is empty: it must contain the shift, for example 3.',
  'Il contient plusieurs lignes (ou une ligne vide au début) : une seule ligne avec un seul nombre.':
    'It contains several lines (or an empty line at the start): one single line with one single number.',
  'Il commence par un signe ({sign}) : le décalage est un nombre positif, sans signe.': 'It starts with a sign ({sign}): the shift is a positive number, with no sign.',
  "Il contient {n} (au début, à la fin ou au milieu) : aucun espace n'est accepté.": 'It contains {n} (at the start, the end or in the middle): no spaces are allowed.',
  'espace ou tabulation': 'space or tab',
  'espaces ou tabulations': 'spaces or tabs',
  'Il contient des lettres : {list}.': 'It contains letters: {list}.',
  'Il contient des caractères qui ne sont pas des chiffres : {list}{dec}.': 'It contains characters that are not digits: {list}{dec}.',
  ' (pas de nombre décimal : un entier)': ' (no decimal number: a whole number)',
  'Il contient un signe + ou − : seuls les chiffres 0 à 9 sont acceptés.': 'It contains a + or − sign: only the digits 0 to 9 are accepted.',
  'Le nombre est trop long ({n} chiffres) : au plus {max} chiffres.': 'The number is too long ({n} digits): {max} digits at most.',
  'décalage {v}': 'shift {v}',
  'Le fichier est vide : il doit contenir le mot-clé, par exemple PLAYFAIR.': 'The file is empty: it must contain the keyword, for example PLAYFAIR.',
  'Il contient plusieurs lignes (ou une ligne vide au début) : une seule ligne avec le mot-clé.':
    'It contains several lines (or an empty line at the start): one single line with the keyword.',
  'Il contient des chiffres : {list}.': 'It contains digits: {list}.',
  'Il contient des lettres hors A–Z (accents ou autre alphabet) : {list}. Écris-les sans accent.':
    'It contains letters outside A–Z (accents or another alphabet): {list}. Write them without accents.',
  'Il contient des caractères spéciaux : {list}.': 'It contains special characters: {list}.',
  '→ (tabulation)': '→ (tab)',
  'Le mot-clé est trop long : au plus {max} lettres.': 'The keyword is too long: {max} letters at most.',
  'clé {v}': 'key {v}',
  'Le fichier est vide : il doit contenir la matrice.': 'The file is empty: it must contain the matrix.',
  '{tok} (ligne {r}, valeur {c})': '{tok} (line {r}, value {c})',
  'Ces éléments ne sont pas des nombres entiers : {list}. Pas de lettres, de crochets, de parenthèses, de virgule décimale ni de signe + .':
    'These items are not whole numbers: {list}. No letters, brackets, parentheses, decimal points or + sign.',
  "Cet élément n'est pas un nombre entier : {list}. Pas de lettres, de crochets, de parenthèses, de virgule décimale ni de signe + .":
    'This item is not a whole number: {list}. No letters, brackets, parentheses, decimal points or + sign.',
  'Un nombre est trop long (ligne {r}) : au plus {max} chiffres.': 'A number is too long (line {r}): {max} digits at most.',
  'Tous les nombres sont sur une seule ligne ({n} nombres) : écris une ligne par rangée de la matrice.':
    'All the numbers are on one single line ({n} numbers): write one line per row of the matrix.',
  "Les lignes n'ont pas toutes le même nombre de valeurs : la ligne 1 en a {a}, la ligne {r} en a {b}.":
    'The lines do not all have the same number of values: line 1 has {a}, line {r} has {b}.',
  "La matrice n'est pas carrée : {rows} de {cols}. Il faut autant de lignes que de valeurs par ligne.":
    'The matrix is not square: {rows} of {cols}. There must be as many lines as values per line.',
  'ligne': 'line', 'lignes': 'lines', 'valeur': 'value', 'valeurs': 'values',
  'Taille {n}×{n} non acceptée : de {min}×{min} à {max}×{max}.': 'Size {n}×{n} not accepted: from {min}×{min} to {max}×{max}.',
  'matrice {n}×{n}': '{n}×{n} matrix',
  'Le fichier est vide : il doit contenir un message.': 'The file is empty: it must contain a message.',
  "Il contient des lettres hors de l'alphabet A–Z : {list}. Elles ne peuvent pas être chiffrées (supprimées ou refusées selon l'algorithme).":
    'It contains letters outside the A–Z alphabet: {list}. They cannot be encrypted (removed or refused depending on the algorithm).',
  'Il contient {n}.': 'It contains {n}.',
  'caractère de contrôle invisible': 'invisible control character',
  'caractères de contrôle invisibles': 'invisible control characters',
  "Il ne contient aucune lettre (A–Z) : seules les lettres sont chiffrées, il n'y aurait rien à chiffrer.":
    'It contains no letter (A–Z): only letters are encrypted, there would be nothing to encrypt.',
  'Il est trop long ({n} caractères) : au plus {max}.': 'It is too long ({n} characters): {max} at most.',
  'lettre': 'letter', 'lettres': 'letters',
  'autre caractère non chiffré': 'other character not encrypted',
  'autres caractères non chiffrés': 'other characters not encrypted',
  '(conservé tel quel)': '(kept as is)',
  '(conservés tels quels)': '(kept as is)',
  // FilePick.tsx
  '✓ {name} chargé : {info}.': '✓ {name} loaded: {info}.',
  "Fermer l'avertissement": 'Close the warning',
  'Fermer': 'Close',
  '{name} ne peut pas servir de {what}.': '{name} cannot be used as {what}.',
  'Contenu lu :': 'Content read:',
  'Format accepté pour une clé Hill :': 'Accepted format for a Hill key:',
}
export default files
