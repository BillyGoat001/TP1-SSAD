// Section « Limites et Failles » (LimitsFlaws.tsx)
const limits: Record<string, string> = {
  'Limites et Failles': 'Limitations and Flaws',
  'Limite': 'Limitation',
  'Limites': 'Limitations',
  'Faille': 'Flaw',
  'Failles': 'Flaws',
  'Dans notre appli :': 'In our app:',
  'le message est bien chiffré, mais le résultat se reconnaît ou se casse très facilement.':
    'the message is encrypted, but the result is easy to recognise or to break.',
  "l'algorithme ne chiffre pas, ou ne permet pas de retrouver le message d'origine.":
    'the algorithm does not encrypt, or the original message cannot be recovered.',

  // ---- César
  'César': 'Caesar',
  "Chaque lettre est décalée de k positions dans l'alphabet.": 'Each letter is shifted by k positions in the alphabet.',
  'La clé 13 (ROT13).': 'Key 13 (ROT13).',
  "Chiffrer deux fois avec 13 redonne le message : chiffrer et déchiffrer sont la même opération. Le message est bien chiffré, mais c'est une convention très connue, reconnue tout de suite.":
    'Encrypting twice with 13 gives the message back: encrypting and decrypting are the same operation. The message is encrypted, but it is a very well-known convention, recognised straight away.',
  "L'appli affiche un avertissement.": 'The app shows a warning.',
  'Seulement 26 clés.': 'Only 26 keys.',
  "Les décalages de 0 à 25 (le décalage 26 est le même que 0), dont 25 décalages utiles. Un attaquant les essaie tous : un seul donne un texte lisible. Un grand décalage comme 10⁵⁰ se ramène à son reste modulo 26, il n'est pas plus fort.":
    'Shifts from 0 to 25 (shift 26 is the same as 0), of which 25 are useful. An attacker tries them all: only one gives a readable text. A big shift such as 10⁵⁰ comes down to its remainder modulo 26, it is not any stronger.',
  'Alphabet de 26 lettres.': '26-letter alphabet.',
  'Seules les lettres A à Z sont décalées : les chiffres, les accents et la ponctuation ne sont pas chiffrés.':
    'Only the letters A to Z are shifted: digits, accents and punctuation are not encrypted.',
  'Les accents sont retirés à la saisie.': 'Accents are removed while typing.',
  'Les espaces et la ponctuation restent visibles.': 'Spaces and punctuation stay visible.',
  "César ne touche qu'aux lettres : on voit la longueur de chaque mot et la structure de la phrase, ce qui aide à deviner le contenu. Le message est chiffré mais reconnaissable : c'est une limite, pas une faille, car on retrouve bien le message d'origine, espaces compris.":
    'Caesar only changes letters: you can see the length of each word and the structure of the sentence, which helps to guess the content. The message is encrypted but recognisable: it is a limitation, not a flaw, because the original message is recovered, spaces included.',
  'Le chiffré sort en un seul bloc de lettres, sans espaces ; ils sont remis au déchiffrement.':
    'The ciphertext comes out as one single block of letters, without spaces; they are put back when decrypting.',
  'Une lettre = toujours la même lettre.': 'One letter = always the same letter.',
  "C'est une substitution monoalphabétique : la lettre la plus fréquente du chiffré correspond très probablement au E, ce qui donne le décalage sans rien tester d'autre. Une seule paire (lettre claire, lettre chiffrée) suffit aussi : k = chiffré − clair (mod 26).":
    'It is a monoalphabetic substitution: the most frequent letter of the ciphertext very probably stands for E, which gives the shift without testing anything else. A single pair (plain letter, encrypted letter) is also enough: k = cipher − plain (mod 26).',
  'Clé 0 et clé 26.': 'Key 0 and key 26.',
  "Le message ressort identique : il n'est pas chiffré. 0 et 26 sont en réalité la même clé modulo 26, comme 52, 78, etc.":
    'The message comes out unchanged: it is not encrypted. 0 and 26 are actually the same key modulo 26, like 52, 78, etc.',

  // ---- Playfair
  'Les lettres sont chiffrées par paires (digrammes) avec une grille 5×5 construite à partir de la clé.':
    'Letters are encrypted in pairs (digrams) with a 5×5 grid built from the key.',
  'Une même paire est toujours chiffrée pareil.': 'The same pair is always encrypted the same way.',
  "Chaque paire de lettres du clair donne toujours la même paire dans le chiffré : c'est une substitution sur 600 paires possibles. C'est plus dur à casser que César, mais les répétitions se voient et l'analyse des fréquences de paires fonctionne avec quelques centaines de lettres.":
    'Each pair of plaintext letters always gives the same pair in the ciphertext: it is a substitution over 600 possible pairs. It is harder to break than Caesar, but repetitions show and pair-frequency analysis works with a few hundred letters.',
  'BONBONBON → HA AY NA HA AW (BO donne HA les deux fois)': 'BONBONBON → HA AY NA HA AW (BO gives HA both times)',
  "Une lettre n'est jamais chiffrée par elle-même.": 'A letter is never encrypted as itself.',
  "Dans chacun des trois cas (même ligne, même colonne, rectangle) la lettre change toujours. Il n'existe donc aucune clé qui laisse le message identique, ni qui ne fasse que réarranger ses lettres (comme ABC → CBA) (vérifié sur 3 000 grilles tirées au hasard, 3,6 millions de lettres comparées : aucune exception). Ce qui est une fuite : cela élimine des possibilités pour l'attaquant. De plus, si AB devient BI, alors BA devient IB, et le chiffré ne contient jamais deux lettres identiques dans une paire.":
    'In each of the three cases (same row, same column, rectangle) the letter always changes. So there is no key that leaves the message unchanged, nor one that only rearranges its letters (like ABC → CBA) (checked on 3,000 random grids, 3.6 million letters compared: no exception). This is a leak: it rules out possibilities for the attacker. Also, if AB becomes BI, then BA becomes IB, and the ciphertext never contains two identical letters in a pair.',
  'AB → BI et BA → IB': 'AB → BI and BA → IB',
  "Le chiffré de l'envers est l'envers du chiffré.": 'The ciphertext of the reverse is the reverse of the ciphertext.',
  "Si on écrit le message à l'envers (longueur paire, sans lettre doublée dans une paire), son chiffré est exactement le chiffré d'origine lu à l'envers. L'attaquant apprend donc quelque chose sans connaître la clé. Vérifié sur 1 736 messages aléatoires : 1 736 sur 1 736.":
    'If the message is written backwards (even length, no doubled letter in a pair), its ciphertext is exactly the original ciphertext read backwards. So the attacker learns something without knowing the key. Checked on 1,736 random messages: 1,736 out of 1,736.',
  "Une clé qui laisse la grille de l'alphabet.": 'A key that leaves the alphabet grid.',
  "La clé vide, ou un début d'alphabet (A, AB, ABC, ABCDE… : 26 clés possibles, le J comptant pour I), donne la grille A B C D E / F G H I K… Le message est bien chiffré, mais c'est la première grille qu'un attaquant essaie. Sur une même ligne, une lettre est simplement décalée d'une place, comme un César de clé 1.":
    'The empty key, or the start of the alphabet (A, AB, ABC, ABCDE…: 26 possible keys, J counting as I), gives the grid A B C D E / F G H I K… The message is encrypted, but it is the first grid an attacker tries. On the same row, a letter is simply shifted by one place, like a Caesar with key 1.',
  'clé ABCDE : ABCD → BCDE': 'key ABCDE: ABCD → BCDE',
  'Alphabet de 25 lettres.': '25-letter alphabet.',
  'Pas de chiffres ni de ponctuation (et le J disparaît, voir les failles).': 'No digits or punctuation (and J disappears, see the flaws).',
  'La clé est un mot.': 'The key is a word.',
  "Il y a 25! ≈ 1,55 × 10²⁵ grilles possibles, mais une clé choisie par un humain est un mot : l'attaquant teste un dictionnaire (MONARCHY, PLAYFAIR…) au lieu de toutes les grilles. Un clair connu ou deviné (« BONJOUR ») contraint aussi fortement la grille.":
    'There are 25! ≈ 1.55 × 10²⁵ possible grids, but a key chosen by a human is a word: the attacker tries a dictionary (MONARCHY, PLAYFAIR…) instead of every grid. A known or guessed plaintext ("BONJOUR") also strongly constrains the grid.',
  'Le J devient I et ne revient jamais.': 'J becomes I and never comes back.',
  "La grille n'a que 25 cases : I et J partagent la même. Au déchiffrement on obtient un I, même si le message d'origine avait un J.":
    'The grid only has 25 cells: I and J share the same one. When decrypting you get an I, even if the original message had a J.',
  'La position des J est gardée à côté du chiffré ; un chiffré collé qui ne vient pas de cette session ne les retrouve pas.':
    'The position of the Js is kept next to the ciphertext; a pasted ciphertext that does not come from this session does not get them back.',
  'Les minuscules sont perdues.': 'Lowercase letters are lost.',
  "L'algorithme ne connaît que les majuscules : le chiffré est en majuscules, et le déchiffré n'a plus de minuscules.":
    'The algorithm only knows capital letters: the ciphertext is in capitals, and the decrypted text has no lowercase letters any more.',
  'Bonjour → chiffré → BONJOUR': 'Bonjour → encrypted → BONJOUR',
  'La position des minuscules est retenue et remise, seulement pour un chiffré produit dans la session.':
    'The position of the lowercase letters is remembered and restored, only for a ciphertext produced in this session.',
  'Les X ajoutés ne partent pas.': 'The added Xs do not go away.',
  "Un X est inséré entre deux lettres identiques d'une paire (un Q si c'est déjà un X), et une lettre finale est ajoutée si la longueur est impaire. Au déchiffrement, ces lettres parasites restent dans le message. Pire : on ne peut pas savoir si un X faisait partie du message d'origine, et deux messages différents donnent le même chiffré.":
    'An X is inserted between two identical letters of a pair (a Q if it is already an X), and a final letter is added if the length is odd. When decrypting, these extra letters stay in the message. Worse: you cannot tell whether an X was part of the original message, and two different messages give the same ciphertext.',
  'BALLON → BALXLONX, BON → BONX ; AA et AXAX donnent tous deux BABA': 'BALLON → BALXLONX, BON → BONX; AA and AXAX both give BABA',
  'Leurs positions sont retenues et retirées, seulement pour un chiffré produit dans la session.':
    'Their positions are remembered and removed, only for a ciphertext produced in this session.',
  'Les espaces et la ponctuation sont perdus.': 'Spaces and punctuation are lost.',
  "L'algorithme ne travaille que sur les lettres : le déchiffré n'a plus ni espaces ni ponctuation.":
    'The algorithm only works on letters: the decrypted text has no spaces or punctuation any more.',
  'Leur position est retenue et remise, seulement pour un chiffré produit dans la session.':
    'Their position is remembered and restored, only for a ciphertext produced in this session.',

  // ---- Hill
  'Des blocs de n lettres sont multipliés par une matrice n×n, modulo 26.': 'Blocks of n letters are multiplied by an n×n matrix, modulo 26.',
  'La matrice diagonale.': 'The diagonal matrix.',
  "Chaque lettre est multipliée par un nombre, indépendamment des autres (ce n'est pas un décalage comme César, mais une multiplication). Une lettre est donc toujours remplacée par la même : c'est une substitution simple, cassée par l'analyse des fréquences.":
    'Each letter is multiplied by a number, independently of the others (it is not a shift like Caesar, but a multiplication). So a letter is always replaced by the same one: it is a simple substitution, broken by frequency analysis.',
  'diagonale 3 : A→A, B→D, C→G, D→J…': 'diagonal 3: A→A, B→D, C→G, D→J…',
  'La matrice de permutation.': 'The permutation matrix.',
  "Un seul 1 par ligne et par colonne, des 0 ailleurs : les lettres ne sont pas remplacées, seulement déplacées dans chaque bloc. On retrouve bien le message en déchiffrant, mais n'importe qui reconnaît les mêmes lettres dans un autre ordre : c'est un chiffrement par transposition. L'inversion n×n retourne chaque bloc de n lettres.":
    'A single 1 per row and per column, 0s everywhere else: letters are not replaced, only moved within each block. The message is recovered when decrypting, but anyone can recognise the same letters in another order: it is a transposition cipher. The n×n reversal flips each block of n letters.',
  'inversion 3×3 : ABCDEF → CBAFED (ABC → CBA) ; échange 2×2 : BONJOUR → OBJNUOXR': '3×3 reversal: ABCDEF → CBAFED (ABC → CBA); 2×2 swap: BONJOUR → OBJNUOXR',
  'Clair connu.': 'Known plaintext.',
  'On a C = K·P (mod 26). Avec n blocs de clair connus et leurs chiffrés, un simple calcul matriciel donne la clé : K = C·P⁻¹. En 2×2, 4 lettres suffisent, à condition que P soit inversible.':
    'We have C = K·P (mod 26). With n known plaintext blocks and their ciphertexts, a simple matrix calculation gives the key: K = C·P⁻¹. In 2×2, 4 letters are enough, provided P is invertible.',
  'Blocs identiques, chiffrés identiques.': 'Identical blocks, identical ciphertexts.',
  'Les répétitions du clair se voient dans le chiffré. Un bloc composé uniquement de A (la valeur 0) est toujours chiffré en un bloc de A, puisque K·0 = 0. Changer une lettre ne modifie que son bloc de n lettres.':
    'Repetitions in the plaintext show in the ciphertext. A block made only of A (the value 0) is always encrypted as a block of A, since K·0 = 0. Changing one letter only changes its block of n letters.',
  'matrice [[3, 3], [2, 5]] : ABAB → DFDF': 'matrix [[3, 3], [2, 5]]: ABAB → DFDF',
  'Pas de chiffres ni de ponctuation.': 'No digits or punctuation.',
  'La matrice identité.': 'The identity matrix.',
  "Chaque bloc est multiplié par 1 : le message n'est pas chiffré.": 'Each block is multiplied by 1: the message is not encrypted.',
  'BONJOUR → BONJOURX (le X est le bourrage)': 'BONJOUR → BONJOURX (the X is padding)',
  'La matrice non inversible.': 'The non-invertible matrix.',
  "Si le déterminant est pair ou multiple de 13, la matrice n'a pas d'inverse modulo 26 : on peut chiffrer, mais jamais déchiffrer. C'est une faille, puisque le message d'origine est perdu. En 2×2, 299 728 matrices sur 456 976 (environ 66 %) sont dans ce cas : seules 157 248 sont inversibles.":
    'If the determinant is even or a multiple of 13, the matrix has no inverse modulo 26: you can encrypt, but never decrypt. It is a flaw, since the original message is lost. In 2×2, 299,728 matrices out of 456,976 (about 66%) are in this case: only 157,248 are invertible.',
  '[[2, 4], [1, 2]] (déterminant 0) : BONJOUR → GDKFECWL, impossible à déchiffrer': '[[2, 4], [1, 2]] (determinant 0): BONJOUR → GDKFECWL, impossible to decrypt',
  "L'appli affiche « tu peux chiffrer, mais PAS déchiffrer ».": 'The app shows "you can encrypt, but NOT decrypt".',
  "Si la longueur n'est pas un multiple de n, des X sont ajoutés à la fin du dernier bloc. Au déchiffrement, ils restent dans le message.":
    'If the length is not a multiple of n, Xs are added at the end of the last block. When decrypting, they stay in the message.',
  'BONJOUR (7 lettres, matrice 2×2) → BONJOURX': 'BONJOUR (7 letters, 2×2 matrix) → BONJOURX',
  "Seules les lettres sont chiffrées : le déchiffré n'a plus ni espaces ni ponctuation.":
    'Only letters are encrypted: the decrypted text has no spaces or punctuation any more.',
}
export default limits
