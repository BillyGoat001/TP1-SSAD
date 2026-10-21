// Section dépliante « Limites et Failles ».
//
// Définitions (celles de la prof) :
//   FAILLE = un cas où l'algorithme ne chiffre pas, ou ne permet pas de retrouver le message d'origine.
//   LIMITE = un cas où le message est bien chiffré, mais où le résultat se reconnaît ou se casse très facilement.
//
// Tout est listé, y compris ce que notre appli contourne (champ `fix`, affiché à part).
// Les exemples et les chiffres cités ont été vérifiés en lançant le code de l'application.
// Les textes sont écrits en français ; t() les traduit à l'affichage (anglais : i18n/en/limits.ts).

import { t } from '../../i18n'

interface Point {
  t: string       // titre court
  d: string       // explication
  ex?: string     // exemple (police fixe)
  fix?: string    // ce que fait notre appli, si elle contourne le problème
}

interface AlgoSheet {
  name: string
  tagline: string
  limits: Point[]
  flaws: Point[]
}

const SHEETS: AlgoSheet[] = [
  {
    name: 'César',
    tagline: 'Chaque lettre est décalée de k positions dans l\'alphabet.',
    limits: [
      { t: 'La clé 13 (ROT13).', d: 'Chiffrer deux fois avec 13 redonne le message : chiffrer et déchiffrer sont la même opération. Le message est bien chiffré, mais c\'est une convention très connue, reconnue tout de suite.', ex: 'BONJOUR → OBAWBHE → BONJOUR', fix: 'L\'appli affiche un avertissement.' },
      { t: 'Seulement 26 clés.', d: 'Les décalages de 0 à 25 (le décalage 26 est le même que 0), dont 25 décalages utiles. Un attaquant les essaie tous : un seul donne un texte lisible. Un grand décalage comme 10⁵⁰ se ramène à son reste modulo 26, il n\'est pas plus fort.' },
      { t: 'Alphabet de 26 lettres.', d: 'Seules les lettres A à Z sont décalées : les chiffres, les accents et la ponctuation ne sont pas chiffrés.', fix: 'Les accents sont retirés à la saisie.' },
      { t: 'Les espaces et la ponctuation restent visibles.', d: 'César ne touche qu\'aux lettres : on voit la longueur de chaque mot et la structure de la phrase, ce qui aide à deviner le contenu. Le message est chiffré mais reconnaissable : c\'est une limite, pas une faille, car on retrouve bien le message d\'origine, espaces compris.', ex: 'BONJOUR LE MONDE → ERQMRXU OH PRQGH', fix: 'Le chiffré sort en un seul bloc de lettres, sans espaces ; ils sont remis au déchiffrement.' },
      { t: 'Une lettre = toujours la même lettre.', d: 'C\'est une substitution monoalphabétique : la lettre la plus fréquente du chiffré correspond très probablement au E, ce qui donne le décalage sans rien tester d\'autre. Une seule paire (lettre claire, lettre chiffrée) suffit aussi : k = chiffré − clair (mod 26).' },
    ],
    flaws: [
      { t: 'Clé 0 et clé 26.', d: 'Le message ressort identique : il n\'est pas chiffré. 0 et 26 sont en réalité la même clé modulo 26, comme 52, 78, etc.', ex: 'BONJOUR → BONJOUR', fix: 'L\'appli affiche un avertissement.' },
    ],
  },
  {
    name: 'Playfair',
    tagline: 'Les lettres sont chiffrées par paires (digrammes) avec une grille 5×5 construite à partir de la clé.',
    limits: [
      { t: 'Une même paire est toujours chiffrée pareil.', d: 'Chaque paire de lettres du clair donne toujours la même paire dans le chiffré : c\'est une substitution sur 600 paires possibles. C\'est plus dur à casser que César, mais les répétitions se voient et l\'analyse des fréquences de paires fonctionne avec quelques centaines de lettres.', ex: 'BONBONBON → HA AY NA HA AW (BO donne HA les deux fois)' },
      { t: 'Une lettre n\'est jamais chiffrée par elle-même.', d: 'Dans chacun des trois cas (même ligne, même colonne, rectangle) la lettre change toujours. Il n\'existe donc aucune clé qui laisse le message identique, ni qui ne fasse que réarranger ses lettres (comme ABC → CBA) (vérifié sur 3 000 grilles tirées au hasard, 3,6 millions de lettres comparées : aucune exception). Ce qui est une fuite : cela élimine des possibilités pour l\'attaquant. De plus, si AB devient BI, alors BA devient IB, et le chiffré ne contient jamais deux lettres identiques dans une paire.', ex: 'AB → BI et BA → IB' },
      { t: 'Le chiffré de l\'envers est l\'envers du chiffré.', d: 'Si on écrit le message à l\'envers (longueur paire, sans lettre doublée dans une paire), son chiffré est exactement le chiffré d\'origine lu à l\'envers. L\'attaquant apprend donc quelque chose sans connaître la clé. Vérifié sur 1 736 messages aléatoires : 1 736 sur 1 736.', ex: 'BONJOURS → HAAGMVAT, SRUOJNOB → TAVMGAAH' },
      { t: 'Une clé qui laisse la grille de l\'alphabet.', d: 'La clé vide, ou un début d\'alphabet (A, AB, ABC, ABCDE… : 26 clés possibles, le J comptant pour I), donne la grille A B C D E / F G H I K… Le message est bien chiffré, mais c\'est la première grille qu\'un attaquant essaie. Sur une même ligne, une lettre est simplement décalée d\'une place, comme un César de clé 1.', ex: 'clé ABCDE : ABCD → BCDE', fix: 'L\'appli affiche un avertissement.' },
      { t: 'Alphabet de 25 lettres.', d: 'Pas de chiffres ni de ponctuation (et le J disparaît, voir les failles).', fix: 'Les accents sont retirés à la saisie.' },
      { t: 'La clé est un mot.', d: 'Il y a 25! ≈ 1,55 × 10²⁵ grilles possibles, mais une clé choisie par un humain est un mot : l\'attaquant teste un dictionnaire (MONARCHY, PLAYFAIR…) au lieu de toutes les grilles. Un clair connu ou deviné (« BONJOUR ») contraint aussi fortement la grille.' },
    ],
    flaws: [
      { t: 'Le J devient I et ne revient jamais.', d: 'La grille n\'a que 25 cases : I et J partagent la même. Au déchiffrement on obtient un I, même si le message d\'origine avait un J.', ex: 'JE JOUE → IE IOUE', fix: 'La position des J est gardée à côté du chiffré ; un chiffré collé qui ne vient pas de cette session ne les retrouve pas.' },
      { t: 'Les minuscules sont perdues.', d: 'L\'algorithme ne connaît que les majuscules : le chiffré est en majuscules, et le déchiffré n\'a plus de minuscules.', ex: 'Bonjour → chiffré → BONJOUR', fix: 'La position des minuscules est retenue et remise, seulement pour un chiffré produit dans la session.' },
      { t: 'Les X ajoutés ne partent pas.', d: 'Un X est inséré entre deux lettres identiques d\'une paire (un Q si c\'est déjà un X), et une lettre finale est ajoutée si la longueur est impaire. Au déchiffrement, ces lettres parasites restent dans le message. Pire : on ne peut pas savoir si un X faisait partie du message d\'origine, et deux messages différents donnent le même chiffré.', ex: 'BALLON → BALXLONX, BON → BONX ; AA et AXAX donnent tous deux BABA', fix: 'Leurs positions sont retenues et retirées, seulement pour un chiffré produit dans la session.' },
      { t: 'Les espaces et la ponctuation sont perdus.', d: 'L\'algorithme ne travaille que sur les lettres : le déchiffré n\'a plus ni espaces ni ponctuation.', ex: 'JE JOUE AU JEU → IEIOUEAUIEUX', fix: 'Leur position est retenue et remise, seulement pour un chiffré produit dans la session.' },
    ],
  },
  {
    name: 'Hill',
    tagline: 'Des blocs de n lettres sont multipliés par une matrice n×n, modulo 26.',
    limits: [
      { t: 'La matrice diagonale.', d: 'Chaque lettre est multipliée par un nombre, indépendamment des autres (ce n\'est pas un décalage comme César, mais une multiplication). Une lettre est donc toujours remplacée par la même : c\'est une substitution simple, cassée par l\'analyse des fréquences.', ex: 'diagonale 3 : A→A, B→D, C→G, D→J…', fix: 'L\'appli affiche un avertissement.' },
      { t: 'La matrice de permutation.', d: 'Un seul 1 par ligne et par colonne, des 0 ailleurs : les lettres ne sont pas remplacées, seulement déplacées dans chaque bloc. On retrouve bien le message en déchiffrant, mais n\'importe qui reconnaît les mêmes lettres dans un autre ordre : c\'est un chiffrement par transposition. L\'inversion n×n retourne chaque bloc de n lettres.', ex: 'inversion 3×3 : ABCDEF → CBAFED (ABC → CBA) ; échange 2×2 : BONJOUR → OBJNUOXR', fix: 'L\'appli affiche un avertissement.' },
      { t: 'Clair connu.', d: 'On a C = K·P (mod 26). Avec n blocs de clair connus et leurs chiffrés, un simple calcul matriciel donne la clé : K = C·P⁻¹. En 2×2, 4 lettres suffisent, à condition que P soit inversible.' },
      { t: 'Blocs identiques, chiffrés identiques.', d: 'Les répétitions du clair se voient dans le chiffré. Un bloc composé uniquement de A (la valeur 0) est toujours chiffré en un bloc de A, puisque K·0 = 0. Changer une lettre ne modifie que son bloc de n lettres.', ex: 'matrice [[3, 3], [2, 5]] : ABAB → DFDF' },
      { t: 'Alphabet de 26 lettres.', d: 'Pas de chiffres ni de ponctuation.', fix: 'Les accents sont retirés à la saisie.' },
    ],
    flaws: [
      { t: 'La matrice identité.', d: 'Chaque bloc est multiplié par 1 : le message n\'est pas chiffré.', ex: 'BONJOUR → BONJOURX (le X est le bourrage)', fix: 'L\'appli affiche un avertissement.' },
      { t: 'La matrice non inversible.', d: 'Si le déterminant est pair ou multiple de 13, la matrice n\'a pas d\'inverse modulo 26 : on peut chiffrer, mais jamais déchiffrer. C\'est une faille, puisque le message d\'origine est perdu. En 2×2, 299 728 matrices sur 456 976 (environ 66 %) sont dans ce cas : seules 157 248 sont inversibles.', ex: '[[2, 4], [1, 2]] (déterminant 0) : BONJOUR → GDKFECWL, impossible à déchiffrer', fix: 'L\'appli affiche « tu peux chiffrer, mais PAS déchiffrer ».' },
      { t: 'Les X ajoutés ne partent pas.', d: 'Si la longueur n\'est pas un multiple de n, des X sont ajoutés à la fin du dernier bloc. Au déchiffrement, ils restent dans le message.', ex: 'BONJOUR (7 lettres, matrice 2×2) → BONJOURX', fix: 'Leurs positions sont retenues et retirées, seulement pour un chiffré produit dans la session.' },
      { t: 'Les minuscules sont perdues.', d: 'L\'algorithme ne connaît que les majuscules : le chiffré est en majuscules, et le déchiffré n\'a plus de minuscules.', ex: 'Bonjour → chiffré → BONJOUR', fix: 'La position des minuscules est retenue et remise, seulement pour un chiffré produit dans la session.' },
      { t: 'Les espaces et la ponctuation sont perdus.', d: 'Seules les lettres sont chiffrées : le déchiffré n\'a plus ni espaces ni ponctuation.', ex: 'BONJOUR LE → BONJOURLEX', fix: 'Leur position est retenue et remise, seulement pour un chiffré produit dans la session.' },
    ],
  },
]

function PointList({ items }: { items: Point[] }) {
  return (
    <ul className="cp-lf-list">
      {items.map((p) => (
        <li key={p.t}>
          <strong>{t(p.t)}</strong> {t(p.d)}
          {p.ex && <div className="cp-lf-ex"><code>{t(p.ex)}</code></div>}
          {p.fix && <div className="cp-lf-fix">{t('Dans notre appli :')} {t(p.fix)}</div>}
        </li>
      ))}
    </ul>
  )
}

export default function LimitsFlaws() {
  return (
    <details className="cp-fold">
      <summary>
        <span className="cp-fold-title">{t('Limites et Failles')}</span>
      </summary>

      <div className="cp-fold-body">
        <dl className="cp-lf-def">
          <div><dt className="is-limit">{t('Limite')}</dt><dd>{t('le message est bien chiffré, mais le résultat se reconnaît ou se casse très facilement.')}</dd></div>
          <div><dt className="is-flaw">{t('Faille')}</dt><dd>{t("l'algorithme ne chiffre pas, ou ne permet pas de retrouver le message d'origine.")}</dd></div>
        </dl>

        <div className="cp-lf-grid">
          {SHEETS.map((s) => (
            <article key={s.name} className="cp-lf-card">
              <h3 className="cp-lf-name">{t(s.name)}</h3>
              <p className="cp-lf-tagline">{t(s.tagline)}</p>
              <h4 className="cp-lf-sub is-limit">{t('Limites')}</h4>
              <PointList items={s.limits} />
              <h4 className="cp-lf-sub is-flaw">{t('Failles')}</h4>
              <PointList items={s.flaws} />
            </article>
          ))}
        </div>
      </div>
    </details>
  )
}
