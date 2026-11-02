// Import d'UN fichier texte (.txt, .md, .key… : l'extension n'a aucune importance,
// seul le CONTENU compte) et verification de ce contenu :
//   - est-ce une cle valable pour l'algorithme choisi (Cesar / Playfair / Hill) ?
//   - est-ce un message valable ?
// Rien n'est modifie a l'ecran tant que le contenu n'est pas juge valable : sinon on renvoie
// un « probleme » avec la liste de ce qui ne va pas (et, pour Hill, le format accepte).
// Les messages sont ecrits dans la langue choisie au moment de l'import (voir i18n).

import { t, _t, getLang, num, plural as pl } from '../../i18n'

export interface Problem {
  /** Ce qui ne va pas, une raison par ligne. */
  reasons: string[]
  /** Le contenu lu, avec les espaces rendus visibles (aide a reperer l'invisible). */
  seen?: string
  /** Format accepte, a afficher tel quel (police fixe). */
  format?: { text: string; example: string }
}

export type Checked<T> = { ok: true; value: T; info: string } | { ok: false; problem: Problem }

export const MAX_FILE_BYTES = 200 * 1024   // au-dela ce n'est plus une cle ni un message de TP
export const MAX_SHIFT_DIGITS = 200        // meme borne que le backend
export const MAX_KEY_LETTERS = 200
export const MAX_MESSAGE_CHARS = 4000      // l'historique et la conversation acceptent 5000 caracteres
export const HILL_MIN = 2
export const HILL_MAX = 5

export const HILL_FORMAT_TEXT = _t('Une ligne par rangée de la matrice, les nombres séparés par un espace (la virgule, le point-virgule et la tabulation sont aussi acceptés). Entiers positifs ou négatifs, sans crochets ni lettres. La matrice doit être carrée, de {min}×{min} à {max}×{max}. Exemple en 2×2 :')
export const HILL_FORMAT = {
  get text() { return t(HILL_FORMAT_TEXT, { min: HILL_MIN, max: HILL_MAX }) },
  example: '3 3\n2 5',
}

const fail = (reasons: string[], extra: Partial<Problem> = {}): Checked<never> => ({
  ok: false, problem: { reasons, ...extra },
})

// Les espaces et tabulations rendus visibles : « 3 4 » → « 3·4 », tabulation → « → ».
function visible(s: string): string {
  const one = s.replace(/\n/g, '⏎').replace(/ /g, '·').replace(/\t/g, '→')
  return one.length > 60 ? one.slice(0, 60) + '…' : one
}

// Au plus 5 caracteres distincts, entre guillemets (francais « x », anglais "x").
const q = (c: string) => (getLang() === 'en' ? `"${c}"` : `« ${c} »`)
function quote(chars: string[]): string {
  const uniq = [...new Set(chars)]
  const shown = uniq.slice(0, 5).map(q).join(', ')
  return uniq.length > 5 ? `${shown}…` : shown
}

// « 3 lignes » : le nombre puis le mot, accorde et traduit
const plural = (n: number, one: string, many: string) => `${num(n)} ${t(pl(n, one, many))}`

// ------------------------------------------------------------ lecture -------

/** Texte d'un fichier lu en octets : UTF-8 (avec ou sans BOM) ou UTF-16 avec BOM
 *  (le « Unicode » du Bloc-notes). Un fichier binaire est refuse. Fins de ligne → \n. */
export function decodeText(buf: ArrayBuffer): Checked<string> {
  const b = new Uint8Array(buf)
  let label = 'utf-8'
  if (b[0] === 0xff && b[1] === 0xfe) label = 'utf-16le'
  else if (b[0] === 0xfe && b[1] === 0xff) label = 'utf-16be'
  let text: string
  try {
    text = new TextDecoder(label, { fatal: true }).decode(b)
  } catch {
    return fail([t("Ce n'est pas un fichier texte lisible en UTF-8. C'est soit un fichier binaire (image, PDF, Word, archive…), soit un texte enregistré en ANSI / Latin-1 avec des accents : réenregistre-le en UTF-8.")])
  }
  if (text.includes('\u0000')) {
    return fail([t("Ce n'est pas un fichier texte : il contient des octets binaires (image, PDF, Word, archive… ?).")])
  }
  text = text.replace(/^﻿/, '').replace(/\r\n?/g, '\n')
  return { ok: true, value: text, info: '' }
}

export async function readTextFile(file: File): Promise<Checked<string>> {
  if (file.size > MAX_FILE_BYTES) {
    return fail([t('Le fichier est trop gros ({size} Ko) : au plus {max} Ko.', { size: num(Math.ceil(file.size / 1024)), max: MAX_FILE_BYTES / 1024 })])
  }
  let buf: ArrayBuffer
  try {
    buf = await file.arrayBuffer()
  } catch {
    return fail([t('Le fichier n\'a pas pu être lu.')])
  }
  return decodeText(buf)
}

// ------------------------------------------------------------ Cesar ---------

/** Decalage : uniquement des chiffres (nombre positif, sans signe, sans espace, sans lettre). */
export function checkCaesarKey(raw: string): Checked<string> {
  const text = raw.replace(/\n+$/, '')                  // un retour a la ligne final est tolere
  if (text.trim() === '') return fail([t('Le fichier est vide : il doit contenir le décalage, par exemple 3.')])

  const reasons: string[] = []
  if (text.includes('\n')) reasons.push(t('Il contient plusieurs lignes (ou une ligne vide au début) : une seule ligne avec un seul nombre.'))
  const flat = text.replace(/\n/g, '')
  if (/^\s*[+\-−–]/.test(flat)) reasons.push(t('Il commence par un signe ({sign}) : le décalage est un nombre positif, sans signe.', { sign: q(flat.trim()[0]) }))
  const blanks = (flat.match(/[ \t ]/g) ?? []).length
  if (blanks) reasons.push(t('Il contient {n} (au début, à la fin ou au milieu) : aucun espace n\'est accepté.', { n: plural(blanks, 'espace ou tabulation', 'espaces ou tabulations') }))
  const letters = flat.match(/\p{L}/gu) ?? []
  if (letters.length) reasons.push(t('Il contient des lettres : {list}.', { list: quote(letters) }))
  const others = (flat.replace(/[ \t ]/g, '').match(/[^\d\p{L}+\-−–]/gu) ?? [])
  if (others.length) {
    const dec = others.some((c) => c === '.' || c === ',')
    reasons.push(t('Il contient des caractères qui ne sont pas des chiffres : {list}{dec}.', { list: quote(others), dec: dec ? t(' (pas de nombre décimal : un entier)') : '' }))
  }
  // un signe au milieu (« 3-4 »)
  if (!/^\s*[+\-−–]/.test(flat) && /[+\-−–]/.test(flat)) reasons.push(t('Il contient un signe + ou − : seuls les chiffres 0 à 9 sont acceptés.'))
  if (reasons.length) return fail(reasons, { seen: visible(text) })

  if (flat.length > MAX_SHIFT_DIGITS) return fail([t('Le nombre est trop long ({n} chiffres) : au plus {max} chiffres.', { n: flat.length, max: MAX_SHIFT_DIGITS })])
  const value = flat.replace(/^0+(?=\d)/, '')
  return { ok: true, value, info: t('décalage {v}', { v: value.length > 24 ? value.slice(0, 24) + '…' : value }) }
}

// ------------------------------------------------------------ Playfair ------

/** Mot-cle : des lettres A–Z (majuscules ou minuscules), espaces autorises entre les mots. */
export function checkPlayfairKey(raw: string): Checked<string> {
  const text = raw.replace(/\n+$/, '')
  if (text.trim() === '') return fail([t('Le fichier est vide : il doit contenir le mot-clé, par exemple PLAYFAIR.')])

  const reasons: string[] = []
  if (text.includes('\n')) reasons.push(t('Il contient plusieurs lignes (ou une ligne vide au début) : une seule ligne avec le mot-clé.'))
  const flat = text.replace(/\n/g, '')
  const digits = flat.match(/\d/g) ?? []
  if (digits.length) reasons.push(t('Il contient des chiffres : {list}.', { list: quote(digits) }))
  const accented = (flat.match(/\p{L}/gu) ?? []).filter((c) => !/^[A-Za-z]$/.test(c))
  if (accented.length) reasons.push(t('Il contient des lettres hors A–Z (accents ou autre alphabet) : {list}. Écris-les sans accent.', { list: quote(accented) }))
  const others = flat.match(/[^A-Za-z \d\p{L}]/gu) ?? []
  if (others.length) reasons.push(t('Il contient des caractères spéciaux : {list}.', { list: quote(others.map((c) => (c === '\t' ? t('→ (tabulation)') : c))) }))
  if (reasons.length) return fail(reasons, { seen: visible(text) })

  const word = flat.replace(/\s+/g, ' ').trim().toUpperCase()
  if (word.replace(/ /g, '').length > MAX_KEY_LETTERS) return fail([t('Le mot-clé est trop long : au plus {max} lettres.', { max: MAX_KEY_LETTERS })])
  return { ok: true, value: word, info: t('clé {v}', { v: word.length > 30 ? word.slice(0, 30) + '…' : word }) }
}

// ------------------------------------------------------------ Hill ----------

/** Matrice ecrite dans un fichier texte : une ligne par rangee, nombres separes par des
 *  espaces (virgule, point-virgule ou tabulation acceptes). Carree, de 2×2 a 5×5. */
export function checkHillKey(raw: string): Checked<string[][]> {
  const fmt = { format: HILL_FORMAT }
  const lines = raw.split('\n').map((l) => l.trim()).filter((l) => l !== '')   // lignes vides ignorees
  if (lines.length === 0) return fail([t('Le fichier est vide : il doit contenir la matrice.')], fmt)

  const rows = lines.map((l) => l.split(/[\s,;]+/).filter((t) => t !== ''))
  const reasons: string[] = []

  // 1. chaque element doit etre un entier
  const bad: string[] = []
  rows.forEach((row, r) => row.forEach((tok, c) => {
    if (!/^-?\d+$/.test(tok) && bad.length < 40) bad.push(t('{tok} (ligne {r}, valeur {c})', { tok: q(tok), r: r + 1, c: c + 1 }))
  }))
  if (bad.length) {
    const shown = bad.slice(0, 4).join(', ') + (bad.length > 4 ? '…' : '')
    reasons.push(t(bad.length > 1
      ? 'Ces éléments ne sont pas des nombres entiers : {list}. Pas de lettres, de crochets, de parenthèses, de virgule décimale ni de signe + .'
      : "Cet élément n'est pas un nombre entier : {list}. Pas de lettres, de crochets, de parenthèses, de virgule décimale ni de signe + .", { list: shown }))
  }
  let tooLong = false
  rows.forEach((row, r) => row.forEach((tok) => {
    if (/^-?\d+$/.test(tok) && tok.replace('-', '').length > MAX_SHIFT_DIGITS && !tooLong) {
      tooLong = true
      reasons.push(t('Un nombre est trop long (ligne {r}) : au plus {max} chiffres.', { r: r + 1, max: MAX_SHIFT_DIGITS }))
    }
  }))

  // 2. la forme : carree, de 2×2 a 5×5
  const n = rows.length
  const widths = rows.map((r) => r.length)
  if (n === 1 && widths[0] > 1) {
    reasons.push(t('Tous les nombres sont sur une seule ligne ({n} nombres) : écris une ligne par rangée de la matrice.', { n: widths[0] }))
  } else if (new Set(widths).size > 1) {
    const first = widths.findIndex((w) => w !== widths[0])
    reasons.push(t('Les lignes n\'ont pas toutes le même nombre de valeurs : la ligne 1 en a {a}, la ligne {r} en a {b}.', { a: widths[0], r: first + 1, b: widths[first] }))
  } else if (widths[0] !== n) {
    reasons.push(t('La matrice n\'est pas carrée : {rows} de {cols}. Il faut autant de lignes que de valeurs par ligne.', { rows: plural(n, 'ligne', 'lignes'), cols: plural(widths[0], 'valeur', 'valeurs') }))
  } else if (n < HILL_MIN || n > HILL_MAX) {
    reasons.push(t('Taille {n}×{n} non acceptée : de {min}×{min} à {max}×{max}.', { n, min: HILL_MIN, max: HILL_MAX }))
  }

  if (reasons.length) return fail(reasons, { ...fmt, seen: visible(lines.join('\n')) })

  const cells = rows.map((row) => row.map((t) => t.replace(/^(-?)0+(?=\d)/, '$1')))
  return { ok: true, value: cells, info: t('matrice {n}×{n}', { n }) }
}

// ------------------------------------------------------------ Message -------

/** Meme nettoyage que la saisie au clavier : accents retires ; majuscules, sauf pour un message clair (keepCase). */
const clean = (s: string, keepCase = false) => {
  const t = s.normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  return keepCase ? t : t.toUpperCase()
}

/** Message : du texte (lettres, espaces, ponctuation, chiffres, retours a la ligne) avec au
 *  moins une lettre. Les lettres hors de l'alphabet A–Z (AE, Ø, 你, Ж…) sont refusees. */
export function checkMessage(raw: string, keepCase = false): Checked<string> {
  const text = raw.replace(/\n+$/, '')
  if (text.trim() === '') return fail([t('Le fichier est vide : il doit contenir un message.')])

  const cleaned = clean(text, keepCase)
  const reasons: string[] = []
  const foreign = (cleaned.match(/\p{L}/gu) ?? []).filter((c) => !/^[A-Za-z]$/.test(c))
  if (foreign.length) reasons.push(t('Il contient des lettres hors de l\'alphabet A–Z : {list}. Elles ne peuvent pas être chiffrées (supprimées ou refusées selon l\'algorithme).', { list: quote(foreign) }))
  const control = cleaned.match(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g)
  if (control) reasons.push(t('Il contient {n}.', { n: plural(control.length, 'caractère de contrôle invisible', 'caractères de contrôle invisibles') }))
  const letters = (cleaned.match(/[A-Za-z]/g) ?? []).length
  if (letters === 0 && !foreign.length) reasons.push(t("Il ne contient aucune lettre (A–Z) : seules les lettres sont chiffrées, il n'y aurait rien à chiffrer."))
  if (cleaned.length > MAX_MESSAGE_CHARS) reasons.push(t('Il est trop long ({n} caractères) : au plus {max}.', { n: num(cleaned.length), max: num(MAX_MESSAGE_CHARS) }))
  if (reasons.length) return fail(reasons, { seen: visible(text) })

  const kept = cleaned.length - letters
  return {
    ok: true, value: cleaned,
    info: plural(letters, 'lettre', 'lettres') +
      (kept ? ', ' + plural(kept, 'autre caractère non chiffré', 'autres caractères non chiffrés') + ' ' + t(pl(kept, '(conservé tel quel)', '(conservés tels quels)')) : ''),
  }
}
