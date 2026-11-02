// Traduction FR ⇄ EN de toute l'interface.
//
// Le code reste ecrit en francais : chaque texte affiche passe par t('texte francais').
//   - en francais, t() renvoie le texte tel quel ;
//   - en anglais, t() cherche sa traduction dans le dictionnaire (en.ts) ; pour les
//     messages qui contiennent des valeurs (un nombre, une lettre…), des regles
//     (PATTERNS) reconnaissent la phrase et la traduisent.
// Le backend repond toujours en francais : ses messages sont traduits ici, a l'affichage.
// Changer de langue redessine toute l'appli : meme un message deja affiche change de langue.
//
// _t('texte') ne traduit rien : il marque un texte range dans une constante, qui sera
// traduit plus tard, au moment de l'affichage, par t(constante).

import { EN, PATTERNS } from './en'

export type Lang = 'fr' | 'en'
type Vars = Record<string, string | number>

let current: Lang = readSaved()

function readSaved(): Lang {
  try {
    return localStorage.getItem('tp-lang') === 'en' ? 'en' : 'fr'
  } catch {
    return 'fr'
  }
}

export function getLang(): Lang { return current }

export function setLang(l: Lang) {
  current = l
  try { localStorage.setItem('tp-lang', l) } catch { /* ignore */ }
  document.documentElement.lang = l
}

const fill = (s: string, vars?: Vars) =>
  vars ? s.replace(/\{(\w+)\}/g, (m, k: string) => (vars[k] !== undefined ? String(vars[k]) : m)) : s

/** Le texte francais `fr` dans la langue choisie ; {nom} est remplace par vars.nom. */
export function t(fr: string | null | undefined, vars?: Vars): string {
  if (fr == null) return ''
  if (current === 'fr') return fill(fr, vars)
  const hit = EN[fr]
  if (hit !== undefined) return fill(hit, vars)
  for (const [re, fn] of PATTERNS) {
    const m = fr.match(re)
    if (m) return fill(fn(m), vars)
  }
  return fill(fr, vars)
}

/** Marque un texte a traduire plus tard (il est range dans une constante). */
export const _t = (fr: string) => fr

/** Format des nombres : 1 234,5 en francais, 1,234.5 en anglais. */
export const locale = () => (current === 'en' ? 'en-US' : 'fr-FR')
export const num = (n: number, maxFrac = 0) => n.toLocaleString(locale(), { maximumFractionDigits: maxFrac })

/** Pluriel : plural(n, 'essai', 'essais') (textes francais, a passer ensuite dans t()).
 *  Regle francaise : pluriel a partir de 2 ; regle anglaise : pluriel sauf pour 1. */
export const plural = (n: number, one: string, many: string) =>
  (current === 'en' ? Math.abs(n) !== 1 : Math.abs(n) >= 2) ? many : one
