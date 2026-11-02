// Mise en forme des durees et des nombres d'essais (virgule decimale en francais, point en anglais).
import { getLang, locale } from '../../i18n'

const nf = (n: number, maxFrac = 0) => n.toLocaleString(locale(), { maximumFractionDigits: maxFrac })
const en = () => getLang() === 'en'

// Duree d'une attaque, de la nanoseconde a l'age de l'univers :
// 0,5 ns · 12 µs · 3,4 ms · 8,2 s · 2 min 5 s · 3 h 20 min · 2 j 4 h · 12 ans · 10^21 ans
// (en anglais : 0.5 ns · … · 2 d 4 h · 12 years · 10^21 years)
export function fmtDur(sec: number): string {
  if (!isFinite(sec)) return '∞'
  if (sec <= 0) return '0 s'
  if (sec < 1e-6) return `${nf(sec * 1e9, sec * 1e9 < 10 ? 1 : 0)} ns`
  if (sec < 1e-3) return `${nf(sec * 1e6, sec * 1e6 < 10 ? 1 : 0)} µs`
  if (sec < 1) return `${nf(sec * 1e3, sec * 1e3 < 10 ? 1 : 0)} ms`
  if (sec < 10) return `${nf(sec, 1)} s`
  const parts = (a: number, au: string, b: number, bu: string) => (b ? `${a} ${au} ${b} ${bu}` : `${a} ${au}`)
  const t = Math.round(sec)
  if (t < 60) return `${t} s`
  if (t < 3600) return parts(Math.floor(t / 60), 'min', t % 60, 's')
  const tm = Math.round(sec / 60)
  if (tm < 1440) return parts(Math.floor(tm / 60), 'h', tm % 60, 'min')
  const th = Math.round(sec / 3600)
  const YEAR_H = 365 * 24
  if (th < YEAR_H) return parts(Math.floor(th / 24), en() ? 'd' : 'j', th % 24, 'h')
  const y = sec / 31_536_000
  if (en()) {
    if (y < 100) return `${nf(y, y < 10 ? 1 : 0)} year${nf(y, y < 10 ? 1 : 0) === '1' ? '' : 's'}`
    if (y < 1000) return `${nf(y / 100)} centuries`
    if (y < 1e6) return `${nf(y / 1000)} millennia`
    return `10^${Math.floor(Math.log10(y))} years`
  }
  if (y < 100) return `${nf(y, y < 10 ? 1 : 0)} an${y >= 2 ? 's' : ''}`
  if (y < 1000) return `${nf(y / 100)} siècles`
  if (y < 1e6) return `${nf(y / 1000)} millénaires`
  return `10^${Math.floor(Math.log10(y))} ans`
}

// Nombre d'essais : entier groupe tant qu'il reste lisible, sinon 3,4 × 10^15
export function fmtTries(n: number): string {
  if (!isFinite(n)) return '∞'
  if (n < 1e15) return Math.round(n).toLocaleString(locale())
  const e = Math.floor(Math.log10(n))
  return `${nf(n / 10 ** e, 2)} × 10^${e}`
}
