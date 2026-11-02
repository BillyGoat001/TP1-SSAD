// Morceaux d'affichage de l'echange A ↔ B : icones, champs de cles, et la
// demonstration du chiffrement / dechiffrement dans les boites floutees.

import type { CSSProperties } from 'react'
import type { Algo, ExchangeParams, RsaKey, Trace } from '../../types'
import { usePlayback } from '../cipher/usePlayback'
import Playback from '../cipher/Playback'
import CaesarViz from '../cipher/CaesarViz'
import PlayfairViz from '../cipher/PlayfairViz'
import HillViz from '../cipher/HillViz'
import { t, _t } from '../../i18n'

export type U = 'a' | 'b'
export const OTHER: Record<U, U> = { a: 'b', b: 'a' }
export const UP = (u: U) => u.toUpperCase()
// nom de l'algorithme, en francais (a passer dans t() pour l'afficher : algoName)
export const NAME: Record<Algo, string> = { caesar: _t('César'), playfair: 'Playfair', hill: 'Hill' }
export const algoName = (a: Algo) => t(NAME[a])

/** 1234567890123 → « 12345…90123 » (le nombre complet reste dans l'info-bulle). */
export function short(s: string, k = 5): string {
  return s.length <= 2 * k + 3 ? s : s.slice(0, k) + '…' + s.slice(-k)
}

/** La cle symetrique en clair, telle qu'elle voyage dans le coffre (en francais : t() la traduit a l'affichage). */
export function keyText(p: ExchangeParams): string {
  if (p.algo === 'caesar') return `${p.shift} · ${p.direction === 'left' ? 'gauche' : 'droite'}`
  if (p.algo === 'playfair') return p.key ?? ''
  return (p.matrix ?? []).map((r) => r.join(' ')).join(' · ')
}

/** La meme cle, chaque tres grand nombre abrege : pour les titres, les bulles et les pastilles. */
export function keyShort(p: ExchangeParams): string {
  return keyText(p).replace(/-?\d{14,}/g, (s) => short(s))
}

/** Texte sur une seule ligne, coupe proprement (pour les animations). */
export function clip(s: string, max = 90): string {
  const t = s.replace(/\s+/g, ' ').trim()
  return t.length > max ? t.slice(0, max - 1) + '…' : t
}

/** Chaque lettre s'anime seule, decalee selon son rang (meme effet que la partie simple). */
export function Letters({ text, className, step }: { text: string; className: string; step: number }) {
  return (
    <span className={className}>
      {[...text].map((ch, i) => (
        <span key={i} style={{ '--i': i, '--step': `${step}ms` } as CSSProperties}>{ch === ' ' ? ' ' : ch}</span>
      ))}
    </span>
  )
}

// ---------------------------------------------------------------- icones ----
export const LockIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V7.5a4 4 0 0 1 8 0V11" />
  </svg>
)
export const UnlockIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V7.5a4 4 0 0 1 7.6-1.7" />
  </svg>
)
export const UserIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="8" r="4" />
    <path d="M4.5 20.5a7.5 7.5 0 0 1 15 0" />
  </svg>
)
/** Petite fleche pleine, tournee vers le destinataire. */
export const Arrow = ({ dir }: { dir: 'left' | 'right' }) => (
  <svg className="ex-arrow" viewBox="0 0 10 10" aria-hidden="true">
    <path d={dir === 'right' ? 'M2.2 1.2 8.6 5l-6.4 3.8z' : 'M7.8 1.2 1.4 5l6.4 3.8z'} fill="currentColor" />
  </svg>
)
export const ChestIcon = ({ open = false }: { open?: boolean }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ overflow: 'visible' }}>
    <path d="M3 11.5h18V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    <path d="M3 11.5V10.2C3 7.3 7 5.2 12 5.2s9 2.1 9 5v1.3z" transform={open ? 'rotate(-24 3 11.5)' : undefined} />
    <path d="M7 11.5v9.5M17 11.5v9.5" strokeWidth="1.4" />
    <circle cx="12" cy="15.2" r="1.7" fill="currentColor" stroke="none" />
    <path d="M12 16v2.4" strokeWidth="2.1" />
  </svg>
)
export const KeyIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="7.5" cy="8" r="3.5" />
    <path d="M10 10.5 19 19M16 16l2.2-2.2M19 19l2-2" />
  </svg>
)
export const EyeOpen = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z" /><circle cx="12" cy="12" r="3" />
  </svg>
)
export const EyeOff = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
)

// ---------------------------------------------------------- champ de cle ----
// La cle est affichee dans son champ : publique (e, n) ou privee (d, n).
interface KeyFieldProps {
  kind: 'pub' | 'priv'
  owner: U
  k: RsaKey | null
  hidden: boolean
  iconHidden: boolean
  fieldRef: (el: HTMLElement | null) => void
  iconRef: (el: HTMLElement | null) => void
}
export function KeyField({ kind, owner, k, hidden, iconHidden, fieldRef, iconRef }: KeyFieldProps) {
  const val = !k ? '—' : kind === 'pub' ? `e = ${k.e} · n = ${short(k.n)}` : `d = ${short(k.d)} · n = ${short(k.n)}`
  const full = !k ? undefined : kind === 'pub' ? `e = ${k.e}\nn = ${k.n}` : `d = ${k.d}\nn = ${k.n}`
  return (
    <div ref={fieldRef} className={`ex-kp ex-from-${owner}` + (hidden ? ' is-hidden' : '')} title={full}>
      <div className="ex-kp-text">
        <span className="ex-kp-label">
          {t(kind === 'pub' ? 'Clé publique de {u}' : 'Clé privée de {u}', { u: UP(owner) })}
          <span className="ex-kp-pair">{kind === 'pub' ? ' (e, n)' : ' (d, n)'}</span>
        </span>
        <span className="ex-kp-val">{val}</span>
      </div>
      <span ref={iconRef} className={'ex-kp-ico' + (iconHidden ? ' is-hidden' : '')}>
        {kind === 'pub' ? <ChestIcon /> : <KeyIcon />}
      </span>
    </div>
  )
}

// ------------------------------------------------- contenu des boites ----
// Chiffrer : la boite prend la couleur de l'utilisateur. Dechiffrer : celle de
// l'autre (l'auteur du message). Le resultat, lui, est toujours vert.
export interface BoxView {
  op: 'encrypt' | 'decrypt'
  trace: Trace
  original: string
  params: ExchangeParams
}

/** Demonstration pas a pas (memes composants que la partie simple), avec le resultat sous le mot. */
export function TraceView({ view }: { view: BoxView }) {
  const { trace, original, params } = view
  const total = trace.steps.length
  const pb = usePlayback(total)
  const atEnd = pb.index >= total - 1
  return (
    <div className="ex-trace">
      <div className="ex-sec-title" title={keyShort(params) !== keyText(params) ? t(keyText(params)) : undefined}>
        {t(view.op === 'encrypt' ? 'Chiffrement {algo} · clé {key}' : 'Déchiffrement {algo} · clé {key}', { algo: algoName(params.algo), key: t(keyShort(params)) })}
      </div>
      {trace.kind === 'caesar' && <CaesarViz trace={trace} index={pb.index} showResult />}
      {trace.kind === 'playfair' && <PlayfairViz trace={trace} index={pb.index} original={original} showResult />}
      {trace.kind === 'hill' && <HillViz trace={trace} index={pb.index} original={original} showResult />}
      <Playback
        playing={pb.playing} speed={pb.speed} setSpeed={pb.setSpeed}
        play={pb.play} pause={pb.pause} step={pb.step} reset={pb.reset} atEnd={atEnd}
      />
      <div className="step-counter">{t('Étape {i} / {n}', { i: Math.max(0, pb.index + 1), n: total })}</div>
    </div>
  )
}
