// La fenêtre de vérification. Un NOUVEAU défi est tiré à chaque ouverture, à chaque
// erreur et à chaque clic sur « Autre défi » (jamais deux fois la même sorte de suite) ;
// fermer la fenêtre abandonne le défi. La preuve de travail se calcule en arrière-plan
// pendant que la personne résout le défi.
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../api'
import type { Challenge, LoginResult } from '../../types'
import { t, _t } from '../../i18n'
import { solvePow, type PowJob } from './pow'
import MotionCaptcha from './MotionCaptcha'
import IllusionCaptcha from './IllusionCaptcha'
import ShuffleCaptcha from './ShuffleCaptcha'

export interface CaptchaSubmit { id: string; answer: string | number; nonce: number }
type Status = 'loading' | 'ready' | 'checking' | 'success' | 'failed'

const KIND_LABEL = { motion: _t('Mouvement'), illusion: _t('Illusion'), shuffle: _t('Mémoire') } as const
const TIPS = {
  motion: _t('Astuce : cherche la zone où les points vont à contre-sens des autres.'),
  illusion: _t("Astuce : cherche où les rayures changent d'inclinaison."),
  shuffle: '',
} as const
const READ_MS = 2300          // le serveur refuse une réponse plus rapide qu'un regard humain

export default function CaptchaModal({ submit, onClose, onDone }: {
  submit: (p: CaptchaSubmit) => Promise<LoginResult>
  onClose: () => void
  onDone: (r: LoginResult) => void      // tout résultat qui n'est pas une erreur de captcha
}) {
  const [ch, setCh] = useState<Challenge | null>(null)
  const [status, setStatus] = useState<Status>('loading')
  const [notice, setNotice] = useState<string | null>(null)
  const [answer, setAnswer] = useState('')
  const [picked, setPicked] = useState<number | null>(null)
  const [powDone, setPowDone] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [shaking, setShaking] = useState(false)
  const seq = useRef(0)
  const kind = useRef<string | undefined>(undefined)
  const pow = useRef<PowJob | null>(null)
  const born = useRef(0)
  const liveId = useRef<string | null>(null)       // le défi affiché : s'il est abandonné, on le détruit côté serveur
  const input = useRef<HTMLInputElement>(null)

  const shake = () => { setShaking(false); requestAnimationFrame(() => setShaking(true)); setTimeout(() => setShaking(false), 600) }

  const load = useCallback(async (message?: string) => {
    const my = ++seq.current
    pow.current?.cancel()
    if (liveId.current) { api.authDiscard(liveId.current); liveId.current = null }
    setStatus('loading'); setCh(null); setAnswer(''); setPicked(null); setPowDone(false); setElapsed(0)
    setNotice(message ?? null)
    try {
      const c = await api.authCaptcha(kind.current)
      if (my !== seq.current) return
      kind.current = c.kind
      liveId.current = c.id
      born.current = performance.now()
      setCh(c); setStatus('ready')
      const job = solvePow(c.pow.challenge, c.pow.bits)
      pow.current = job
      job.promise.then(() => { if (my === seq.current) setPowDone(true) }, () => undefined)
    } catch {
      if (my !== seq.current) return
      setStatus('failed')
      setNotice(_t('Impossible de charger le défi. Le serveur est-il lancé ?'))
    }
  }, [])

  useEffect(() => {
    void load()
    return () => {
      seq.current++; pow.current?.cancel()
      if (liveId.current) api.authDiscard(liveId.current)
    }
  }, [load])

  // le temps passe : l'attente de lecture, puis l'expiration du défi
  useEffect(() => {
    if (!ch || status !== 'ready') return
    const id = setInterval(() => {
      const e = performance.now() - born.current
      setElapsed(e)
      if (e > ch.ttl * 1000) void load(_t("Le défi a expiré. Un nouveau défi t'attend."))
    }, 200)
    return () => clearInterval(id)
  }, [ch, status, load])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => { if (status === 'ready' && ch && ch.kind !== 'shuffle') input.current?.focus() }, [status, ch])

  const send = async (value: string | number) => {
    if (!ch || status !== 'ready') return
    const job = pow.current
    if (!job) return
    setStatus('checking'); setNotice(null)
    liveId.current = null                         // la réponse consomme le défi
    let nonce = 0
    try { nonce = await job.promise } catch { return }
    let r: LoginResult
    try {
      r = await submit({ id: ch.id, answer: value, nonce })
    } catch {
      shake()
      void load(_t('Le serveur est injoignable. Réessaie dans un instant.'))
      return
    }
    if (r.ok) {
      setStatus('success')
      setTimeout(() => onDone(r), 900)
    } else if (r.error === 'captcha') {
      shake()
      void load(r.message ?? _t("Défi raté. Un nouveau défi t'attend."))
    } else {
      onDone(r)
    }
  }

  const textKind = ch && ch.kind !== 'shuffle'
  const readyToAnswer = status === 'ready' && elapsed >= READ_MS
  const wait = Math.min(1, elapsed / READ_MS)
  const leftS = ch ? Math.max(0, Math.round(ch.ttl - elapsed / 1000)) : 0

  return (
    <div className="cap-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div
        className={'cap-modal is-' + status + (shaking ? ' is-shaking' : '')}
        role="dialog" aria-modal="true" aria-label={t('Vérification de sécurité')}
      >
        <header className="cap-head">
          <span className="cap-shield" aria-hidden="true">
            <svg viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V5z" fill="currentColor" /><path d="m8.6 12 2.4 2.4 4.4-4.8" fill="none" stroke="var(--accent-fg)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </span>
          <div className="cap-title">
            <strong>{t('Vérification de sécurité')}</strong>
            {ch && <span className={'cap-kind k-' + ch.kind}>{t(KIND_LABEL[ch.kind])}</span>}
          </div>
          <button type="button" className="cap-close" onClick={onClose} aria-label={t('Fermer')} title={t('Fermer')}>✕</button>
        </header>

        <div className="cap-body">
          {status === 'loading' && (
            <div className="cap-loading"><span className="cap-spin" />{t("Préparation d'un nouveau défi…")}</div>
          )}
          {ch && status !== 'loading' && (
            <div className="cap-challenge" key={ch.id}>
              <p className="cap-prompt">{t(ch.prompt)}</p>
              {ch.kind === 'motion' && <MotionCaptcha ch={ch} />}
              {ch.kind === 'illusion' && <IllusionCaptcha ch={ch} />}
              {ch.kind === 'shuffle' && (
                <ShuffleCaptcha ch={ch} locked={status !== 'ready'} picked={picked}
                  onPick={(slot) => { setPicked(slot); void send(slot) }} />
              )}
              {TIPS[ch.kind] && <p className="cap-tip">{t(TIPS[ch.kind])}</p>}
              {textKind && (
                <form className="cap-answer" onSubmit={(e) => { e.preventDefault(); if (readyToAnswer && answer.length === 4) void send(answer) }}>
                  <input
                    ref={input} className="cap-input" value={answer} inputMode="text" autoComplete="off" spellCheck={false}
                    maxLength={4} placeholder="••••" aria-label={t('Les 4 caractères')} disabled={status !== 'ready'}
                    onChange={(e) => setAnswer(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, ''))}
                  />
                  <button type="submit" className="cap-go" disabled={!readyToAnswer || answer.length !== 4}>
                    <span className="cap-go-fill" style={{ transform: `scaleX(${wait})` }} />
                    <span className="cap-go-text">{status === 'checking' ? t('Vérification…') : t('Valider')}</span>
                  </button>
                </form>
              )}
            </div>
          )}
          {status === 'success' && (
            <div className="cap-ok" role="status">
              <svg viewBox="0 0 52 52" aria-hidden="true"><circle cx="26" cy="26" r="23" /><path d="m15 27 8 8 15-17" /></svg>
              <span>{t('Vérifié')}</span>
            </div>
          )}
          {status === 'checking' && ch?.kind === 'shuffle' && (
            <div className="cap-checking"><span className="cap-spin" />{t('Vérification…')}</div>
          )}
          {notice && <p className="cap-notice" role="alert">{t(notice)}</p>}
        </div>

        <footer className="cap-foot">
          <span className={'cap-pow' + (powDone ? ' is-done' : '')} title={ch ? t('Preuve de travail : SHA-256 sur {n} bits', { n: ch.pow.bits }) : ''}>
            {powDone ? <i className="cap-tick">✓</i> : <span className="cap-spin sm" />}
            {powDone ? t('Preuve de travail prête') : t('Preuve de travail…')}
          </span>
          <button type="button" className="cap-again" onClick={() => void load()} disabled={status === 'checking' || status === 'success'}>
            ↻ {t('Autre défi')}
          </button>
        </footer>
        {ch && status === 'ready' && (
          <div className="cap-timer" aria-hidden="true" title={t('Temps restant : {n} s', { n: leftS })}>
            <span style={{ width: `${Math.max(0, 100 - (elapsed / (ch.ttl * 1000)) * 100)}%` }} />
          </div>
        )}
      </div>
    </div>
  )
}
