// La page de connexion : identifiant + mot de passe, puis un défi anti-robot (fenêtre
// CaptchaModal). Le serveur vérifie tout ; cette page ne décide jamais de rien.
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { api } from '../../api'
import type { LoginResult } from '../../types'
import { t, _t } from '../../i18n'
import LockLogo, { type LockState } from './LockLogo'
import CaptchaModal, { type CaptchaSubmit } from './CaptchaModal'
import GlyphField from './GlyphField'

const Eye = ({ off }: { off: boolean }) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" />
    <circle cx="12" cy="12" r="3" />
    {off && <path d="m4 4 16 16" />}
  </svg>
)

export default function LoginPage({ onSuccess, actions, configured }: {
  onSuccess: (user: string) => void
  actions: ReactNode            // le sélecteur de langue et le bouton de thème
  configured: boolean
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [caps, setCaps] = useState(false)
  const [errs, setErrs] = useState<{ u?: string; p?: string }>({})
  const [message, setMessage] = useState<string | null>(null)
  const [modal, setModal] = useState(false)
  const [phase, setPhase] = useState<'form' | 'open' | 'leaving'>('form')
  const [flash, setFlash] = useState(false)
  const [lockLeft, setLockLeft] = useState(0)
  const [welcome, setWelcome] = useState('')
  const root = useRef<HTMLDivElement>(null)
  const pwRef = useRef<HTMLInputElement>(null)
  const t0 = useRef(performance.now())
  const events = useRef(0)
  const raf = useRef(0)

  // la page garde le projecteur sous le curseur, et compte les gestes (le serveur attend
  // qu'un humain ait bougé la souris ou tapé au clavier avant d'accepter une connexion)
  const onPointerMove = (e: React.PointerEvent) => {
    events.current++
    const { clientX: x, clientY: y } = e
    cancelAnimationFrame(raf.current)
    raf.current = requestAnimationFrame(() => {
      root.current?.style.setProperty('--mx', `${x}px`)
      root.current?.style.setProperty('--my', `${y}px`)
    })
  }
  useEffect(() => () => cancelAnimationFrame(raf.current), [])

  // décompte d'un verrouillage (trop d'échecs)
  useEffect(() => {
    if (lockLeft <= 0) return
    const id = setInterval(() => setLockLeft((n) => Math.max(0, n - 1)), 1000)
    return () => clearInterval(id)
  }, [lockLeft > 0])  // eslint-disable-line react-hooks/exhaustive-deps

  const submit = (p: CaptchaSubmit) =>
    api.login({
      username: username.trim(), password, captcha_id: p.id, answer: p.answer, nonce: p.nonce,
      human: { ms: performance.now() - t0.current, events: events.current },
    })

  const done = (r: LoginResult) => {
    setModal(false)
    if (r.ok) {
      setWelcome(r.user ?? username.trim())
      setPhase('open')
      setTimeout(() => setPhase('leaving'), 1500)
      setTimeout(() => onSuccess(r.user ?? username.trim()), 2050)
      return
    }
    if (r.error === 'locked') setLockLeft(r.retry_after ?? 15)
    setMessage(r.message ?? _t('Connexion impossible.'))
    if (r.error === 'credentials') {
      setPassword('')
      setFlash(true)
      setTimeout(() => setFlash(false), 900)
      setTimeout(() => pwRef.current?.focus(), 50)
    }
  }

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (lockLeft > 0 || phase !== 'form') return
    const next: { u?: string; p?: string } = {}
    if (!username.trim()) next.u = _t('Renseigne ton identifiant.')
    if (!password) next.p = _t('Renseigne ton mot de passe.')
    setErrs(next); setMessage(null)
    if (!next.u && !next.p) setModal(true)
  }

  const lockState: LockState = phase !== 'form' ? 'open' : flash ? 'error' : modal ? 'checking' : 'idle'
  const shownMessage = lockLeft > 0 ? t('Trop de tentatives. Réessaie dans {n} s.', { n: lockLeft }) : message ? t(message) : null

  return (
    <div
      ref={root} className={'login' + (phase !== 'form' ? ' is-' + phase : '')}
      onPointerMove={onPointerMove} onKeyDown={() => { events.current++ }} onPointerDown={() => { events.current++ }}
    >
      <div className="login-bg" aria-hidden="true">
        <i className="orb o1" /><i className="orb o2" /><i className="orb o3" />
        <div className="login-grid" />
        <div className="login-spot" />
        <GlyphField />
      </div>
      <div className="login-top">{actions}</div>

      <main className="login-card" data-blocker>
        <LockLogo state={lockState} />
        <h1 className="login-title">{t('TP Sécurité')}</h1>

        <div className="login-swap">
          <form className="login-form" onSubmit={onSubmit} noValidate aria-hidden={phase !== 'form'}>
            {!configured && (
              <p className="warn amber" role="alert">
                {t("Aucun compte n'est configuré sur ce serveur.")} <code>python make_user.py nom</code>
              </p>
            )}

            <label className={'login-field' + (errs.u ? ' has-err' : '')} style={{ ['--i' as string]: 0 }}>
              <span className="field-label">{t('Identifiant')}</span>
              <input
                className="login-input" value={username} autoComplete="username" autoCapitalize="none" spellCheck={false}
                autoFocus disabled={phase !== 'form'}
                onChange={(e) => { setUsername(e.target.value); setErrs((x) => ({ ...x, u: undefined })) }}
              />
              {errs.u && <span className="login-err" role="alert">{t(errs.u)}</span>}
            </label>

            <label className={'login-field' + (errs.p ? ' has-err' : '')} style={{ ['--i' as string]: 1 }}>
              <span className="field-label">{t('Mot de passe')}</span>
              <span className="login-pw">
                <input
                  ref={pwRef} className="login-input" value={password} type={showPw ? 'text' : 'password'}
                  autoComplete="current-password" disabled={phase !== 'form'}
                  onChange={(e) => { setPassword(e.target.value); setErrs((x) => ({ ...x, p: undefined })) }}
                  onKeyUp={(e) => setCaps(e.getModifierState?.('CapsLock') ?? false)}
                  onBlur={() => setCaps(false)}
                />
                <button type="button" className="login-eye" onClick={() => setShowPw((v) => !v)}
                  aria-label={showPw ? t('Masquer le mot de passe') : t('Afficher le mot de passe')}
                  title={showPw ? t('Masquer le mot de passe') : t('Afficher le mot de passe')}>
                  <Eye off={showPw} />
                </button>
              </span>
              {caps && <span className="login-caps">⇪ {t('Verr. Maj. est activé.')}</span>}
              {errs.p && <span className="login-err" role="alert">{t(errs.p)}</span>}
            </label>

            {shownMessage && <p className="login-msg" role="alert" key={shownMessage + lockLeft}>{shownMessage}</p>}

            <button type="submit" className="login-btn" disabled={lockLeft > 0 || phase !== 'form'} style={{ ['--i' as string]: 2 }}>
              <span className="login-btn-text">{lockLeft > 0 ? t('Patiente {n} s', { n: lockLeft }) : t('Se connecter')}</span>
              <svg className="login-btn-arrow" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6" /></svg>
            </button>
          </form>

          <div className="login-welcome" role="status" aria-live="polite">
            <strong>{t('Accès autorisé')}</strong>
            <span>{t('Bienvenue, {u}', { u: welcome })}</span>
          </div>
        </div>
      </main>

      {modal && <CaptchaModal submit={submit} onClose={() => setModal(false)} onDone={done} />}
    </div>
  )
}
