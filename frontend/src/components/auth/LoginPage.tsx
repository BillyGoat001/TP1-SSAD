// La page de connexion : identifiant + mot de passe, puis un défi anti-robot (fenêtre
// CaptchaModal). Le serveur vérifie tout ; cette page ne décide jamais de rien.
// La carte se retourne (lien discret en bas) : au verso, l'inscription, protégée par le
// même défi anti-robot. Le serveur vérifie aussi les règles du mot de passe ; la liste
// de contrôle affichée ici sert seulement à guider la saisie.
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

const Flip = () => (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5" />
  </svg>
)

// Les règles du mot de passe (les mêmes que côté serveur, backend/auth.py)
const RULES: { label: string; test: (p: string) => boolean }[] = [
  { label: _t('8 caractères minimum'), test: (p) => p.length >= 8 },
  { label: _t('Une majuscule'), test: (p) => /[A-Z]/.test(p) },
  { label: _t('Une minuscule'), test: (p) => /[a-z]/.test(p) },
  { label: _t('Un chiffre'), test: (p) => /[0-9]/.test(p) },
  { label: _t('Un symbole'), test: (p) => /[!-/:-@[-`{-~]/.test(p) },
]

function passwordProblem(p: string): string | null {
  if (!/^[\x21-\x7E]+$/.test(p)) return _t('Le mot de passe ne doit contenir ni espace ni accent.')
  if (p.length < 8) return _t('Le mot de passe doit contenir au moins 8 caractères.')
  if (p.length > 64) return _t('Le mot de passe ne peut pas dépasser 64 caractères.')
  if (!/[A-Z]/.test(p)) return _t('Le mot de passe doit contenir une majuscule.')
  if (!/[a-z]/.test(p)) return _t('Le mot de passe doit contenir une minuscule.')
  if (!/[0-9]/.test(p)) return _t('Le mot de passe doit contenir un chiffre.')
  if (!/[!-/:-@[-`{-~]/.test(p)) return _t('Le mot de passe doit contenir un symbole (par ex. ! ? # @).')
  return null
}

type Mode = 'login' | 'register'
type RegErrs = { u?: string; p?: string; c?: string }
const BLOCKED = _t('Compte bloqué après 4 mots de passe erronés. Débloque-le avec : python make_user.py nom --unlock')

export default function LoginPage({ onSuccess, actions, configured }: {
  onSuccess: (user: string) => void
  actions: ReactNode            // le sélecteur de langue et le bouton de thème
  configured: boolean
}) {
  const [mode, setMode] = useState<Mode>('login')
  // ---- connexion
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [caps, setCaps] = useState(false)
  const [errs, setErrs] = useState<{ u?: string; p?: string }>({})
  const [message, setMessage] = useState<string | null>(null)
  const [okMsg, setOkMsg] = useState<string | null>(null)
  const [attempts, setAttempts] = useState<{ u: string; n: number } | null>(null)   // essais restants, pour CE compte
  const [blockedFor, setBlockedFor] = useState<string | null>(null)
  // ---- inscription
  const [regUser, setRegUser] = useState('')
  const [regPw, setRegPw] = useState('')
  const [regPw2, setRegPw2] = useState('')
  const [showRegPw, setShowRegPw] = useState(false)
  const [regErrs, setRegErrs] = useState<RegErrs>({})
  const [regMsg, setRegMsg] = useState<string | null>(null)
  // ---- commun
  const [modal, setModal] = useState<Mode | null>(null)
  const [phase, setPhase] = useState<'form' | 'open' | 'leaving'>('form')
  const [flash, setFlash] = useState(false)
  const [lockLeft, setLockLeft] = useState(0)
  const [welcome, setWelcome] = useState('')
  const root = useRef<HTMLDivElement>(null)
  const front = useRef<HTMLElement>(null)
  const back = useRef<HTMLElement>(null)
  const pwRef = useRef<HTMLInputElement>(null)
  const regUserRef = useRef<HTMLInputElement>(null)
  const userRef = useRef<HTMLInputElement>(null)
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

  // la face cachée de la carte ne reçoit ni clic ni focus clavier
  useEffect(() => {
    const setInert = (el: HTMLElement | null, v: boolean) => { if (el) (el as HTMLElement & { inert: boolean }).inert = v }
    setInert(front.current, mode !== 'login')
    setInert(back.current, mode !== 'register')
  }, [mode])

  // décompte d'un verrouillage (trop d'échecs depuis cette adresse)
  useEffect(() => {
    if (lockLeft <= 0) return
    const id = setInterval(() => setLockLeft((n) => Math.max(0, n - 1)), 1000)
    return () => clearInterval(id)
  }, [lockLeft > 0])  // eslint-disable-line react-hooks/exhaustive-deps

  const typed = username.trim().toLowerCase()
  const isBlocked = blockedFor !== null && blockedFor === typed
  const att = attempts && attempts.u === typed && attempts.n > 0 && !isBlocked ? attempts.n : 0
  const busy = phase !== 'form' || modal !== null

  const flipTo = (m: Mode) => {
    if (busy) return
    setMode(m)
    setTimeout(() => (m === 'register' ? regUserRef.current : (username ? pwRef.current : userRef.current))?.focus(), 450)
  }

  // ------------------------------------------------------------------ connexion
  const human = () => ({ ms: performance.now() - t0.current, events: events.current })

  const submit = (p: CaptchaSubmit) =>
    api.login({ username: username.trim(), password, captcha_id: p.id, answer: p.answer, nonce: p.nonce, human: human() })

  const done = (r: LoginResult) => {
    setModal(null)
    if (r.ok) {
      setWelcome(r.user ?? username.trim())
      setPhase('open')
      setTimeout(() => setPhase('leaving'), 1500)
      setTimeout(() => onSuccess(r.user ?? username.trim()), 2050)
      return
    }
    if (r.error === 'locked') setLockLeft(r.retry_after ?? 15)
    if (r.error === 'blocked') {
      setBlockedFor(typed); setAttempts(null); setMessage(null)
      setPassword('')
      setFlash(true)
      setTimeout(() => setFlash(false), 900)
      return
    }
    setMessage(r.message ?? _t('Connexion impossible.'))
    if (r.error === 'credentials') {
      setAttempts({ u: typed, n: r.remaining ?? 0 })
      setPassword('')
      setFlash(true)
      setTimeout(() => setFlash(false), 900)
      setTimeout(() => pwRef.current?.focus(), 50)
    }
  }

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (lockLeft > 0 || busy || isBlocked) return
    const next: { u?: string; p?: string } = {}
    if (!username.trim()) next.u = _t('Renseigne ton identifiant.')
    if (!password) next.p = _t('Renseigne ton mot de passe.')
    setErrs(next); setMessage(null); setOkMsg(null)
    if (!next.u && !next.p) setModal('login')
  }

  // ---------------------------------------------------------------- inscription
  const submitReg = (p: CaptchaSubmit) =>
    api.register({ username: regUser.trim(), password: regPw, captcha_id: p.id, answer: p.answer, nonce: p.nonce, human: human() })

  const doneReg = (r: LoginResult) => {
    setModal(null)
    if (r.ok) {                                   // compte créé : retour à la connexion, identifiant prérempli
      setUsername(r.user ?? regUser.trim()); setPassword('')
      setRegUser(''); setRegPw(''); setRegPw2(''); setRegErrs({}); setRegMsg(null); setShowRegPw(false)
      setMessage(null); setAttempts(null); setErrs({})
      setOkMsg(_t('Compte créé. Tu peux te connecter.'))
      setMode('login')
      setTimeout(() => pwRef.current?.focus(), 450)
      return
    }
    if (r.error === 'locked') setLockLeft(r.retry_after ?? 15)
    if (r.error === 'exists' || r.error === 'username') setRegErrs({ u: r.message })
    else if (r.error === 'policy') setRegErrs({ p: r.message })
    else setRegMsg(r.message ?? _t('Inscription impossible.'))
  }

  const onRegister = (e: React.FormEvent) => {
    e.preventDefault()
    if (lockLeft > 0 || busy) return
    const next: RegErrs = {}
    if (!/^[A-Za-z0-9._@-]{3,40}$/.test(regUser.trim())) next.u = _t('Identifiant : 3 à 40 caractères (lettres, chiffres, . _ @ -).')
    const problem = passwordProblem(regPw)
    if (problem) next.p = problem
    if (regPw2 !== regPw) next.c = _t('Les deux mots de passe sont différents.')
    setRegErrs(next); setRegMsg(null)
    if (!next.u && !next.p && !next.c) setModal('register')
  }

  const lockState: LockState = phase !== 'form' ? 'open' : flash ? 'error' : modal === 'login' ? 'checking' : 'idle'
  const lockText = lockLeft > 0 ? t('Trop de tentatives. Réessaie dans {n} s.', { n: lockLeft }) : null
  const shownMessage = lockText ?? (isBlocked ? t(BLOCKED) : message ? t(message) : null)
  const rulesOk = RULES.map((r) => r.test(regPw))

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

      <main className={'login-card' + (mode === 'register' ? ' is-flipped' : '')} data-blocker>
        <div className="flip">
          {/* ---------------------------------------------------------- recto : connexion */}
          <section className="face face-front" ref={front} aria-hidden={mode !== 'login'}>
            <LockLogo state={lockState} />
            <h1 className="login-title">{t('TP Sécurité')}</h1>

            <div className="login-swap">
              <form className="login-form" onSubmit={onSubmit} noValidate aria-hidden={phase !== 'form'}>
                {!configured && (
                  <p className="warn amber" role="alert">
                    {t("Aucun compte pour l'instant : inscris-toi avec le lien en bas.")}
                  </p>
                )}
                {okMsg && <p className="login-ok" role="status">{t(okMsg)}</p>}

                <label className={'login-field' + (errs.u ? ' has-err' : '')} style={{ ['--i' as string]: 0 }}>
                  <span className="field-label">{t('Identifiant')}</span>
                  <input
                    ref={userRef}
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
                {att > 0 && (
                  <p className={'login-att att-' + att} role="alert" key={'att' + att}>
                    <span className="att-pips" aria-hidden="true">{[0, 1, 2, 3].map((i) => <i key={i} className={i < att ? 'on' : ''} />)}</span>
                    {att === 1 ? t('Il reste 1 tentative.') : t('Il reste {n} tentatives.', { n: att })}
                  </p>
                )}

                <button type="submit" className="login-btn" disabled={lockLeft > 0 || busy || isBlocked} style={{ ['--i' as string]: 2 }}>
                  <span className="login-btn-text">
                    {lockLeft > 0 ? t('Patiente {n} s', { n: lockLeft }) : isBlocked ? t('Compte bloqué') : t('Se connecter')}
                  </span>
                  <svg className="login-btn-arrow" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6" /></svg>
                </button>
              </form>

              <div className="login-welcome" role="status" aria-live="polite">
                <strong>{t('Accès autorisé')}</strong>
                <span>{t('Bienvenue, {u}', { u: welcome })}</span>
              </div>
            </div>

            <button type="button" className="flip-link" onClick={() => flipTo('register')} disabled={busy}>
              <Flip /> {t("Pas de compte ? S'inscrire")}
            </button>
          </section>

          {/* ------------------------------------------------------------ verso : inscription */}
          <section className="face face-back" ref={back} aria-hidden={mode !== 'register'}>
            <LockLogo state={modal === 'register' ? 'checking' : 'idle'} />
            <h1 className="login-title">{t('Inscription')}</h1>

            <form className="login-form reg-form" onSubmit={onRegister} noValidate>
              <label className={'login-field' + (regErrs.u ? ' has-err' : '')} style={{ ['--i' as string]: 0 }}>
                <span className="field-label">{t('Identifiant')}</span>
                <input
                  ref={regUserRef} className="login-input" value={regUser} autoComplete="username" autoCapitalize="none" spellCheck={false}
                  maxLength={40}
                  onChange={(e) => { setRegUser(e.target.value); setRegErrs((x) => ({ ...x, u: undefined })) }}
                />
                {regErrs.u && <span className="login-err" role="alert">{t(regErrs.u)}</span>}
              </label>

              <label className={'login-field' + (regErrs.p ? ' has-err' : '')} style={{ ['--i' as string]: 1 }}>
                <span className="field-label">{t('Mot de passe')}</span>
                <span className="login-pw">
                  <input
                    className="login-input" value={regPw} type={showRegPw ? 'text' : 'password'} autoComplete="new-password"
                    maxLength={64}
                    onChange={(e) => { setRegPw(e.target.value); setRegErrs((x) => ({ ...x, p: undefined })) }}
                  />
                  <button type="button" className="login-eye" onClick={() => setShowRegPw((v) => !v)}
                    aria-label={showRegPw ? t('Masquer le mot de passe') : t('Afficher le mot de passe')}
                    title={showRegPw ? t('Masquer le mot de passe') : t('Afficher le mot de passe')}>
                    <Eye off={showRegPw} />
                  </button>
                </span>
                {regErrs.p && <span className="login-err" role="alert">{t(regErrs.p)}</span>}
              </label>

              <ul className="pw-rules" aria-label={t('Le mot de passe doit contenir :')}>
                {RULES.map((r, i) => (
                  <li key={r.label} className={rulesOk[i] ? 'ok' : ''}>
                    <span aria-hidden="true">{rulesOk[i] ? '✓' : '○'}</span> {t(r.label)}
                  </li>
                ))}
              </ul>

              <label className={'login-field' + (regErrs.c ? ' has-err' : '')} style={{ ['--i' as string]: 2 }}>
                <span className="field-label">{t('Confirmer le mot de passe')}</span>
                <input
                  className="login-input" value={regPw2} type={showRegPw ? 'text' : 'password'} autoComplete="new-password"
                  maxLength={64}
                  onChange={(e) => { setRegPw2(e.target.value); setRegErrs((x) => ({ ...x, c: undefined })) }}
                />
                {regErrs.c && <span className="login-err" role="alert">{t(regErrs.c)}</span>}
              </label>

              {(lockText || regMsg) && <p className="login-msg" role="alert" key={(lockText ?? regMsg ?? '') + lockLeft}>{lockText ?? t(regMsg ?? '')}</p>}

              <button type="submit" className="login-btn" disabled={lockLeft > 0 || busy} style={{ ['--i' as string]: 3 }}>
                <span className="login-btn-text">{lockLeft > 0 ? t('Patiente {n} s', { n: lockLeft }) : t('Créer le compte')}</span>
                <svg className="login-btn-arrow" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6" /></svg>
              </button>
            </form>

            <button type="button" className="flip-link" onClick={() => flipTo('login')} disabled={busy}>
              <Flip /> {t('Déjà un compte ? Se connecter')}
            </button>
          </section>
        </div>
      </main>

      {modal && (
        <CaptchaModal
          submit={modal === 'register' ? submitReg : submit}
          onClose={() => setModal(null)}
          onDone={modal === 'register' ? doneReg : done}
        />
      )}
    </div>
  )
}
