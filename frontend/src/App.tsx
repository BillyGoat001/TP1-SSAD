import { useEffect, useState } from 'react'
import CipherTab, { type Part } from './components/cipher/CipherTab'
import PasswordsPanel from './components/passwords/PasswordsPanel'
import IntegrityPanel from './components/integrity/IntegrityPanel'
import { t, _t, getLang, setLang, type Lang } from './i18n'

type TabId = 'cipher' | 'passwords' | 'integrity'

const TABS: { id: TabId; label: string }[] = [
  { id: 'cipher', label: _t('Chiffrement') },
  { id: 'passwords', label: _t('Mots de passe') },
  { id: 'integrity', label: _t('Intégrité') },
]

// La page affichée vit dans l'adresse (#chiffrement, #echange, #mots-de-passe,
// #integrite) : un rafraîchissement garde la même page.
const ROUTES: Record<string, { tab: TabId; part?: Part }> = {
  chiffrement: { tab: 'cipher', part: 'simple' },
  echange: { tab: 'cipher', part: 'exchange' },
  'mots-de-passe': { tab: 'passwords' },
  integrite: { tab: 'integrity' },
}
function readRoute() {
  const slug = decodeURIComponent(window.location.hash.replace(/^#\/?/, ''))
  return ROUTES[slug] ?? ROUTES.chiffrement
}
// La dernière partie ouverte de l'onglet Chiffrement est aussi retenue.
function savedPart(): Part {
  try {
    return localStorage.getItem('tp-cipher-part') === 'exchange' ? 'exchange' : 'simple'
  } catch {
    return 'simple'
  }
}
function slugOf(tab: TabId, part: Part) {
  if (tab === 'cipher') return part === 'exchange' ? 'echange' : 'chiffrement'
  return tab === 'passwords' ? 'mots-de-passe' : 'integrite'
}

// Logo : un bouclier (la sécurité) avec un cadenas fermé au centre. Deux tons : le
// contour et le cadenas prennent la couleur du texte du carré, l'intérieur celle du carré.
const SsadMark = () => (
  <svg viewBox="3 1.5 18 21.2" aria-hidden="true">
    <path fill="currentColor" d="M12 1.8 3.5 4.6V11c0 5.4 3.5 9.4 8.5 11.4 5-2 8.5-6 8.5-11.4V4.6z" />
    <path fill="var(--accent)" d="M12 3.9 5.6 6.1V11c0 4.2 2.6 7.4 6.4 9.2 3.8-1.8 6.4-5 6.4-9.2V6.1z" />
    <path fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" d="M10.2 10.6V9.3a1.8 1.8 0 0 1 3.6 0v1.3" />
    <rect x="9" y="10.6" width="6" height="4.8" rx="1" fill="currentColor" />
    <circle cx="12" cy="12.6" r="0.8" fill="var(--accent)" />
    <rect x="11.65" y="12.9" width="0.7" height="1.5" rx="0.3" fill="var(--accent)" />
  </svg>
)

function useTheme() {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try {
      const saved = localStorage.getItem('tp-theme')
      if (saved === 'light' || saved === 'dark') return saved
    } catch {
      /* ignore */
    }
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try {
      localStorage.setItem('tp-theme', theme)
    } catch {
      /* ignore */
    }
  }, [theme])
  return { theme, toggle: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')) }
}

export default function App() {
  const [tab, setTab] = useState<TabId>(() => readRoute().tab)
  const [part, setPart] = useState<Part>(() => readRoute().part ?? savedPart())
  const { theme, toggle } = useTheme()
  // Langue de l'interface (FR / EN), retenue d'une visite à l'autre. On la fixe AVANT de
  // dessiner les enfants : tous les t() de ce rendu utilisent la nouvelle langue.
  const [lang, setLangState] = useState<Lang>(getLang)
  if (getLang() !== lang) setLang(lang)
  useEffect(() => {
    setLang(lang)
    document.title = t('TP Sécurité — Chiffrement')
  }, [lang])
  // La page Mots de passe reste montée (seulement cachée) une fois ouverte : changer
  // d'onglet n'interrompt donc jamais une attaque en cours.
  const [pwOpened, setPwOpened] = useState(tab === 'passwords')
  useEffect(() => { if (tab === 'passwords') setPwOpened(true) }, [tab])

  // l'adresse suit la page affichée…
  useEffect(() => {
    const slug = slugOf(tab, part)
    if (window.location.hash !== '#' + slug) window.history.replaceState(null, '', '#' + slug)
    try {
      localStorage.setItem('tp-cipher-part', part)
    } catch {
      /* ignore */
    }
  }, [tab, part])

  // …et la page suit l'adresse si on la modifie à la main
  useEffect(() => {
    const onHash = () => {
      const r = readRoute()
      setTab(r.tab)
      if (r.part) setPart(r.part)
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark"><SsadMark /></span>
          <div>
            <div className="brand-title">{t('TP Sécurité')}</div>
            <div className="brand-sub">{t('Chiffrement · Mots de passe · Intégrité')}</div>
          </div>
        </div>
        <div className="header-actions">
          {/* FR | EN : la langue active est en surbrillance */}
          <div className="lang-switch" role="group" aria-label={t('Langue')}>
            {(['fr', 'en'] as const).map((l) => (
              <button
                key={l} type="button" lang={l}
                className={'lang-opt' + (lang === l ? ' is-on' : '')}
                aria-pressed={lang === l}
                title={l === 'fr' ? 'Français' : 'English'}
                onClick={() => setLangState(l)}
              >
                {l.toUpperCase()}
              </button>
            ))}
          </div>
          <button className="theme-btn" onClick={toggle} aria-label={t('Changer de thème')} title={t('Changer de thème')}>
            {theme === 'dark' ? '☾' : '☀'}
          </button>
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((tb) => (
          <button
            key={tb.id}
            className={'tab' + (tab === tb.id ? ' is-active' : '')}
            onClick={() => setTab(tb.id)}
          >
            {t(tb.label)}
          </button>
        ))}
      </nav>

      <main className="app-main">
        {tab === 'cipher' && <CipherTab part={part} onPart={setPart} />}
        {pwOpened && <div hidden={tab !== 'passwords'}><PasswordsPanel /></div>}
        {tab === 'integrity' && <IntegrityPanel />}
      </main>
    </div>
  )
}
