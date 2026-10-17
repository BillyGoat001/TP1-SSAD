import { useEffect, useState } from 'react'
import CipherTab, { type Part } from './components/cipher/CipherTab'
import PasswordsPanel from './components/passwords/PasswordsPanel'
import IntegrityPanel from './components/integrity/IntegrityPanel'

type TabId = 'cipher' | 'passwords' | 'integrity'

const TABS: { id: TabId; label: string }[] = [
  { id: 'cipher', label: 'Chiffrement' },
  { id: 'passwords', label: 'Mots de passe' },
  { id: 'integrity', label: 'Authenticité / Intégrité' },
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

// Icône du module SSAD (Stratégie de sécurité pour l'aide à la décision) :
// un bouclier (la sécurité) traversé par une fourche (le choix, la décision).
const SsadMark = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M12 2.6 4.6 5.4v5.5c0 4.7 3.1 8.6 7.4 10 4.3-1.4 7.4-5.3 7.4-10V5.4z" />
    <path d="M12 16.5V12M12 12 8.6 8.6M12 12l3.4-3.4" />
    <path d="M8.6 11V8.6H11M15.4 11V8.6H13" />
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
            <div className="brand-title">TP Sécurité</div>
            <div className="brand-sub">Chiffrement · Mots de passe · Intégrité</div>
          </div>
        </div>
        <button className="theme-btn" onClick={toggle} aria-label="Changer de thème">
          {theme === 'dark' ? '☾' : '☀'}
        </button>
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={'tab' + (tab === t.id ? ' is-active' : '')}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <main className="app-main">
        {tab === 'cipher' && <CipherTab part={part} onPart={setPart} />}
        {tab === 'passwords' && <PasswordsPanel />}
        {tab === 'integrity' && <IntegrityPanel />}
      </main>

      <footer className="app-footer">
        Backend Python (FastAPI) · Frontend React + TypeScript
      </footer>
    </div>
  )
}
