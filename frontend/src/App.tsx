import { useEffect, useState } from 'react'
import CipherPanel from './components/cipher/CipherPanel'
import PasswordsPanel from './components/passwords/PasswordsPanel'
import IntegrityPanel from './components/integrity/IntegrityPanel'

type TabId = 'cipher' | 'passwords' | 'integrity'

const TABS: { id: TabId; label: string }[] = [
  { id: 'cipher', label: 'Chiffrement' },
  { id: 'passwords', label: 'Mots de passe' },
  { id: 'integrity', label: 'Authenticité / Intégrité' },
]

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
  const [tab, setTab] = useState<TabId>('cipher')
  const { theme, toggle } = useTheme()

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">◳</span>
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
        {tab === 'cipher' && <CipherPanel />}
        {tab === 'passwords' && <PasswordsPanel />}
        {tab === 'integrity' && <IntegrityPanel />}
      </main>

      <footer className="app-footer">
        Backend Python (FastAPI) · Frontend React + TypeScript
      </footer>
    </div>
  )
}
