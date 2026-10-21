import { useLayoutEffect, useRef, useState } from 'react'
import { t } from '../../i18n'

// Cellule de tableau en police mono : le texte est coupé par « … » quand il est trop long ;
// un clic (ou Entrée) l'affiche en entier, un second clic le replie.
export default function MonoCell({ text, className = '' }: { text: string; className?: string }) {
  const ref = useRef<HTMLTableCellElement>(null)
  const [open, setOpen] = useState(false)
  const [cut, setCut] = useState(false)   // le texte est-il coupé quand la cellule est repliée ?

  useLayoutEffect(() => {
    const el = ref.current
    if (!el || open) return
    const measure = () => setCut(el.scrollWidth > el.clientWidth + 1)
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [text, open])

  const expandable = cut || open
  const toggle = () => {
    if (window.getSelection()?.toString()) return   // l'utilisateur sélectionne du texte : on ne replie pas
    setOpen((o) => !o)
  }
  return (
    <td
      ref={ref}
      className={`cp-hist-mono ${className}` + (expandable ? ' is-exp' : '') + (open ? ' is-open' : '')}
      title={expandable ? (open ? t('Cliquer pour réduire') : t('Cliquer pour voir en entier')) : text}
      tabIndex={expandable ? 0 : undefined}
      aria-expanded={expandable ? open : undefined}
      onClick={expandable ? toggle : undefined}
      onKeyDown={expandable ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle() } } : undefined}
    >
      {text}
    </td>
  )
}
