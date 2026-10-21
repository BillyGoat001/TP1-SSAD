import { useEffect, useRef } from 'react'
import type { Problem } from './fileImport'
import { t, getLang } from '../../i18n'

const quoted = (name: string) => (getLang() === 'en' ? `"${name}"` : `« ${name} »`)

// Résultat affiché sous un champ après le choix d'un fichier.
export type FileNote =
  | { ok: true; name: string; info: string }
  | { ok: false; name: string; problem: Problem }

const FileIcon = () => (
  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" />
  </svg>
)

// Bouton « choisir UN fichier » : le sélecteur natif n'a pas l'attribut multiple.
// Aucune restriction d'extension : le contenu est vérifié, pas le nom.
export function FilePicker({ label, onFile }: { label: string; onFile: (f: File) => void }) {
  const ref = useRef<HTMLInputElement>(null)
  return (
    <>
      {/* bouton discret : juste l'icône ; le titre s'affiche au survol (data-tip) ou au focus clavier */}
      <button type="button" className="btn tiny cp-file-btn" aria-label={t(label)} data-tip={t(label)} onClick={() => ref.current?.click()}>
        <FileIcon />
      </button>
      <input
        ref={ref} type="file" className="cp-file-input" tabIndex={-1} aria-label={t(label)}
        onChange={(e) => {
          const f = e.target.files?.[0]
          e.target.value = '' // permet de re-choisir le même fichier après l'avoir corrigé
          if (f) onFile(f)
        }}
      />
    </>
  )
}

// Succès (disparaît seul) ou avertissement rouge (reste jusqu'à ce qu'on le ferme ou qu'on continue).
export function FileNotice({ note, what, onClose }: { note: FileNote | null; what: string; onClose: () => void }) {
  useEffect(() => {
    if (!note || !note.ok) return
    const t = window.setTimeout(onClose, 6000)
    return () => window.clearTimeout(t)
  }, [note]) // eslint-disable-line react-hooks/exhaustive-deps
  if (!note) return null

  if (note.ok) {
    return <div className="cp-file-ok" role="status">{t('✓ {name} chargé : {info}.', { name: quoted(note.name), info: note.info })}</div>
  }
  const { reasons, seen, format } = note.problem
  return (
    <div className="warn error cp-file-warn" role="alert">
      <button type="button" className="cp-file-x" onClick={onClose} aria-label={t("Fermer l'avertissement")} title={t('Fermer')}>×</button>
      <strong>{t('{name} ne peut pas servir de {what}.', { name: quoted(note.name), what: t(what) })}</strong>
      <ul>{reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
      {seen && <div className="cp-file-seen">{t('Contenu lu :')} <code>{seen}</code></div>}
      {format && (
        <div className="cp-file-format">
          <div>{t('Format accepté pour une clé Hill :')} {format.text}</div>
          <pre>{format.example}</pre>
        </div>
      )}
    </div>
  )
}
