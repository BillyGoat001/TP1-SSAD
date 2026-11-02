import type { HistoryEntry } from '../../types'
import MonoCell from './MonoCell'
import { t, locale } from '../../i18n'

// 3 µs (entier, sans virgule) · 1,2 ms · 1,5 s (virgule decimale en francais, point en anglais)
export function fmtTime(us: number): string {
  const whole = Math.max(1, Math.round(us))
  if (whole < 1000) return `${whole} µs`
  const ms = us / 1000
  if (ms < 1000) return `${ms.toLocaleString(locale(), { maximumFractionDigits: 2 })} ms`
  return `${(ms / 1000).toLocaleString(locale(), { maximumFractionDigits: 2 })} s`
}

// Section depliante « Historique » : une ligne par operation, la plus recente en haut.
export default function History({ entries, onRemove, onClear }: {
  entries: HistoryEntry[]
  onRemove: (id: number) => void   // supprime UNE ligne
  onClear: () => void              // supprime tout
}) {
  return (
    <details className="cp-fold">
      <summary>
        <span className="cp-fold-title">{t('Historique')}</span>
        <span className="cp-badge" aria-label={t('{n} opération(s)', { n: entries.length })}>{entries.length}</span>
      </summary>

      <div className="cp-fold-body">
        {entries.length === 0 ? (
          <p className="cp-empty">{t("Rien pour l'instant : chaque chiffrement ou déchiffrement réussi s'ajoutera ici.")}</p>
        ) : (
          <>
            <div className="cp-hist-scroll">
              <table className="cp-hist">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>{t('Opération')}</th>
                    <th>{t('Message clair')}</th>
                    <th>{t('Message chiffré')}</th>
                    <th>{t('Algorithme')}</th>
                    <th>{t('Clé')}</th>
                    <th title={t("Temps de calcul de l'algorithme (backend), hors animation et réseau")}>{t('Temps')}</th>
                    <th aria-label={t('Supprimer')} />
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => (
                    <tr key={e.id}>
                      <td className="cp-hist-n">{e.id}</td>
                      <td>
                        <span className={'cp-op ' + (e.op === 'encrypt' ? 'is-enc' : 'is-dec')}>
                          {e.op === 'encrypt' ? t('Chiffrement') : t('Déchiffrement')}
                        </span>
                      </td>
                      <MonoCell text={e.clear} />
                      <MonoCell text={e.cipher} />
                      <td>{t(e.algoLabel)}</td>
                      <MonoCell text={t(e.key)} />
                      <td className="cp-hist-time">{e.timeUs == null ? '—' : fmtTime(e.timeUs)}</td>
                      <td className="cp-hist-act">
                        <button
                          type="button" className="cp-hist-del"
                          onClick={() => onRemove(e.id)}
                          aria-label={t("Supprimer la ligne {n} de l'historique", { n: e.id })}
                          title={t('Supprimer cette ligne')}
                        >
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden="true">
                            <path d="M6 6l12 12M18 6L6 18" />
                          </svg>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <button className="btn tiny cp-hist-clear" onClick={onClear}>{t("Vider l'historique")}</button>
          </>
        )}
      </div>
    </details>
  )
}
