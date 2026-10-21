import type { PwHistoryEntry, PwResult } from '../../types'
import { fmtDur, fmtTries } from './format'
import MonoCell from '../cipher/MonoCell'
import { t, _t } from '../../i18n'

const RESULT: Record<PwResult, { label: string; cls: string; tip: string }> = {
  found: { label: _t('Cracké'), cls: 'is-bad', tip: _t('Le mot de passe a été trouvé') },
  blocked: { label: _t('Bloqué'), cls: 'is-good', tip: _t('La limite de tentatives a arrêté l\'attaque') },
  resist: { label: _t('Résiste'), cls: 'is-good', tip: _t('Le mot de passe n\'est pas dans le dictionnaire') },
  interrupted: { label: _t('Interrompu'), cls: 'is-mid', tip: _t('Tu as arrêté l\'attaque') },
}
const CASE_LABEL = { binaire: _t('Binaire'), numerique: _t('Numérique'), complexe: _t('Complexe') } as const

// Section dépliante « Historique » des attaques : une ligne par attaque, la plus récente en haut.
export default function PwHistory({ entries, onRemove, onClear }: {
  entries: PwHistoryEntry[]
  onRemove: (id: number) => void
  onClear: () => void
}) {
  return (
    <details className="cp-fold pw-hist-fold">
      <summary>
        <span className="cp-fold-title">{t('Historique')}</span>
        <span className="cp-badge" aria-label={t('{n} attaque(s)', { n: entries.length })}>{entries.length}</span>
      </summary>

      <div className="cp-fold-body">
        {entries.length === 0 ? (
          <p className="cp-empty">{t("Rien pour l'instant : chaque attaque (terminée ou interrompue) s'ajoutera ici.")}</p>
        ) : (
          <>
            <div className="cp-hist-scroll">
              <table className="cp-hist">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>{t('Attaque')}</th>
                    <th>{t('Cas')}</th>
                    <th>{t('Mot de passe')}</th>
                    <th>{t('Protection')}</th>
                    <th>{t('Résultat')}</th>
                    <th>{t('Essais')}</th>
                    <th title={t("Durée de l'attaque à la vitesse supposée de l'attaquant (10 milliards d'essais/s)")}>{t('Temps')}</th>
                    <th aria-label={t('Supprimer')} />
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => {
                    const r = RESULT[e.result]
                    return (
                      <tr key={e.id}>
                        <td className="cp-hist-n">{e.id}</td>
                        <td>{e.attack === 'brute' ? t('Force brute') : t('Dictionnaire')}</td>
                        <td>{t(CASE_LABEL[e.case])}</td>
                        <MonoCell text={e.password} />
                        <td className="pw-hist-prot">
                          <div className="pw-pills">
                            {e.protection.split(' · ').map((p, i) => (
                              <span key={i} className={'pw-pill-tag' + (p === 'Aucune' ? ' is-none' : '')}>{t(p)}</span>
                            ))}
                          </div>
                        </td>
                        <td><span className={'cp-op pw-res ' + r.cls} title={t(r.tip)}>{t(r.label)}</span></td>
                        <td className="cp-hist-time">{fmtTries(e.tries)}</td>
                        <td className="cp-hist-time">{fmtDur(e.timeSec)}</td>
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
                    )
                  })}
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
