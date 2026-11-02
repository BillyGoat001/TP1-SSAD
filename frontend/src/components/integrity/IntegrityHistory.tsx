import type { IntegrityHistoryEntry, IntegrityResultKind } from '../../types'
import MonoCell from '../cipher/MonoCell'
import { t, _t, num } from '../../i18n'

// Verdict de chaque envoi. « Non vérifié » devient une faille (rouge) quand C a vraiment
// modifié le message : B l'a accepté sans rien voir.
function verdict(e: IntegrityHistoryEntry): { label: string; cls: string; tip: string } {
  const R: Record<IntegrityResultKind, { label: string; cls: string; tip: string }> = {
    intact: { label: _t('Intact'), cls: 'is-good', tip: _t('Les deux étiquettes sont identiques : le message n’a pas été modifié') },
    detected: { label: _t('Altération détectée'), cls: 'is-good', tip: _t('Les étiquettes diffèrent : B a vu que le message avait été modifié') },
    unchecked: e.altered
      ? { label: _t('Altération non détectée'), cls: 'is-bad', tip: _t('Protection désactivée : B a accepté un message modifié sans rien voir') }
      : { label: _t('Non vérifié'), cls: 'is-mid', tip: _t('Protection désactivée : B n’a rien vérifié') },
    broken: { label: _t('Illisible'), cls: 'is-mid', tip: _t('Le chiffré reçu est devenu invalide : B n’a pas pu le déchiffrer') },
  }
  return R[e.result]
}

// Le chiffre qui compte : combien de l'étiquette a changé entre A et B (0 % = intact).
// Taux de changement de l'étiquette : part de ses caractères hexadécimaux qui diffèrent (≈ 94 % dès
// qu'un message est modifié : 15 chances sur 16 par caractère). Repli sur le taux en bits si absent.
export function charRate(changed: number | null | undefined, total: number | null | undefined, fallback: number | null = null) {
  return changed != null && total ? (100 * changed) / total : fallback
}

function RateCell({ e }: { e: IntegrityHistoryEntry }) {
  if (e.changeRate === null) {
    return (
      <td className="ih-rate is-na"
        title={t(e.result === 'broken'
          ? 'Pas de taux : le chiffré reçu est illisible, B n’a pas pu recalculer l’étiquette'
          : 'Pas de taux : la protection était désactivée, B n’a pas recalculé d’étiquette')}>
        —
      </td>
    )
  }
  const same = e.bitsChanged === 0
  const rate = charRate(e.charsChanged, e.charsTotal, e.changeRate) ?? 0
  return (
    <td className={'ih-rate ' + (same ? 'is-ok' : 'is-bad')}
      title={t('{b} bits sur {bt} · {c} caractère(s) sur {ct}', {
        b: e.bitsChanged ?? 0, bt: e.bitsTotal ?? 256, c: e.charsChanged ?? 0, ct: e.charsTotal ?? 64,
      })}>
      <span className="ih-rate-num">{num(rate, 1)} %</span>
      <span className="ih-rate-bar"><span style={{ width: `${rate}%` }} /></span>
    </td>
  )
}

// Section dépliante « Historique » de la page Intégrité : un envoi A → B par ligne, le plus récent en haut.
export default function IntegrityHistory({ entries, onRemove, onClear }: {
  entries: IntegrityHistoryEntry[]
  onRemove: (id: number) => void
  onClear: () => void
}) {
  return (
    <details className="cp-fold pw-hist-fold">
      <summary>
        <span className="cp-fold-title">{t('Historique')}</span>
        <span className="cp-badge" aria-label={t('{n} envoi(s)', { n: entries.length })}>{entries.length}</span>
      </summary>

      <div className="cp-fold-body">
        {entries.length === 0 ? (
          <p className="cp-empty">{t('Rien pour l’instant : chaque envoi de A vers B mené à son terme s’ajoutera ici.')}</p>
        ) : (
          <>
            <div className="cp-hist-scroll">
              <table className="cp-hist">
                <thead>
                  <tr>
                    <th>#</th>
                    <th title={t('Part des caractères de l’étiquette qui ont changé entre celle de A et celle recalculée par B (0 % = intact, environ 94 % = message modifié)')}>
                      {t('Taux de changement')}
                    </th>
                    <th>{t('Message de A')}</th>
                    <th>{t('Algorithme')}</th>
                    <th>{t('Altéré par C')}</th>
                    <th>{t('Protection')}</th>
                    <th>{t('Résultat')}</th>
                    <th aria-label={t('Supprimer')} />
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => {
                    const v = verdict(e)
                    return (
                      <tr key={e.id}>
                        <td className="cp-hist-n">{e.id}</td>
                        <RateCell e={e} />
                        <MonoCell text={e.message} />
                        <td className="ih-algo" title={e.key ? t(e.key) : undefined}>
                          <span className={'ih-algo-name' + (e.algo ? '' : ' is-none')}>{t(e.algoLabel)}</span>
                          {e.key && <span className="ih-algo-key">{t(e.key)}</span>}
                        </td>
                        <td>{e.altered ? t('Oui') : t('Non')}</td>
                        <td>
                          <span className={'pw-pill-tag' + (e.protect ? '' : ' is-none')}>
                            {e.protect ? 'HMAC' : t('Aucune')}
                          </span>
                        </td>
                        <td><span className={'cp-op pw-res ' + v.cls} title={t(v.tip)}>{t(v.label)}</span></td>
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
