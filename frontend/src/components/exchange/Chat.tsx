import { Fragment } from 'react'
import type { CSSProperties } from 'react'
import type { ExchangeParams } from '../../types'
import { type U, algoName, keyText, keyShort, UserIcon, LockIcon, UnlockIcon } from './parts'
import { t } from '../../i18n'

export interface ChatMsg {
  id: number
  from: U
  plain: string   // le message tel que l'expéditeur l'a écrit
  cipher: string  // ce qui a circulé sur le canal
  params: ExchangeParams
}

// La conversation entre A et B, façon messagerie. A écrit à gauche, B à droite
// (comme dans les cartes). Chaque message a sa bulle d'explication sur le côté,
// reliée par un trait : l'algorithme et la clé utilisés pour CE message.
// Un bouton bascule entre la conversation en clair et ce qui a réellement
// circulé (le chiffré).
export default function Chat({ msgs, cipherView, onToggle, onClear }: {
  msgs: ChatMsg[]
  cipherView: boolean
  onToggle: () => void
  onClear: () => void   // supprime toute la conversation (écran + fichier)
}) {
  const n = msgs.length
  return (
    <section className="ex-chat" aria-label={t('Conversation entre A et B')}>
      <div className={'ex-chat-grid' + (cipherView ? ' is-cipher' : '')}>
        <div className="ex-chat-window" style={{ gridRow: `1 / ${n > 0 ? n + 3 : 2}` }} aria-hidden="true" />

        <header className={'ex-chat-head' + (n > 0 ? '' : ' is-empty')} style={{ gridRow: 1 }}>
          <span className="ex-chat-avatars">
            <span className="ex-avatar ex-from-a"><UserIcon /></span>
            <span className="ex-avatar ex-from-b"><UserIcon /></span>
          </span>
          <span className="ex-chat-title"><b>{t('Chat entre A et B')}</b></span>
          {n > 0 && (
            <button type="button" className="ex-chat-del" onClick={onClear}
              aria-label={t('Supprimer le chat')} title={t('Supprimer toute la conversation')}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v5M14 11v5" />
              </svg>
              <span className="ex-chat-del-text">{t('Supprimer le chat')}</span>
            </button>
          )}
          {/* les deux libellés sont empilés : le bouton garde la même largeur dans les deux vues */}
          <button type="button" className={'ex-chat-toggle' + (cipherView ? ' is-on' : '')} onClick={onToggle} aria-pressed={cipherView}>
            <span className={'ex-tog' + (cipherView ? ' is-off' : '')} aria-hidden={cipherView}><LockIcon /> {t('Voir chiffré')}</span>
            <span className={'ex-tog' + (cipherView ? '' : ' is-off')} aria-hidden={!cipherView}><UnlockIcon /> {t('Voir en clair')}</span>
          </button>
        </header>

        {msgs.map((m, i) => {
          const side = m.from === 'a' ? 'l' : 'r'
          const firstOfGroup = i === 0 || msgs[i - 1].from !== m.from
          const lastOfGroup = i === n - 1 || msgs[i + 1].from !== m.from
          const full = t(keyText(m.params)), abbr = t(keyShort(m.params))
          const how = t('{algo} · clé {key}', { algo: algoName(m.params.algo), key: abbr })
          return (
            <Fragment key={m.id}>
              {/* hors de la fenêtre : visible seulement dans la vue chiffrée, bulle après bulle */}
              <div
                className={`ex-side ex-side-${side} ex-from-${m.from}`} aria-hidden={!cipherView}
                style={{ gridRow: i + 2, '--d': `${Math.min(i, 8) * 70}ms` } as CSSProperties}
              >
                <div className="ex-callout">
                  <span className="ex-callout-algo">{algoName(m.params.algo)}</span>
                  <span className="ex-callout-key" title={abbr !== full ? full : undefined}>{t('clé {key}', { key: abbr })}</span>
                </div>
                <span className="ex-link" aria-hidden="true" />
              </div>
              <div
                className={`ex-chat-row is-${m.from} ex-from-${m.from}` + (i === 0 ? ' is-first' : firstOfGroup ? ' is-group' : '')}
                style={{ gridRow: i + 2 }}
              >
                <span className={'ex-avatar sm' + (lastOfGroup ? '' : ' is-ghost')}><UserIcon /></span>
                <div className="ex-bubble-wrap">
                  {/* clair et chiffré sont empilés dans la même case : la bulle (et donc la fenêtre) garde
                      exactement la même taille dans les deux vues, seul l'un des deux textes se voit */}
                  <div className={'ex-bubble' + (cipherView ? ' is-cipher' : '')} title={cipherView ? how : undefined}>
                    <span className={'ex-bubble-layer' + (cipherView ? ' is-off' : '')} aria-hidden={cipherView}>{m.plain}</span>
                    <span className={'ex-bubble-layer is-secret' + (cipherView ? '' : ' is-off')} aria-hidden={!cipherView}>
                      <span className="ex-bubble-lock"><LockIcon /></span>{m.cipher}
                    </span>
                  </div>
                  <span className="ex-bubble-cap">{how}</span>
                </div>
              </div>
            </Fragment>
          )
        })}

        {/* un peu d'air sous la dernière bulle */}
        {n > 0 && <div className="ex-chat-foot" style={{ gridRow: n + 2 }} aria-hidden="true" />}
      </div>
    </section>
  )
}
