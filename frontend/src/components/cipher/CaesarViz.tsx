import type { CaesarTrace } from '../../types'
import { t, getLang } from '../../i18n'

const q = (c: string) => (getLang() === 'en' ? `"${c}"` : `« ${c} »`)

interface Props {
  trace: CaesarTrace
  index: number
  showResult?: boolean // sous chaque lettre, son résultat (partie Échange)
}

const show = (ch: string) => (ch === ' ' ? '␣' : ch === '\n' ? '↵' : ch)

// Two aligned alphabet rows (plain -> shifted). Walking the message, each letter
// lights up its column, and the shifted letter below it is the result.
export default function CaesarViz({ trace, index, showResult = false }: Props) {
  const current = index >= 0 ? trace.steps[index] : null
  const highlightCol = current && current.type === 'map' ? current.index! : null

  return (
    <div className="viz">
      <div className="viz-caption">
        {t('Décalage effectif :')} <strong>+{trace.shift}</strong> — {t('chaque lettre du haut est remplacée par celle du bas.')}
      </div>

      <div className="alpha-scroll">
        <div className="alpha-grid">
          {trace.alphabetIn.map((ch, i) => (
            <div
              key={i}
              className={'alpha-col' + (i === highlightCol ? ' is-active' : '')}
            >
              <div className="alpha-cell in">{ch}</div>
              <div className="alpha-arrow">↓</div>
              <div className="alpha-cell out">{trace.alphabetOut[i]}</div>
            </div>
          ))}
        </div>
      </div>

      {current && current.type === 'map' && (
        <div className="focus">
          <span className="focus-in">{current.char}</span>
          <span className="focus-op">→</span>
          <span className="focus-out">{current.out}</span>
        </div>
      )}
      {current && current.type === 'skip' && (
        <div className="focus muted">
          {t('{c} n\'est pas une lettre → inchangé', { c: q(current.char === ' ' ? t('espace') : current.char === '\n' ? t('retour à la ligne') : current.char) })}
        </div>
      )}

      {showResult ? (
        <div className="tiles tiles-io">
          {trace.steps.map((s, i) => {
            const out = s.type === 'map' ? s.out! : s.char
            return (
              <div key={i} className="tile-io">
                <span className={'tile' + (i < index ? ' done' : '') + (i === index ? ' current' : '') + (s.type === 'skip' ? ' skip' : '')}>
                  {show(s.char)}
                </span>
                <span className={'tile tile-out' + (i <= index ? ' is-shown' : '') + (i === index ? ' is-current' : '') + (s.type === 'skip' ? ' skip' : '')}>
                  {i <= index ? show(out) : ''}
                </span>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="tiles">
          {trace.steps.map((s, i) => (
            <span
              key={i}
              className={
                'tile' +
                (i < index ? ' done' : '') +
                (i === index ? ' current' : '') +
                (s.type === 'skip' ? ' skip' : '')
              }
            >
              {show(s.char)}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
