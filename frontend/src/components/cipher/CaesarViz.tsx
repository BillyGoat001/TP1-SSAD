import type { CaesarTrace } from '../../types'

interface Props {
  trace: CaesarTrace
  index: number
}

// Two aligned alphabet rows (plain -> shifted). Walking the message, each letter
// lights up its column, and the shifted letter below it is the result.
export default function CaesarViz({ trace, index }: Props) {
  const current = index >= 0 ? trace.steps[index] : null
  const highlightCol = current && current.type === 'map' ? current.index! : null

  return (
    <div className="viz">
      <div className="viz-caption">
        Décalage effectif : <strong>+{trace.shift}</strong> — chaque lettre du
        haut est remplacée par celle du bas.
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
          « {current.char === ' ' ? 'espace' : current.char} » n'est pas une lettre → inchangé
        </div>
      )}

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
            {s.char === ' ' ? '␣' : s.char}
          </span>
        ))}
      </div>
    </div>
  )
}
