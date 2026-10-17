import type { PlayfairTrace } from '../../types'

interface Props {
  trace: PlayfairTrace
  index: number
  original: string
  showResult?: boolean // sous chaque paire, son résultat (partie Échange)
}

const RULE_LABEL: Record<string, string> = {
  row: 'même ligne → lettre à droite',
  col: 'même colonne → lettre en dessous',
  rect: 'rectangle → échange des colonnes',
}

// 5x5 grid on the left; the prepared message, digrams and current step on the
// right. The I cell shows "I/J" (the two letters share it).
export default function PlayfairViz({ trace, index, original, showResult = false }: Props) {
  const current = index >= 0 ? trace.steps[index] : null
  const isAt = (pos: [number, number] | undefined, r: number, c: number) =>
    !!pos && pos[0] === r && pos[1] === c

  const prepared = trace.steps.map((s) => s.a + s.b).join(' ')
  const cleanOriginal = original.toUpperCase().replace(/[^A-Z]/g, '') || '—'

  return (
    <div className="viz split-layout">
      <div className="split-main">
        <div className="viz-caption">Grille 5×5 construite à partir de la clé.</div>
        <div className="pf-grid">
          {trace.grid.map((row, r) =>
            row.map((ch, c) => {
              const source =
                current && (isAt(current.aPos, r, c) || isAt(current.bPos, r, c))
              const target =
                current && (isAt(current.outAPos, r, c) || isAt(current.outBPos, r, c))
              return (
                <div
                  key={`${r}-${c}`}
                  className={
                    'pf-cell' +
                    (ch === 'I' ? ' pf-ij' : '') +
                    (source ? ' is-source' : '') +
                    (target ? ' is-target' : '')
                  }
                >
                  {ch === 'I' ? 'I/J' : ch}
                </div>
              )
            }),
          )}
        </div>
      </div>

      <div className="split-side">
        <div className="prep">
          <span className="prep-label">Message préparé</span>
          <div className="prep-flow">
            <code className="prep-orig">{cleanOriginal}</code>
            <span className="prep-arrow">→</span>
            <code className="prep-digrams">{prepared || '—'}</code>
          </div>
          <span className="prep-note">J est remplacé par I, et un X complète si besoin.</span>
        </div>

        {showResult ? (
          <div className="tiles tiles-io">
            {trace.steps.map((s, i) => (
              <div key={i} className="tile-io">
                <span className={'tile wide' + (i < index ? ' done' : '') + (i === index ? ' current' : '')}>
                  {s.a}{s.b}
                </span>
                <span className={'tile wide tile-out' + (i <= index ? ' is-shown' : '') + (i === index ? ' is-current' : '')}>
                  {i <= index ? s.outA + s.outB : ''}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="tiles">
            {trace.steps.map((s, i) => (
              <span
                key={i}
                className={'tile wide' + (i < index ? ' done' : '') + (i === index ? ' current' : '')}
              >
                {s.a}{s.b}
              </span>
            ))}
          </div>
        )}

        {current && (
          <div className="focus">
            <span className="focus-in">{current.a}{current.b}</span>
            <span className="focus-op">→</span>
            <span className="focus-out">{current.outA}{current.outB}</span>
            <span className="rule-tag">{RULE_LABEL[current.rule]}</span>
          </div>
        )}
      </div>
    </div>
  )
}
