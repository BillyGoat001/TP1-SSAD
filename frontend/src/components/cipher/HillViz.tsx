import type { HillTrace } from '../../types'

interface Props {
  trace: HillTrace
  index: number
  original: string
}

// Matrix × block on the left; the prepared message and the current dot-product
// on the right; an A=0 … Z=25 reference row below.
export default function HillViz({ trace, index, original }: Props) {
  const current = index >= 0 ? trace.steps[index] : null
  const blockIdx = current ? current.blockIndex : 0
  const block = trace.blocks[blockIdx]
  const cleanOriginal = original.toUpperCase().replace(/[^A-Z]/g, '') || '—'

  // Which letters/values are "active" in the current step (to highlight them below).
  const activeValues = new Set(current ? current.values : [])

  return (
    <div className="viz">
      <div className="split-layout">
        <div className="split-main">
          <div className="viz-caption">
            {trace.n}×{trace.n} — matrice clé × bloc de {trace.n} lettres (mod 26).
          </div>
          <div className="hill-eq">
            <div className="hill-matrix">
              {trace.matrix.map((row, r) => (
                <div
                  key={r}
                  className={'hill-row' + (current && r === current.rowIndex ? ' is-active' : '')}
                >
                  {row.map((v, c) => (
                    <span key={c} className="hill-num">{v}</span>
                  ))}
                </div>
              ))}
            </div>
            <div className="hill-times">×</div>
            <div className="hill-vector">
              {block.letters.map((ch, i) => (
                <div key={i} className="hill-vcell">
                  <span className="hill-vletter">{ch}</span>
                  <span className="hill-vval">{block.values[i]}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="split-side">
          <div className="prep">
            <span className="prep-label">Message préparé</span>
            <div className="prep-flow">
              <code className="prep-orig">{cleanOriginal}</code>
              <span className="prep-arrow">→</span>
              <code className="prep-digrams">{trace.cleaned}</code>
            </div>
            <span className="prep-note">Un X complète le dernier bloc si besoin.</span>
          </div>

          {current && (
            <div className="hill-calc">
              <span className="focus-in">ligne {current.rowIndex + 1}</span>
              <span className="calc-terms">
                {current.terms.map(([m, v], i) => (
                  <span key={i}>
                    {i > 0 ? ' + ' : ''}{m}·{v}
                  </span>
                ))}
                {' = '}{current.sum} ≡ {current.mod} (mod 26)
              </span>
              <span className="focus-op">→</span>
              <span className="focus-out">{current.outChar}</span>
            </div>
          )}
        </div>
      </div>

      {/* A = 0 … Z = 25 reference */}
      <div className="hill-alpha-caption">Correspondance lettre → nombre (A = 0 … Z = 25)</div>
      <div className="hill-alphabet-scroll">
        <div className="hill-alphabet">
          {Array.from({ length: 26 }, (_, i) => (
            <div key={i} className={'ha-col' + (activeValues.has(i) ? ' is-active' : '')}>
              <span className="ha-letter">{String.fromCharCode(65 + i)}</span>
              <span className="ha-num">{i}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
