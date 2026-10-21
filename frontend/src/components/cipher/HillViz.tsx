import type { CSSProperties } from 'react'
import type { HillTrace } from '../../types'
import { t } from '../../i18n'

interface Props {
  trace: HillTrace
  index: number
  original: string
  showResult?: boolean // sous chaque bloc, son résultat (partie Échange)
}

/** Un très grand nombre s'affiche abrégé (12345…67890) ; la valeur exacte reste dans l'info-bulle. */
function Num({ v, className }: { v: number | string; className?: string }) {
  const s = String(v)
  const cut = s.length > 13
  return <span className={className} title={cut ? s : undefined}>{cut ? s.slice(0, 5) + '…' + s.slice(-5) : s}</span>
}

// Matrix × block on the left; the prepared message and the current dot-product
// on the right; an A=0 … Z=25 reference row below.
export default function HillViz({ trace, index, original, showResult = false }: Props) {
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
            {t('{n}×{n} — matrice clé × bloc de {n} lettres (mod 26).', { n: trace.n })}
          </div>
          <div className="hill-eq">
            <div className="hill-matrix" style={{ '--n': trace.n } as CSSProperties}>
              {trace.matrix.map((row, r) => (
                <div
                  key={r}
                  className={'hill-row' + (current && r === current.rowIndex ? ' is-active' : '')}
                >
                  {row.map((v, c) => (
                    <Num key={c} className="hill-num" v={v} />
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
            <span className="prep-label">{t('Message préparé')}</span>
            <div className="prep-flow">
              <code className="prep-orig">{cleanOriginal}</code>
              <span className="prep-arrow">→</span>
              <code className="prep-digrams">{trace.cleaned}</code>
            </div>
            <span className="prep-note">{t('Un X complète le dernier bloc si besoin.')}</span>
          </div>

          {current && (
            <div className="hill-calc">
              <span className="focus-in">{t('ligne {n}', { n: current.rowIndex + 1 })}</span>
              <span className="calc-terms">
                {current.terms.map(([m, v], i) => (
                  <span key={i}>
                    {i > 0 ? ' + ' : ''}<Num v={m} />·{v}
                  </span>
                ))}
                {' = '}<Num v={current.sum} /> ≡ {current.mod} (mod 26)
              </span>
              <span className="focus-op">→</span>
              <span className="focus-out">{current.outChar}</span>
            </div>
          )}
        </div>
      </div>

      {showResult && (
        <div className="tiles tiles-io hill-io">
          {trace.blocks.map((b, bi) => {
            const steps = trace.steps.map((s, i) => ({ s, i })).filter((x) => x.s.blockIndex === bi)
            const isCur = !!current && current.blockIndex === bi
            const done = steps.length > 0 && steps[steps.length - 1].i < index && !isCur
            const out = steps.filter((x) => x.i <= index).map((x) => x.s.outChar).join('')
            return (
              <div key={bi} className="tile-io">
                <span className={'tile wide' + (done ? ' done' : '') + (isCur ? ' current' : '')}>{b.letters.join('')}</span>
                <span className={'tile wide tile-out' + (out ? ' is-shown' : '') + (isCur ? ' is-current' : '')}>{out}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* A = 0 … Z = 25 reference */}
      <div className="hill-alpha-caption">{t('Correspondance lettre → nombre (A = 0 … Z = 25)')}</div>
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
