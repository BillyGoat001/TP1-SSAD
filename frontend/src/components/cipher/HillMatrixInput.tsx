import { useEffect, useState } from 'react'
import type { CSSProperties } from 'react'
import { t } from '../../i18n'

interface Props {
  matrix: number[][]
  /** Cases de depart en texte (prioritaires sur `matrix`) : permet de partir de cases vides. */
  cells?: string[][]
  /** Les cases grandissent avec le nombre mais la grille ne depasse jamais son conteneur. */
  fit?: boolean
  onChange: (numbers: number[][], valid: boolean, cells: string[][]) => void
}

const SIZES = [2, 3, 4, 5]
const INTEGER = /^-?\d+$/ // a real integer: not empty, not a lone "-"
const GAP = 6 // px, same as .matrix-grid gap

function toCells(m: number[][]): string[][] {
  return m.map((row) => row.map((v) => String(v)))
}
function toNumbers(cells: string[][]): number[][] {
  return cells.map((row) =>
    row.map((s) => {
      const n = parseInt(s, 10)
      return Number.isNaN(n) ? 0 : n
    }),
  )
}
function allValid(cells: string[][]): boolean {
  return cells.every((row) => row.every((s) => INTEGER.test(s)))
}

// Size selector (2×2 … 5×5) + a grid of cells. Cells accept negative numbers;
// a lone "-" is flagged as invalid (an empty cell stays neutral but blocks the
// run). All cells share the width of the longest value, so the grid stays even.
export default function HillMatrixInput({ matrix, cells: initialCells, fit = false, onChange }: Props) {
  const [cells, setCells] = useState<string[][]>(() => initialCells ?? toCells(matrix))
  const n = cells.length

  // Report the current numbers + validity to the parent (also on mount).
  useEffect(() => {
    onChange(toNumbers(cells), allValid(cells), cells)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const commit = (next: string[][]) => {
    setCells(next)
    onChange(toNumbers(next), allValid(next), next)
  }

  const setCell = (r: number, c: number, raw: string) => {
    if (!/^-?\d*$/.test(raw)) return // allow an optional minus while typing
    const clean = raw.replace(/^(-?)0+(?=\d)/, '$1') // drop a leading zero
    const next = cells.map((row) => row.slice())
    next[r][c] = clean
    commit(next)
  }

  const resize = (size: number) => {
    commit(
      Array.from({ length: size }, (_, r) =>
        Array.from({ length: size }, (_, c) => cells[r]?.[c] ?? ''),
      ),
    )
  }

  const maxLen = Math.max(1, ...cells.flat().map((s) => s.length))
  const natural = `calc(${maxLen}ch + 1.6rem)`
  // en mode « fit », la case s'arrete de grandir quand la grille atteint le bord du conteneur
  const cellWidth = fit ? `min(${natural}, calc((100cqw - ${(n - 1) * GAP}px) / ${n}))` : natural

  return (
    <div className="hill-input">
      <div className="size-row">
        <span className="field-label">{t('Taille')}</span>
        {SIZES.map((size) => (
          <button key={size} type="button" className={'seg' + (n === size ? ' is-on' : '')} onClick={() => resize(size)}>
            {size}×{size}
          </button>
        ))}
      </div>

      <div className={'matrix-scroll' + (fit ? ' is-fit' : '')}>
        <div className="matrix-grid" style={{ gridTemplateColumns: `repeat(${n}, auto)` }}>
          {cells.map((row, r) =>
            row.map((v, c) => (
              <input
                key={`${r}-${c}`}
                className={'matrix-cell' + (v === '' || INTEGER.test(v) ? '' : ' invalid')}
                type="text"
                inputMode="numeric"
                placeholder="·"
                value={v}
                style={{ width: cellWidth } as CSSProperties}
                onChange={(e) => setCell(r, c, e.target.value)}
                aria-label={t('ligne {r}, colonne {c}', { r: r + 1, c: c + 1 })}
              />
            )),
          )}
        </div>
      </div>
    </div>
  )
}
