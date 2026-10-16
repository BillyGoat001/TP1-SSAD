import { useEffect, useState } from 'react'
import type { CSSProperties } from 'react'

interface Props {
  matrix: number[][]
  onChange: (numbers: number[][], valid: boolean) => void
}

const SIZES = [2, 3, 4, 5]
const INTEGER = /^-?\d+$/ // a real integer: not empty, not a lone "-"

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
// a lone "-" or an empty cell is flagged as invalid. All cells share the width
// of the longest value, so the grid stays visually even.
export default function HillMatrixInput({ matrix, onChange }: Props) {
  const [cells, setCells] = useState<string[][]>(() => toCells(matrix))
  const n = cells.length

  // Report the current numbers + validity to the parent (also on mount).
  useEffect(() => {
    onChange(toNumbers(cells), allValid(cells))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const commit = (next: string[][]) => {
    setCells(next)
    onChange(toNumbers(next), allValid(next))
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
  const cellWidth = `calc(${maxLen}ch + 1.6rem)`

  return (
    <div className="hill-input">
      <div className="size-row">
        <span className="field-label">Taille</span>
        {SIZES.map((size) => (
          <button key={size} type="button" className={'seg' + (n === size ? ' is-on' : '')} onClick={() => resize(size)}>
            {size}×{size}
          </button>
        ))}
      </div>

      <div className="matrix-scroll">
        <div className="matrix-grid" style={{ gridTemplateColumns: `repeat(${n}, auto)` }}>
          {cells.map((row, r) =>
            row.map((v, c) => (
              <input
                key={`${r}-${c}`}
                className={'matrix-cell' + (INTEGER.test(v) ? '' : ' invalid')}
                type="text"
                inputMode="numeric"
                value={v}
                style={{ width: cellWidth } as CSSProperties}
                onChange={(e) => setCell(r, c, e.target.value)}
                aria-label={`ligne ${r + 1}, colonne ${c + 1}`}
              />
            )),
          )}
        </div>
      </div>
    </div>
  )
}
