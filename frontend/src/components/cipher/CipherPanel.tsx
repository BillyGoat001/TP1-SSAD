import { useEffect, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import type { Algo, Operation, CipherResponse, Trace } from '../../types'
import { api, type CipherInput } from '../../api'
import { usePlayback } from './usePlayback'
import Playback from './Playback'
import CaesarViz from './CaesarViz'
import PlayfairViz from './PlayfairViz'
import HillViz from './HillViz'
import HillMatrixInput from './HillMatrixInput'

const ALGOS: { id: Algo; label: string }[] = [
  { id: 'caesar', label: 'César' },
  { id: 'playfair', label: 'Playfair' },
  { id: 'hill', label: 'Hill' },
]

function runningOutput(trace: Trace, index: number): string {
  if (index < 0) return ''
  if (trace.kind === 'caesar')
    return trace.steps.slice(0, index + 1).map((x) => (x.type === 'map' ? x.out! : x.char)).join('')
  if (trace.kind === 'playfair')
    return trace.steps.slice(0, index + 1).map((x) => x.outA + x.outB).join('')
  return trace.steps.slice(0, index + 1).map((x) => x.outChar).join('')
}

// Each letter animates on its own, staggered by its index (--i).
function Letters({ text, className }: { text: string; className: string }) {
  return (
    <span className={className}>
      {[...text].map((ch, i) => (
        <span key={i} style={{ '--i': i } as CSSProperties}>{ch === ' ' ? ' ' : ch}</span>
      ))}
    </span>
  )
}

const EyeOpen = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z" /><circle cx="12" cy="12" r="3" />
  </svg>
)
const EyeOff = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
)

export default function CipherPanel() {
  const [algo, setAlgo] = useState<Algo>('caesar')
  const [message, setMessage] = useState('BONJOUR')
  const [shift, setShift] = useState(3)
  const [direction, setDirection] = useState<'right' | 'left'>('right')
  const [playfairKey, setPlayfairKey] = useState('MONARCHY')
  // les cases restent en texte : un très grand nombre garde tous ses chiffres jusqu'au backend
  const [matrix, setMatrix] = useState<string[][]>([['3', '3'], ['2', '5']])
  const [matrixValid, setMatrixValid] = useState(true)

  const [resp, setResp] = useState<CipherResponse | null>(null)
  const [lastOp, setLastOp] = useState<Operation>('encrypt')
  const [revealed, setRevealed] = useState(false)
  const [feeding, setFeeding] = useState(false)   // dissolve + ripple playing
  const [showResult, setShowResult] = useState(false) // result only once it "exits"
  const [animKey, setAnimKey] = useState(0)
  const resultRef = useRef<HTMLDivElement>(null)

  // Glide the screen to the result as it emerges, so it is seen without scrolling.
  useEffect(() => {
    if (showResult) resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [showResult])

  const trace = resp && resp.ok ? resp.trace : undefined
  const total = trace ? trace.steps.length : 0
  const pb = usePlayback(total)
  const atEnd = pb.index >= total - 1
  const output = trace ? runningOutput(trace, pb.index) : ''

  function changeAlgo(a: Algo) {
    setAlgo(a)
    setResp(null)
    setRevealed(false)
    setFeeding(false)
    setShowResult(false)
  }

  function buildInput(op: Operation): CipherInput {
    if (algo === 'caesar') return { algo, operation: op, message, shift, direction }
    if (algo === 'playfair') return { algo, operation: op, message, key: playfairKey }
    return { algo, operation: op, message, matrix }
  }

  async function run(op: Operation) {
    if (algo === 'hill' && !matrixValid) {
      setResp({ ok: false, error: 'Chaque case de la matrice doit contenir un nombre (positif ou négatif).' })
      return
    }
    setLastOp(op)
    setRevealed(false)
    setShowResult(false)
    setFeeding(true)
    setAnimKey((k) => k + 1)
    window.setTimeout(() => setShowResult(true), 1150) // reveal result as it emerges
    window.setTimeout(() => setFeeding(false), 1500)
    try {
      setResp(await api.cipher(buildInput(op)))
    } catch {
      setResp({ ok: false, error: 'Backend injoignable. Lance le serveur Python.' })
    }
  }

  const copy = () => {
    if (output) navigator.clipboard?.writeText(output).catch(() => {})
  }

  return (
    <div className="panel">
      <h2 className="panel-title">Chiffrement &amp; déchiffrement</h2>
      <p className="panel-sub">
        Choisis l'algorithme et la clé, écris ton message, puis chiffre. La
        démonstration est floutée : à toi de la révéler pour voir les étapes.
        Le calcul est fait par le backend Python.
      </p>

      <div className="controls">
        <div className="field">
          <span className="field-label">Algorithme</span>
          <div className="segmented">
            {ALGOS.map((a) => (
              <button key={a.id} className={'seg' + (algo === a.id ? ' is-on' : '')} onClick={() => changeAlgo(a.id)}>
                {a.label}
              </button>
            ))}
          </div>
        </div>

        {algo === 'caesar' && (
          <>
            <div className="field">
              <span className="field-label">Décalage</span>
              <input
                className="text-input small" type="number" min={0} value={shift}
                onChange={(e) => setShift(Math.max(0, parseInt(e.target.value || '0', 10)))}
              />
            </div>
            <div className="field">
              <span className="field-label">Direction</span>
              <div className="segmented">
                <button className={'seg' + (direction === 'right' ? ' is-on' : '')} onClick={() => setDirection('right')}>Droite</button>
                <button className={'seg' + (direction === 'left' ? ' is-on' : '')} onClick={() => setDirection('left')}>Gauche</button>
              </div>
            </div>
          </>
        )}

        {algo === 'playfair' && (
          <div className="field grow">
            <span className="field-label">Clé (lettres)</span>
            <input
              className="text-input" value={playfairKey}
              onChange={(e) => setPlayfairKey(e.target.value.replace(/[^a-zA-Z ]/g, '').toUpperCase())}
              placeholder="ex. PLAYFAIR"
            />
          </div>
        )}

        {algo === 'hill' && (
          <HillMatrixInput
            matrix={[]}
            cells={matrix}
            onChange={(_nums, valid, cells) => {
              setMatrix(cells)
              setMatrixValid(valid)
            }}
          />
        )}
      </div>

      <div className="field">
        <span className="field-label">Message clair</span>
        <textarea
          className="text-area" rows={2} value={message}
          onChange={(e) =>
            setMessage(e.target.value.normalize('NFD').replace(/[̀-ͯ]/g, '').toUpperCase())
          }
        />
      </div>

      <div className="btn-row cipher-actions">
        <button className="btn btn-accent" onClick={() => run('encrypt')}>Chiffrer ↓</button>
        <button className="btn btn-accent" onClick={() => run('decrypt')}>Déchiffrer ↓</button>
      </div>

      {resp && !resp.ok && <div className="warn error">⚠ {resp.error}</div>}
      {resp && resp.ok && resp.warning && <div className="warn">⚠ {resp.warning}</div>}

      {trace && (
        <div className={'demo-box' + (revealed ? '' : ' blurred') + (feeding ? ' feeding' : '')}>
          <button
            className="blur-toggle"
            onClick={() => setRevealed((r) => !r)}
            aria-label={revealed ? 'Flouter' : 'Déflouter'}
            title={revealed ? 'Flouter' : 'Déflouter'}
          >
            {revealed ? <EyeOff /> : <EyeOpen />}
          </button>

          {feeding && (
            <>
              <Letters key={'d' + animKey} className="msg-dissolve" text={(message || ' ').toUpperCase()} />
              <div key={'r' + animKey} className="fog-ripple" />
            </>
          )}

          <div className="demo-content">
            {trace.kind === 'caesar' && <CaesarViz trace={trace} index={pb.index} />}
            {trace.kind === 'playfair' && <PlayfairViz trace={trace} index={pb.index} original={message} />}
            {trace.kind === 'hill' && <HillViz trace={trace} index={pb.index} original={message} />}

            {revealed && (
              <>
                <Playback
                  playing={pb.playing} speed={pb.speed} setSpeed={pb.setSpeed}
                  play={pb.play} pause={pb.pause} step={pb.step} reset={pb.reset} atEnd={atEnd}
                />
                <div className="step-counter">Étape {Math.max(0, pb.index + 1)} / {total}</div>
              </>
            )}
          </div>
        </div>
      )}

      {trace && showResult && (
        <div className="sortie" ref={resultRef} key={'s' + animKey}>
          <span className="output-label">
            {lastOp === 'encrypt' ? 'Message chiffré' : 'Message déchiffré'}
          </span>
          <Letters className="result-text result-materialize" text={output || '—'} />
          <button className="btn tiny" onClick={copy}>Copier</button>
        </div>
      )}
    </div>
  )
}
