import { useEffect, useRef, useState } from 'react'
import type { IntegrityDemo } from '../../types'
import { api } from '../../api'
import { t, _t } from '../../i18n'

// Partie 4 — Intégrité du message (HMAC-SHA256).
// A envoie (message, étiquette) à B sur un canal. Le message peut être
// intercepté et modifié en route par un attaquant C : B recalcule l'étiquette
// sur ce qu'il a reçu et compare. Une étiquette qui ne correspond plus révèle
// la modification. Toute l'idée est montrée par une animation sur le canal.

type Pt = { x: number; y: number }
type Dot = { x: number; y: number; color: 'green' | 'red' }
type Phase = 'idle' | 'leg1' | 'toC' | 'atC' | 'legCB' | 'done'

// Repères de la scène (unités du viewBox ; le SVG se met à l'échelle tout seul).
const VB = { w: 320, h: 228 }
const A: Pt = { x: 46, y: 72 }
const B: Pt = { x: 274, y: 72 }
const C: Pt = { x: 160, y: 176 }
const TICK = 70 // ms entre deux points qui s'allument
const STEP = 11 // espacement des points (unités viewBox)

function dotsAlong(p: Pt, q: Pt, color: 'green' | 'red', step = STEP): Dot[] {
  const dx = q.x - p.x
  const dy = q.y - p.y
  const len = Math.hypot(dx, dy)
  const n = Math.max(1, Math.round(len / step))
  const out: Dot[] = []
  for (let i = 1; i <= n; i++) out.push({ x: p.x + (dx * i) / n, y: p.y + (dy * i) / n, color })
  return out
}

// Exemples affichés en gris dans les champs vides (comme « ex. 3 » dans les autres pages)
const EX_KEY = _t('ex. cle-partagee')
const EX_MSG = _t('ex. Virement de 100 DA vers le compte B')
const EX_TAMPER = _t('ex. Virement de 900 DA vers le compte E')

export default function IntegrityPanel() {
  const [key, setKey] = useState('')
  const [original, setOriginal] = useState('')
  const [tampered, setTampered] = useState('')
  const [error, setError] = useState<string | null>(null)   // champ vide : message rouge, comme dans les autres pages

  const [phase, setPhase] = useState<Phase>('idle')
  const [lit, setLit] = useState<Dot[]>([])      // points déjà allumés (persistants)
  const [base, setBase] = useState<Dot[]>([])    // points à venir (faibles)
  const [tagA, setTagA] = useState('…')          // étiquette calculée par A
  const [result, setResult] = useState<IntegrityDemo | null>(null)

  const timer = useRef<number | undefined>(undefined)
  const phaseRef = useRef<Phase>('idle')
  const intercepted = useRef(false)
  const lastDot = useRef<Pt>(A)
  const tamperRef = useRef(tampered)
  const cRef = useRef<HTMLTextAreaElement>(null)
  phaseRef.current = phase
  tamperRef.current = tampered

  const clearTimer = () => {
    if (timer.current) window.clearInterval(timer.current)
    timer.current = undefined
  }

  // Étiquette de A (affichée dès qu'on a une clé + un message), recalculée en direct.
  useEffect(() => {
    if (!key || !original) { setTagA('…'); return }
    const id = window.setTimeout(() => {
      api.integrityDemo(key, original, original)
        .then((d) => setTagA(d.ok ? d.tag : '…'))
        .catch(() => setTagA('…'))
    }, 150)
    return () => window.clearTimeout(id)
  }, [key, original])

  // Changer la clé / le message de A remet la scène à zéro.
  // (Modifier le texte réécrit par C ne réinitialise rien : on le tape pendant l'interception.)
  useEffect(() => {
    resetScene()
    setError(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, original])

  useEffect(() => () => clearTimer(), [])

  // Quand le message arrive chez C, on met le curseur dans son champ pour écrire tout de suite.
  useEffect(() => {
    if (phase === 'atC') {
      cRef.current?.focus()
      cRef.current?.select()
    }
  }, [phase])

  function resetScene() {
    clearTimer()
    intercepted.current = false
    lastDot.current = A
    setLit([])
    setBase([])
    setResult(null)
    setPhase('idle')
  }

  // Allume une file de points un par un, puis appelle onDone().
  function runLeg(dots: Dot[], onDone: () => void) {
    setBase(dots)
    let i = 0
    clearTimer()
    timer.current = window.setInterval(() => {
      if (i >= dots.length) {
        clearTimer()
        onDone()
        return
      }
      const d = dots[i]
      i++
      lastDot.current = { x: d.x, y: d.y }
      setLit((prev) => [...prev, d])
      setBase((prev) => prev.slice(1))
    }, TICK)
  }

  async function finish(received: string) {
    setPhase('done')
    try {
      const d = await api.integrityDemo(key, original, received)
      setResult(d)
    } catch {
      setResult(null)
    }
  }

  function send() {
    // mêmes garde-fous que dans les autres pages : un champ vide affiche un message clair
    if (!key.trim()) { setError(_t('Indique la clé secrète partagée.')); return }
    if (!original.trim()) { setError(_t('Écris le message de A.')); return }
    setError(null)
    resetScene()
    intercepted.current = false
    setPhase('leg1')
    runLeg(dotsAlong(A, B, 'green'), () => {
      if (!intercepted.current) finish(original)   // arrivé intact
    })
  }

  function alterer() {
    if (phaseRef.current !== 'leg1') return
    intercepted.current = true
    clearTimer()
    setBase([])                                     // on abandonne la fin du trajet A→B
    const from = lastDot.current
    setPhase('toC')
    // le message est tiré vers C, puis on ATTEND : C écrit ce qu'il veut avant de renvoyer
    runLeg(dotsAlong(from, C, 'green'), () => setPhase('atC'))
  }

  // C a réécrit son message et le transmet à B (segment rouge C→B).
  function sendFromC() {
    if (phaseRef.current !== 'atC') return
    if (!tamperRef.current.trim()) { setError(_t('C doit écrire un message à envoyer à B.')); return }
    setError(null)
    setPhase('legCB')
    runLeg(dotsAlong(C, B, 'red'), () => finish(tamperRef.current))
  }

  const sending = phase === 'leg1' || phase === 'toC' || phase === 'atC' || phase === 'legCB'
  const showC = intercepted.current && phase !== 'idle'
  const received = result ? (result.valid ? original : tampered) : original

  const caption =
    t(phase === 'idle' ? 'A va envoyer son message signé à B sur le canal.'
      : phase === 'leg1' ? 'Le message circule sur le canal…'
      : phase === 'toC' ? 'C intercepte le message !'
      : phase === 'atC' ? 'C tient le message — réécris-le dans la carte C, puis « Envoyer à B ».'
      : phase === 'legCB' ? 'Le message modifié repart vers B…'
      : result && result.valid ? '✓ Arrivé intact : les étiquettes correspondent.'
      : '✗ B détecte l’altération : les étiquettes diffèrent.')

  // couleur d'un nœud
  const nodeColor = (who: 'A' | 'B' | 'C') =>
    who === 'A' ? 'var(--ua)' : who === 'B' ? 'var(--ub)' : 'var(--red)'

  return (
    <div className="panel">
      <h2 className="panel-title">{t('Intégrité du message (HMAC-SHA256)')}</h2>
      <div className="intg-fields">
        <div className="field">
          <span className="field-label">{t('Clé secrète partagée (A et B)')}</span>
          <input className="text-input" value={key} placeholder={t(EX_KEY)} autoComplete="off"
            onChange={(e) => setKey(e.target.value)} />
        </div>
        <div className="field">
          <span className="field-label">{t('Message de A')}</span>
          <textarea className="text-area" rows={2} value={original} placeholder={t(EX_MSG)}
            onChange={(e) => setOriginal(e.target.value)} />
        </div>
      </div>

      {/* ---------------- scène animée du canal ---------------- */}
      <div className="intg-scene">
        <svg viewBox={`0 0 ${VB.w} ${VB.h}`} className="intg-svg" role="img"
          aria-label={t('Canal entre A et B, avec interception possible par C')}>
          {/* points à venir (faibles, couleur de l'interface) */}
          {base.map((d, i) => (
            <circle key={'b' + i} cx={d.x} cy={d.y} r={3} className="intg-dot intg-dot-base" />
          ))}
          {/* points allumés (vert = en route, rouge = après C) */}
          {lit.map((d, i) => (
            <circle key={'l' + i} cx={d.x} cy={d.y} r={3.4}
              className={'intg-dot ' + (d.color === 'green' ? 'intg-dot-ok' : 'intg-dot-bad')
                + (i === lit.length - 1 && sending ? ' is-head' : '')} />
          ))}

          {/* nœud A */}
          <g className="intg-node">
            <circle cx={A.x} cy={A.y} r={18} style={{ stroke: nodeColor('A') }} />
            <text x={A.x} y={A.y + 5} className="intg-node-letter" style={{ fill: nodeColor('A') }}>A</text>
          </g>
          {/* nœud B */}
          <g className="intg-node">
            <circle cx={B.x} cy={B.y} r={18} style={{ stroke: nodeColor('B') }} />
            <text x={B.x} y={B.y + 5} className="intg-node-letter" style={{ fill: nodeColor('B') }}>B</text>
          </g>
          {/* nœud C (attaquant), visible seulement après interception */}
          <g className={'intg-node intg-node-c' + (showC ? ' is-on' : '')}>
            <circle cx={C.x} cy={C.y} r={18} style={{ stroke: nodeColor('C') }} />
            <text x={C.x} y={C.y + 5} className="intg-node-letter" style={{ fill: nodeColor('C') }}>C</text>
          </g>
        </svg>

        <div className={'intg-caption' + (phase === 'done' && result ? (result.valid ? ' is-ok' : ' is-bad') : '')}>
          {caption}
        </div>

        <div className="intg-actions">
          {!sending && (
            <button className="btn btn-accent" onClick={send}>
              {phase === 'done' ? t('Renvoyer') : t('Envoyer le message')}
            </button>
          )}
          <button className="btn intg-alter" onClick={alterer} disabled={phase !== 'leg1'}>
            ✂ {t('Altérer en vol')}
          </button>
          {(phase === 'done' || phase === 'atC') && (
            <button className="btn" onClick={resetScene}>{t('Réinitialiser')}</button>
          )}
        </div>
        {error && <div className="warn error intg-error" role="alert">⚠ {t(error)}</div>}
      </div>

      {/* ---------------- cartes : message + étiquettes ---------------- */}
      <div className="intg-cards">
        <div className="party" style={{ borderColor: 'color-mix(in srgb, var(--ua) 45%, var(--border))' }}>
          <div className="party-head" style={{ color: 'var(--ua)' }}>{t('Utilisateur A (expéditeur)')}</div>
          <div className="intg-msg">{original || <span className="intg-pending">—</span>}</div>
          <div className="tag-box">
            <span className="tag-label">{t('Étiquette HMAC envoyée')}</span>
            <code className="tag-hex">{tagA}</code>
          </div>
        </div>

        {showC && (
          <div className="party intg-card-c">
            <div className="party-head" style={{ color: 'var(--red)' }}>{t('Attaquant')}</div>
            <span className="tag-label">{t('Message réécrit par C')}</span>
            <textarea ref={cRef} className="text-area" rows={2} value={tampered}
              disabled={phase !== 'atC'}
              placeholder={t(EX_TAMPER)}
              onChange={(e) => setTampered(e.target.value)} />
            {phase === 'atC' && (
              <button className="btn btn-accent intg-sendc" onClick={sendFromC}>{t('Envoyer à B ↓')}</button>
            )}
            <span className="intg-note">{t('C n’a pas la clé : il ne peut pas refaire une étiquette valide.')}</span>
          </div>
        )}

        <div className="party" style={{ borderColor: 'color-mix(in srgb, var(--ub) 45%, var(--border))' }}>
          <div className="party-head" style={{ color: 'var(--ub)' }}>{t('Utilisateur B (destinataire)')}</div>
          <div className="intg-msg">{phase === 'done' ? received : <span className="intg-pending">{t('en attente…')}</span>}</div>
          <div className="tag-box">
            <span className="tag-label">{t('Étiquette recalculée par B')}</span>
            <code className={'tag-hex' + (result && !result.valid ? ' bad' : '')}>
              {result ? result.recomputed : '…'}
            </code>
          </div>
        </div>
      </div>

      {phase === 'done' && result && (
        <div className={'verdict ' + (result.valid ? 'ok' : 'bad')}>
          {result.valid
            ? t('✓ Message intègre : les deux étiquettes sont identiques, le message n’a pas été modifié.')
            : t('✗ Message altéré : les étiquettes diffèrent, le message a été modifié en transit.')}
        </div>
      )}
    </div>
  )
}
