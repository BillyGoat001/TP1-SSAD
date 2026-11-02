import { useEffect, useRef, useState } from 'react'
import type { CipherRecord, ExchangeParams, IntegrityOpenResult } from '../../types'
import { api } from '../../api'
import { algoName, keyText } from '../exchange/parts'
import { t, _t } from '../../i18n'

// Partie 4 — Integrite du message (HMAC-SHA256).
// A chiffre vraiment son message (Cesar/Playfair/Hill tires au hasard, comme
// pour un mot de passe — voir backend/auth.py) et signe le CLAIR avant
// chiffrement. C'est le CHIFFRE qui « voyage » sur le canal, et un attaquant C
// peut l'intercepter et le modifier en route. Avec la protection activee, B
// recalcule l'etiquette sur ce qu'il a dechiffre et la compare : toute
// alteration du chiffre fait diverger les etiquettes. Sans protection, B
// affiche simplement ce qu'il a dechiffre comme « bien recu », sans aucune
// verification — c'est la faille que la page demontre.

type Pt = { x: number; y: number }
type Dot = { x: number; y: number; color: 'green' | 'red' }
type Phase = 'idle' | 'leg1' | 'toC' | 'atC' | 'legCB' | 'done'

// Reperes de la scene (unites du viewBox ; le SVG se met a l'echelle tout seul).
const VB = { w: 320, h: 228 }
const A: Pt = { x: 46, y: 72 }
const B: Pt = { x: 274, y: 72 }
const C: Pt = { x: 160, y: 176 }
const TICK = 70 // ms entre deux points qui s'allument
const STEP = 11 // espacement des points (unites viewBox)

function dotsAlong(p: Pt, q: Pt, color: 'green' | 'red', step = STEP): Dot[] {
  const dx = q.x - p.x
  const dy = q.y - p.y
  const len = Math.hypot(dx, dy)
  const n = Math.max(1, Math.round(len / step))
  const out: Dot[] = []
  for (let i = 1; i <= n; i++) out.push({ x: p.x + (dx * i) / n, y: p.y + (dy * i) / n, color })
  return out
}

// (algo, cle) d'un CipherRecord CHIFFRE (method non nul), dans la forme
// attendue par keyText/algoName (les memes helpers que la page Echange).
function asParams(r: CipherRecord): ExchangeParams | null {
  if (r.method === 'caesar') return { algo: 'caesar', shift: r.key.shift, direction: 'right' }
  if (r.method === 'playfair') return { algo: 'playfair', key: r.key.key }
  if (r.method === 'hill') return { algo: 'hill', matrix: r.key.matrix }
  return null
}

// Exemples affiches en gris dans les champs vides (comme « ex. 3 » dans les autres pages)
const EX_KEY = _t('ex. cle-partagee')
const EX_MSG = _t('ex. Virement de 100 DA vers le compte B')

export default function IntegrityPanel() {
  const [key, setKey] = useState('')
  const [original, setOriginal] = useState('')
  const [tampered, setTampered] = useState('')          // le CHIFFRE, tel que C le reecrit
  const [error, setError] = useState<string | null>(null)   // champ vide : message rouge, comme dans les autres pages
  const [protect, setProtect] = useState(false)
  const [encrypt, setEncrypt] = useState(false)            // false = le message voyage en clair
  const [revealed, setRevealed] = useState(false)        // algo + cle tires au hasard, reveles ou non

  const [phase, setPhase] = useState<Phase>('idle')
  const [lit, setLit] = useState<Dot[]>([])      // points deja allumes (persistants)
  const [base, setBase] = useState<Dot[]>([])    // points a venir (faibles)
  const [tagA, setTagA] = useState('…')          // etiquette calculee par A (clair), apercu en direct
  const [record, setRecord] = useState<CipherRecord | null>(null)   // chiffrement reel de ce message (une fois envoye)
  const [sealTag, setSealTag] = useState<string | null>(null)       // etiquette REELLEMENT envoyee avec ce record
  const [openResult, setOpenResult] = useState<IntegrityOpenResult | null>(null)

  const timer = useRef<number | undefined>(undefined)
  const phaseRef = useRef<Phase>('idle')
  const intercepted = useRef(false)
  const lastDot = useRef<Pt>(A)
  const tamperRef = useRef(tampered)
  const recordRef = useRef<CipherRecord | null>(null)
  const cRef = useRef<HTMLTextAreaElement>(null)
  phaseRef.current = phase
  tamperRef.current = tampered
  recordRef.current = record

  const clearTimer = () => {
    if (timer.current) window.clearInterval(timer.current)
    timer.current = undefined
  }

  // Etiquette de A (apercu en direct, sur le clair — avant tout envoi reel).
  useEffect(() => {
    if (!protect || !key || !original) { setTagA('…'); return }
    const id = window.setTimeout(() => {
      api.integrityDemo(key, original, original)
        .then((d) => setTagA(d.ok ? d.tag : '…'))
        .catch(() => setTagA('…'))
    }, 150)
    return () => window.clearTimeout(id)
  }, [key, original, protect])

  // Changer la cle / le message de A remet la scene a zero.
  // (Modifier le chiffre reecrit par C ne reinitialise rien : on le tape pendant l'interception.)
  useEffect(() => {
    resetScene()
    setError(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, original])

  useEffect(() => () => clearTimer(), [])

  // Quand le message arrive chez C, on pre-remplit avec le VRAI chiffre intercepte
  // (C modifie ce qui transite reellement, pas un texte invente) et on y met le curseur.
  useEffect(() => {
    if (phase === 'atC') {
      setTampered(recordRef.current?.secret ?? '')
      cRef.current?.focus()
    }
  }, [phase])

  function resetScene() {
    clearTimer()
    intercepted.current = false
    lastDot.current = A
    setLit([])
    setBase([])
    setRecord(null)
    setSealTag(null)
    setOpenResult(null)
    setRevealed(false)
    setTampered('')
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

  async function finish(toOpen: CipherRecord) {
    setPhase('done')
    try {
      const d = await api.integrityOpen(key, toOpen, protect, sealTag)
      setOpenResult(d.ok ? d : null)
      if (!d.ok) setError(_t('Backend injoignable. Lance le serveur Python.'))
    } catch {
      setOpenResult(null)
      setError(_t('Backend injoignable. Lance le serveur Python.'))
    }
  }

  async function send() {
    // memes garde-fous que dans les autres pages : un champ vide affiche un message clair
    if (protect && !key.trim()) { setError(_t('Indique la clé secrète partagée.')); return }
    if (!original.trim()) { setError(_t('Écris le message de A.')); return }
    setError(null)
    resetScene()
    intercepted.current = false
    try {
      // A signe le clair, PUIS chiffre (si l'option est activee) avec un algo + une cle tires au hasard
      const sealed = await api.integritySeal(key, original, encrypt)
      if (!sealed.ok) { setError(_t('Backend injoignable. Lance le serveur Python.')); return }
      setRecord(sealed.record)
      setSealTag(sealed.tag)
      recordRef.current = sealed.record
      setPhase('leg1')
      runLeg(dotsAlong(A, B, 'green'), () => {
        if (!intercepted.current) finish(sealed.record)   // arrive intact
      })
    } catch {
      setError(_t('Backend injoignable. Lance le serveur Python.'))
    }
  }

  function alterer() {
    if (phaseRef.current !== 'leg1') return
    intercepted.current = true
    clearTimer()
    setBase([])                                     // on abandonne la fin du trajet A→B
    const from = lastDot.current
    setPhase('toC')
    // le chiffre est tire vers C, puis on ATTEND : C ecrit ce qu'il veut avant de renvoyer
    runLeg(dotsAlong(from, C, 'green'), () => setPhase('atC'))
  }

  // C a reecrit le chiffre et le transmet a B (segment rouge C→B).
  function sendFromC() {
    if (phaseRef.current !== 'atC') return
    if (!tamperRef.current.trim()) { setError(_t('C doit écrire un chiffré à envoyer à B.')); return }
    if (!recordRef.current) return
    setError(null)
    setPhase('legCB')
    const toOpen: CipherRecord = { ...recordRef.current, secret: tamperRef.current }
    runLeg(dotsAlong(C, B, 'red'), () => finish(toOpen))
  }

  const sending = phase === 'leg1' || phase === 'toC' || phase === 'atC' || phase === 'legCB'
  const showC = intercepted.current && phase !== 'idle'
  const done = phase === 'done' && openResult

  const caption =
    t(phase === 'idle' ? 'A va envoyer son message chiffré et signé à B sur le canal.'
      : phase === 'leg1' ? 'Le chiffré circule sur le canal…'
      : phase === 'toC' ? 'C intercepte le chiffré !'
      : phase === 'atC' ? 'C tient le chiffré — modifie-le dans la carte C, puis « Envoyer à B ».'
      : phase === 'legCB' ? 'Le chiffré modifié repart vers B…'
      : !done ? '⚠ B n’a pas pu ouvrir le canal.'
      : openResult!.broken ? '⚠ B ne peut pas déchiffrer ce qu’il a reçu : le chiffré est devenu invalide.'
      : !protect ? '✓ B affiche ce qu’il a déchiffré comme « bien reçu » — sans AUCUNE vérification.'
      : openResult!.valid ? '✓ Arrivé intact : les étiquettes correspondent.'
      : '✗ B détecte l’altération : les étiquettes diffèrent.')

  // couleur d'un noeud
  const nodeColor = (who: 'A' | 'B' | 'C') =>
    who === 'A' ? 'var(--ua)' : who === 'B' ? 'var(--ub)' : 'var(--red)'

  return (
    <div className="panel">
      <h2 className="panel-title">{t('Intégrité du message (HMAC-SHA256)')}</h2>
      <div className="intg-fields">
        <div className="field">
          <span className="field-label">{t('Message de A')}</span>
          <textarea className="text-area" rows={2} value={original} placeholder={t(EX_MSG)}
            onChange={(e) => setOriginal(e.target.value)} />
        </div>
        {protect && (
          <div className="field">
            <span className="field-label">{t('Clé secrète partagée (A et B)')}</span>
            <input className="text-input" value={key} placeholder={t(EX_KEY)} autoComplete="off"
              onChange={(e) => setKey(e.target.value)} />
          </div>
        )}
      </div>

      <div className="intg-toggles">
        <button className={'pw-protect-btn' + (encrypt ? ' is-on' : '')} aria-pressed={encrypt}
          onClick={() => setEncrypt((v) => !v)} disabled={phase !== 'idle'}
          title={phase !== 'idle'
            ? t('Réinitialise la simulation pour changer cette option.')
            : t('Désactivée, le message voyage EN CLAIR : seule l’étiquette HMAC (si elle est activée) protège son intégrité, indépendamment de tout chiffrement.')}>
          <span className="pw-switch-dot" />{encrypt ? t('Chiffrement activé') : t('Activer le chiffrement')}
        </button>
        <button className={'pw-protect-btn' + (protect ? ' is-on' : '')} aria-pressed={protect}
          onClick={() => setProtect((v) => !v)} disabled={phase !== 'idle'}
          title={phase !== 'idle'
            ? t('Réinitialise la simulation pour changer cette option.')
            : t('B recalcule l’étiquette sur ce qu’il a déchiffré et la compare à celle de A. Désactivée, B affiche le message sans aucune vérification.')}>
          <span className="pw-switch-dot" />{protect ? t('Protection HMAC activée') : t('Activer la protection HMAC')}
        </button>
        {record && record.method && (
          <button className="btn" onClick={() => setRevealed((v) => !v)}>
            {revealed ? t('Cacher l’algo et la clé tirés au hasard') : t('Voir l’algo et la clé tirés au hasard')}
          </button>
        )}
      </div>

      {/* ---------------- scene animee du canal ---------------- */}
      <div className="intg-scene">
        <svg viewBox={`0 0 ${VB.w} ${VB.h}`} className="intg-svg" role="img"
          aria-label={t('Canal entre A et B, avec interception possible par C')}>
          {/* points a venir (faibles, couleur de l'interface) */}
          {base.map((d, i) => (
            <circle key={'b' + i} cx={d.x} cy={d.y} r={3} className="intg-dot intg-dot-base" />
          ))}
          {/* points allumes (vert = en route, rouge = apres C) */}
          {lit.map((d, i) => (
            <circle key={'l' + i} cx={d.x} cy={d.y} r={3.4}
              className={'intg-dot ' + (d.color === 'green' ? 'intg-dot-ok' : 'intg-dot-bad')
                + (i === lit.length - 1 && sending ? ' is-head' : '')} />
          ))}

          {/* noeud A */}
          <g className="intg-node">
            <circle cx={A.x} cy={A.y} r={18} style={{ stroke: nodeColor('A') }} />
            <text x={A.x} y={A.y + 5} className="intg-node-letter" style={{ fill: nodeColor('A') }}>A</text>
          </g>
          {/* noeud B */}
          <g className="intg-node">
            <circle cx={B.x} cy={B.y} r={18} style={{ stroke: nodeColor('B') }} />
            <text x={B.x} y={B.y + 5} className="intg-node-letter" style={{ fill: nodeColor('B') }}>B</text>
          </g>
          {/* noeud C (attaquant), visible seulement apres interception */}
          <g className={'intg-node intg-node-c' + (showC ? ' is-on' : '')}>
            <circle cx={C.x} cy={C.y} r={18} style={{ stroke: nodeColor('C') }} />
            <text x={C.x} y={C.y + 5} className="intg-node-letter" style={{ fill: nodeColor('C') }}>C</text>
          </g>
        </svg>

        <div className={'intg-caption' + (phase === 'done'
          ? (!done || openResult!.broken ? ' is-bad' : !protect ? ' is-ok' : openResult!.valid ? ' is-ok' : ' is-bad')
          : '')}>
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

      {/* ---------------- cartes : message + etiquettes ---------------- */}
      <div className="intg-cards">
        <div className="party" style={{ borderColor: 'color-mix(in srgb, var(--ua) 45%, var(--border))' }}>
          <div className="party-head" style={{ color: 'var(--ua)' }}>{t('Utilisateur A (expéditeur)')}</div>
          <div className="intg-msg">{original || <span className="intg-pending">—</span>}</div>
          {record && record.method && (
            <div className="tag-box">
              <span className="tag-label">
                {t('Chiffré envoyé')} {revealed && `(${algoName(record.method)} · ${t(keyText(asParams(record)!))})`}
              </span>
              <code className="tag-hex">{record.secret}</code>
            </div>
          )}
          {record && !record.method && (
            <div className="intg-note">{t('Chiffrement désactivé : le message voyage en clair.')}</div>
          )}
          {protect && (
            <div className="tag-box">
              <span className="tag-label">{t('Étiquette HMAC envoyée (sur le clair)')}</span>
              <code className="tag-hex">{tagA}</code>
            </div>
          )}
        </div>

        {showC && (
          <div className="party intg-card-c">
            <div className="party-head" style={{ color: 'var(--red)' }}>{t('Attaquant')}</div>
            <span className="tag-label">
              {recordRef.current?.method ? t('Chiffré intercepté — modifie-le') : t('Message intercepté — modifie-le')}
            </span>
            <textarea ref={cRef} className="text-area" rows={2} value={tampered}
              disabled={phase !== 'atC'}
              onChange={(e) => setTampered(e.target.value)} />
            {phase === 'atC' && (
              <button className="btn btn-accent intg-sendc" onClick={sendFromC}>{t('Envoyer à B ↓')}</button>
            )}
            <span className="intg-note">{t('C n’a pas la clé HMAC : même en modifiant ce qu’il intercepte, il ne peut pas produire une étiquette valide.')}</span>
          </div>
        )}

        <div className="party" style={{ borderColor: 'color-mix(in srgb, var(--ub) 45%, var(--border))' }}>
          <div className="party-head" style={{ color: 'var(--ub)' }}>{t('Utilisateur B (destinataire)')}</div>
          <div className="intg-msg">
            {!done
              ? <span className="intg-pending">{t('en attente…')}</span>
              : openResult!.broken
                ? <span className="intg-pending">{t('— déchiffrement impossible —')}</span>
                : openResult!.decrypted}
          </div>
          {protect ? (
            <div className="tag-box">
              <span className="tag-label">{t('Étiquette recalculée par B')}</span>
              <code className={'tag-hex' + (done && !openResult!.broken && !openResult!.valid ? ' bad' : '')}>
                {done && !openResult!.broken ? openResult!.recomputed : '…'}
              </code>
            </div>
          ) : (
            <div className="intg-note">{t('Protection désactivée : B ne vérifie rien, il affiche ce qu’il a déchiffré.')}</div>
          )}
        </div>
      </div>

      {phase === 'done' && (
        <div className={'verdict ' + (!done || openResult!.broken ? 'bad' : !protect ? 'ok' : openResult!.valid ? 'ok' : 'bad')}>
          {!done ? t('⚠ B n’a pas pu ouvrir le canal.')
            : openResult!.broken ? t('⚠ Le chiffré reçu est invalide : B ne peut même pas le déchiffrer.')
            : !protect ? t('✓ B affiche le message comme « bien reçu » — mais SANS AUCUNE vérification : si le chiffré avait été altéré, B ne l’aurait jamais su.')
            : openResult!.valid ? t('✓ Message intègre : les deux étiquettes sont identiques, le message n’a pas été modifié.')
            : t('✗ Message altéré : les étiquettes diffèrent, le message a été modifié en transit.')}
        </div>
      )}
    </div>
  )
}
