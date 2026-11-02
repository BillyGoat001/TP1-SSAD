import { useEffect, useRef, useState } from 'react'
import type {
  Algo, CipherRecord, ExchangeParams, IntegrityOpenResult,
  IntegrityHistoryEntry, IntegrityHistoryDraft, IntegrityResultKind,
} from '../../types'
import { api } from '../../api'
import { algoName, keyText, clip, NAME } from '../exchange/parts'
import { t, _t, num } from '../../i18n'
import HillMatrixInput from '../cipher/HillMatrixInput'
import IntegrityHistory, { charRate } from './IntegrityHistory'

// Partie 4 — Intégrité du message (HMAC-SHA256).
// A chiffre vraiment son message (César, Playfair ou Hill : au hasard par défaut, ou
// l'algorithme et la clé qu'il choisit) puis calcule l'étiquette HMAC de ce chiffré.
// Sur le canal voyage un PAQUET : le chiffré, l'algorithme, la clé et l'étiquette — tout est
// lisible par un attaquant C, qui peut l'intercepter et modifier le chiffré en route. Seule la
// clé HMAC ne voyage jamais. Avec la protection activée, B recalcule l'étiquette sur le chiffré
// reçu et la compare : toute altération la fait diverger. Sans protection, B affiche simplement
// ce qu'il a déchiffré comme « bien reçu », sans aucune vérification — la faille démontrée.

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

// (algo, clé) d'un CipherRecord CHIFFRÉ (method non nul), dans la forme
// attendue par keyText/algoName (les mêmes helpers que la page Échange).
function asParams(r: CipherRecord): ExchangeParams | null {
  if (r.method === 'caesar') return { algo: 'caesar', shift: r.key.shift, direction: 'right' }
  if (r.method === 'playfair') return { algo: 'playfair', key: r.key.key }
  if (r.method === 'hill') return { algo: 'hill', matrix: r.key.matrix }
  return null
}

// Un texte reçu, caractère par caractère : ceux qui diffèrent de ce qui a été envoyé sont
// surlignés (étiquette de B vs étiquette de A, chiffré reçu vs chiffré de A). Une lettre
// ajoutée en fin de texte est surlignée aussi ; une lettre retirée ne laisse rien à surligner.
function TagDiff({ sent, got }: { sent: string | null; got: string }) {
  if (!sent) return <>{got}</>
  return (
    <>
      {Array.from(got).map((ch, i) =>
        ch === sent[i] ? ch : <span key={i} className="tag-diff">{ch}</span>)}
    </>
  )
}

// Combien de caractères C a changés dans le chiffré (position par position ; ajout et retrait comptent).
function msgChange(sent: string, got: string) {
  const total = Math.max(sent.length, got.length)
  let diff = Math.abs(sent.length - got.length)
  for (let i = 0; i < Math.min(sent.length, got.length); i++) if (sent[i] !== got[i]) diff++
  return { diff, total, rate: total ? (100 * diff) / total : 0 }
}

const ALGOS: Algo[] = ['caesar', 'playfair', 'hill']

// L'algorithme et la clé qui accompagnent le chiffré (ils voyagent avec lui, en clair).
function AlgoKey({ rec }: { rec: CipherRecord }) {
  if (!rec.method) return null   // message en clair : pas d'algorithme ni de clé à montrer
  return (
    <>
      <div className="intg-kv">
        <span className="tag-label">{t('Algorithme')}</span>
        <b className="intg-algo-name">{algoName(rec.method)}</b>
      </div>
      <div className="intg-kv">
        <span className="tag-label">{t('Clé')}</span>
        <code className="intg-kv-val">{t(keyText(asParams(rec)!))}</code>
      </div>
    </>
  )
}

// « À quel point l'étiquette de B a changé » : le chiffre clé de la page, avec sa jauge, mis en
// regard de la part du chiffré que C a modifiée (pour voir l'effet d'avalanche : l'étiquette
// change d'environ 94 % (de ses caractères) que C touche 1 caractère ou tous).
function TagChange({ r, sent, got, clear }: { r: IntegrityOpenResult; sent: string; got: string; clear: boolean }) {
  const rate = charRate(r.charsChanged, r.charsTotal, r.changeRate) ?? 0   // % des caractères de l'étiquette qui changent
  const same = r.bitsChanged === 0
  const msg = msgChange(sent, got)
  return (
    <div className={'intg-rate ' + (same ? 'is-ok' : 'is-bad')}>
      <div className="intg-rate-head">
        <span className="tag-label">{t('Taux de changement de l’étiquette')}</span>
        <span className="intg-rate-num">{num(rate, 1)} %</span>
      </div>
      <div className="intg-rate-bar" role="img"
        aria-label={t('{p} % de l’étiquette a changé', { p: num(rate, 1) })}>
        <span className="intg-rate-fill" style={{ width: `${rate}%` }} />
        <i className="intg-rate-mark" style={{ left: '93.75%' }} title={t('≈ 94 % : ce que donne n’importe quelle altération (15 chances sur 16 par caractère)')} />
      </div>
      <div className="intg-rate-detail">
        {t('{c} caractère(s) sur {ct} · {b} bits sur {bt} ({p} %)', {
          c: r.charsChanged ?? 0, ct: r.charsTotal ?? 64, b: r.bitsChanged ?? 0, bt: r.bitsTotal ?? 256, p: num(r.changeRate ?? 0, 1),
        })}
      </div>
      <div className="intg-rate-vs">
        <span>{clear ? t('Message modifié par C') : t('Chiffré modifié par C')} : <b>{num(msg.rate, 1)} %</b>
          {' '}({t('{c} caractère(s) sur {ct}', { c: msg.diff, ct: msg.total })})</span>
        <span>{t('Étiquette modifiée')} : <b>{num(rate, 1)} %</b></span>
      </div>
      <p className="intg-note">
        {same
          ? t('Aucun bit n’a changé : le message est arrivé intact.')
          : t('Que C modifie 1 caractère ou tous, environ 94 % des caractères de l’étiquette changent (15 chances sur 16 par caractère, soit ≈ 50 % des bits) : c’est l’effet d’avalanche de SHA-256. Le taux ne grandit pas avec la taille de la modification, et c’est voulu : la moindre altération rend l’étiquette totalement différente, B ne peut pas s’y tromper.')}
      </p>
    </div>
  )
}

// Issue d'un envoi. Avec la protection, B compare les étiquettes (même un chiffré devenu
// illisible est détecté) ; sans elle, il affiche ce qu'il peut déchiffrer, ou échoue.
function kindOf(protect: boolean, d: IntegrityOpenResult): IntegrityResultKind {
  if (protect) return d.valid ? 'intact' : 'detected'
  return d.broken ? 'broken' : 'unchecked'
}

// Exemples affichés en gris dans les champs vides (comme « ex. 3 » dans les autres pages)
const EX_KEY = _t('ex. cle-partagee')
const EX_MSG = _t('ex. Virement de 100 DA vers le compte B')
const EMPTY_HILL = [['', ''], ['', '']]

export default function IntegrityPanel() {
  const [key, setKey] = useState('')
  const [original, setOriginal] = useState('')
  const [tampered, setTampered] = useState('')          // le CHIFFRÉ, tel que C le réécrit
  const [error, setError] = useState<string | null>(null)   // champ vide : message rouge, comme dans les autres pages
  const [protect, setProtect] = useState(false)
  const [encrypt, setEncrypt] = useState(false)            // false = le message voyage en clair

  // algorithme et clé de A : par défaut tirés au hasard à chaque envoi, ou choisis par A
  const [method, setMethod] = useState<'random' | Algo>('random')
  const [shiftTxt, setShiftTxt] = useState('')             // César (vide = clé tirée au hasard)
  const [pfKey, setPfKey] = useState('')                   // Playfair (vide = clé tirée au hasard)
  const [hillCells, setHillCells] = useState<string[][]>(EMPTY_HILL)   // Hill (vide = clé tirée au hasard)
  const [hillValid, setHillValid] = useState(false)

  const [phase, setPhase] = useState<Phase>('idle')
  const [lit, setLit] = useState<Dot[]>([])      // points déjà allumés (persistants)
  const [base, setBase] = useState<Dot[]>([])    // points à venir (faibles)
  const [record, setRecord] = useState<CipherRecord | null>(null)   // chiffrement réel de ce message (une fois envoyé)
  const [sealTag, setSealTag] = useState<string | null>(null)       // étiquette RÉELLEMENT envoyée avec ce record
  const [sealWarning, setSealWarning] = useState<string | null>(null)   // clé choisie par A jugée faible
  const [arrived, setArrived] = useState<string | null>(null)        // le chiffré tel que B l'a reçu
  const [openResult, setOpenResult] = useState<IntegrityOpenResult | null>(null)
  const [history, setHistory] = useState<IntegrityHistoryEntry[]>([])   // un envoi mené à son terme par ligne
  // aperçu en direct chez C : l'étiquette que B recalculerait pour le texte que C est en train d'écrire
  const [preview, setPreview] = useState<{ recomputed: string | null; changeRate: number | null } | null>(null)

  const localId = useRef(0)                                   // numéros négatifs : lignes non enregistrées côté backend

  const timer = useRef<number | undefined>(undefined)
  const phaseRef = useRef<Phase>('idle')
  const intercepted = useRef(false)
  const lastDot = useRef<Pt>(A)
  const tamperRef = useRef(tampered)
  const recordRef = useRef<CipherRecord | null>(null)
  const sealTagRef = useRef<string | null>(null)
  const cRef = useRef<HTMLTextAreaElement>(null)
  phaseRef.current = phase
  tamperRef.current = tampered
  recordRef.current = record
  sealTagRef.current = sealTag

  const clearTimer = () => {
    if (timer.current) window.clearInterval(timer.current)
    timer.current = undefined
  }

  // Changer la clé / le message / l'algorithme / la clé de chiffrement de A remet la scène à zéro.
  // (Modifier le chiffré réécrit par C ne réinitialise rien : on le tape pendant l'interception.)
  useEffect(() => {
    resetScene()
    setError(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, original, method, shiftTxt, pfKey, hillCells])

  useEffect(() => () => clearTimer(), [])

  // ---- historique (fichier côté backend ; si le backend ne répond pas, la ligne reste à l'écran) ----
  function reloadHistory() {
    api.integrityHistoryList().then((r) => { if (r.ok) setHistory(r.entries) }).catch(() => { /* garde l'écran */ })
  }
  useEffect(reloadHistory, [])

  async function saveRun(draft: IntegrityHistoryDraft) {
    let entry: IntegrityHistoryEntry
    try {
      const r = await api.integrityHistoryAdd(draft)
      entry = r.ok ? r.entry : { ...draft, id: -(++localId.current) }
    } catch {
      entry = { ...draft, id: -(++localId.current) }
    }
    setHistory((h) => [entry, ...h])
  }
  function removeRun(id: number) {
    setHistory((h) => h.filter((e) => e.id !== id))
    if (id > 0) api.integrityHistoryRemove(id).then((r) => { if (!r.ok) reloadHistory() }).catch(reloadHistory)
  }
  function clearHistory() {
    setHistory([])
    api.integrityHistoryClear().then((r) => { if (!r.ok) reloadHistory() }).catch(reloadHistory)
  }

  // Quand le message arrive chez C, on pré-remplit avec le VRAI chiffré intercepté
  // (C modifie ce qui transite réellement, pas un texte inventé) et on y met le curseur.
  useEffect(() => {
    if (phase === 'atC') {
      setTampered(recordRef.current?.secret ?? '')
      cRef.current?.focus()
    }
  }, [phase])

  // Aperçu en direct : à chaque lettre tapée par C, on demande au backend (qui détient la clé HMAC,
  // pas C) l'étiquette que B calculerait pour ce texte, et de combien elle s'écarte de celle de A.
  useEffect(() => {
    if (phase !== 'atC' || !protect || !record || !sealTag) { setPreview(null); return }
    let stale = false
    const h = window.setTimeout(() => {
      api.integrityOpen(key, { ...record, secret: tampered }, true, sealTag)
        .then((d) => { if (!stale && d.ok) setPreview({ recomputed: d.recomputed, changeRate: charRate(d.charsChanged, d.charsTotal, d.changeRate) }) })
        .catch(() => { if (!stale) setPreview(null) })
    }, 150)
    return () => { stale = true; window.clearTimeout(h) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tampered, phase])

  function resetScene() {
    clearTimer()
    intercepted.current = false
    lastDot.current = A
    setLit([])
    setBase([])
    setRecord(null)
    setSealTag(null)
    setSealWarning(null)
    setArrived(null)
    setOpenResult(null)
    setTampered('')
    setPreview(null)
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

  // `tag` est l'étiquette envoyée par A, passée explicitement : cette fonction peut être appelée
  // depuis une animation lancée avant que l'état `sealTag` ne soit à jour (valeur périmée).
  async function finish(toOpen: CipherRecord, tag: string | null) {
    setPhase('done')
    setArrived(toOpen.secret)
    try {
      const d = await api.integrityOpen(key, toOpen, protect, tag)
      setOpenResult(d.ok ? d : null)
      if (!d.ok) { setError(_t('Backend injoignable. Lance le serveur Python.')); return }
      const sent = recordRef.current ?? toOpen            // ce que A a réellement envoyé
      saveRun({
        message: original.slice(0, 5000), received: d.decrypted === null ? null : d.decrypted.slice(0, 5000),
        algo: sent.method, algoLabel: sent.method ? NAME[sent.method] : 'Aucun (en clair)',
        key: sent.method ? keyText(asParams(sent)!) : '',
        protect, altered: toOpen.secret !== sent.secret, result: kindOf(protect, d),
        changeRate: d.changeRate, bitsChanged: d.bitsChanged, bitsTotal: d.bitsTotal,
        charsChanged: d.charsChanged, charsTotal: d.charsTotal,
        tagSent: protect ? tag : null, tagRecomputed: d.recomputed,
      })
    } catch {
      setOpenResult(null)
      setError(_t('Backend injoignable. Lance le serveur Python.'))
    }
  }

  async function send() {
    // mêmes garde-fous que dans les autres pages : un champ vide affiche un message clair
    if (protect && !key.trim()) { setError(_t('Indique la clé secrète partagée.')); return }
    if (!original.trim()) { setError(_t('Écris le message de A.')); return }

    // la clé de chiffrement choisie par A (champ vide = tirée au hasard)
    let keyIn: { shift?: number; playfairKey?: string; matrix?: number[][] } | null = null
    if (encrypt && method === 'caesar' && shiftTxt !== '') keyIn = { shift: Number(shiftTxt) }
    if (encrypt && method === 'playfair' && pfKey.trim() !== '') keyIn = { playfairKey: pfKey }
    if (encrypt && method === 'hill' && !hillCells.every((r) => r.every((c) => c === ''))) {
      if (!hillValid) { setError(_t('Complète toute la matrice Hill (des nombres entiers) ou laisse-la vide.')); return }
      keyIn = { matrix: hillCells.map((r) => r.map((c) => parseInt(c, 10))) }
    }

    setError(null)
    resetScene()
    intercepted.current = false
    try {
      // A chiffre (si l'option est activée), puis signe le chiffré : l'algo est tiré au hasard sauf si A en impose un
      const sealed = await api.integritySeal(key, original, encrypt, encrypt && method !== 'random' ? method : null, keyIn)
      if (!sealed.ok) { setError(sealed.error ?? _t('Backend injoignable. Lance le serveur Python.')); return }
      setRecord(sealed.record)
      setSealTag(sealed.tag)
      setSealWarning(sealed.warning ?? null)
      sealTagRef.current = sealed.tag
      recordRef.current = sealed.record
      setPhase('leg1')
      runLeg(dotsAlong(A, B, 'green'), () => {
        if (!intercepted.current) finish(sealed.record, sealed.tag)   // arrivé intact
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
    // le paquet est tiré vers C, puis on ATTEND : C écrit ce qu'il veut avant de renvoyer
    runLeg(dotsAlong(from, C, 'green'), () => setPhase('atC'))
  }

  // C a réécrit le chiffré et le transmet à B (segment rouge C→B).
  function sendFromC() {
    if (phaseRef.current !== 'atC') return
    if (!tamperRef.current.trim()) { setError(_t('C doit écrire un chiffré à envoyer à B.')); return }
    if (!recordRef.current) return
    setError(null)
    setPhase('legCB')
    const toOpen: CipherRecord = { ...recordRef.current, secret: tamperRef.current }
    runLeg(dotsAlong(C, B, 'red'), () => finish(toOpen, sealTagRef.current))
  }

  const sending = phase === 'leg1' || phase === 'toC' || phase === 'atC' || phase === 'legCB'
  const showC = intercepted.current && phase !== 'idle'
  const done = phase === 'done' && openResult
  const kind = done ? kindOf(protect, openResult!) : null
  const bad = phase === 'done' && (!done || kind === 'broken' || kind === 'detected')
  const clear = !encrypt                                    // le « chiffré » est le message lui-même
  const cipherNow = phase === 'legCB' ? tampered : record?.secret ?? ''   // ce que le paquet transporte en ce moment

  const caption =
    t(phase === 'idle' ? 'A va envoyer son message chiffré et signé à B sur le canal.'
      : phase === 'leg1' ? (clear ? 'Le message circule sur le canal…' : 'Le paquet (chiffré, algorithme, clé, étiquette) circule sur le canal…')
      : phase === 'toC' ? (clear ? 'C intercepte le message !' : 'C intercepte tout le paquet : chiffré, algorithme, clé et étiquette !')
      : phase === 'atC' ? (clear ? 'C tient le message — réécris-le dans la carte C, puis « Envoyer à B ».'
                                 : 'C lit tout le paquet — modifie le chiffré dans la carte C, puis « Envoyer à B ».')
      : phase === 'legCB' ? (clear ? 'Le message modifié repart vers B…' : 'Le paquet, avec le chiffré modifié, repart vers B…')
      : !done ? '⚠ B n’a pas pu ouvrir le canal.'
      : kind === 'broken' ? '⚠ B ne peut pas déchiffrer ce qu’il a reçu : le chiffré est devenu invalide.'
      : kind === 'unchecked' ? '✓ B affiche ce qu’il a déchiffré comme « bien reçu » — sans AUCUNE vérification.'
      : kind === 'intact' ? '✓ Arrivé intact : les étiquettes correspondent.'
      : '✗ B détecte l’altération : les étiquettes diffèrent.')

  // couleur d'un nœud
  const nodeColor = (who: 'A' | 'B' | 'C') =>
    who === 'A' ? 'var(--ua)' : who === 'B' ? 'var(--ub)' : 'var(--red)'

  // position de l'enveloppe : en tête des points allumés (au départ, sur A)
  const head = lit.length ? lit[lit.length - 1] : A

  return (
    <>
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
            : t('B recalcule l’étiquette sur le chiffré qu’il a reçu et la compare à celle de A. Désactivée, B affiche le message sans aucune vérification.')}>
          <span className="pw-switch-dot" />{protect ? t('Protection HMAC activée') : t('Activer la protection HMAC')}
        </button>
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

          {/* le paquet (chiffré + algo + clé + étiquette) : une enveloppe en tête des points */}
          {sending && (
            <g className={'intg-env' + (phase === 'legCB' ? ' is-bad' : '')}
              transform={`translate(${head.x - 9} ${head.y - 34})`}>
              <rect width="18" height="13" rx="2" />
              <path d="M0.8 1.2 L9 7.6 L17.2 1.2" />
            </g>
          )}

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

        {/* ce que contient le paquet qui voyage (le chiffré devient rouge une fois modifié par C) */}
        {record && sending && (
          <div className="intg-chips" aria-label={t('Contenu du paquet qui voyage sur le canal')}>
            <span className={'intg-chip' + (cipherNow !== record.secret ? ' is-bad' : '')}>
              <i>{record.method ? t('chiffré') : t('en clair')}</i> <code>{clip(cipherNow, 24)}</code>
            </span>
            {record.method && <span className="intg-chip"><i>{t('algo')}</i> <b>{algoName(record.method)}</b></span>}
            {record.method && <span className="intg-chip"><i>{t('clé')}</i> <code>{clip(t(keyText(asParams(record)!)), 24)}</code></span>}
            {protect && sealTag && <span className="intg-chip"><i>{t('étiquette')}</i> <code>{sealTag.slice(0, 8)}…</code></span>}
          </div>
        )}

        <div className={'intg-caption' + (phase === 'done' ? (bad ? ' is-bad' : ' is-ok') : '')}>
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

          {/* l'algorithme et la clé de A : tirés au hasard par défaut, modifiables */}
          {encrypt && (
            <div className="intg-akey">
              <div className="field">
                <span className="field-label">{t('Algorithme')}</span>
                <div className="segmented intg-seg">
                  {(['random', ...ALGOS] as const).map((a) => (
                    <button key={a} type="button" className={'seg' + (method === a ? ' is-on' : '')}
                      disabled={sending} onClick={() => setMethod(a)}>
                      {a === 'random' ? t('Aléatoire') : algoName(a)}
                    </button>
                  ))}
                </div>
              </div>
              {method === 'random' ? (
                <div className="intg-note">{t('Par défaut, l’algorithme et la clé sont tirés au hasard à chaque envoi.')}</div>
              ) : (
                <div className="field">
                  <span className="field-label">{t('Clé')}</span>
                  {method === 'caesar' && (
                    <input className="text-input intg-keyin" type="text" inputMode="numeric" autoComplete="off"
                      maxLength={9} value={shiftTxt} disabled={sending} placeholder={t('décalage, ex. 3')}
                      onChange={(e) => setShiftTxt(e.target.value.replace(/\D/g, '').replace(/^0+(?=\d)/, ''))} />
                  )}
                  {method === 'playfair' && (
                    <input className="text-input intg-keyin" autoComplete="off" maxLength={40}
                      value={pfKey} disabled={sending} placeholder={t('lettres, ex. MONARCHY')}
                      onChange={(e) => setPfKey(e.target.value.replace(/[^a-zA-Z ]/g, '').toUpperCase())} />
                  )}
                  {method === 'hill' && (
                    <HillMatrixInput
                      matrix={[]} cells={hillCells} fit
                      onChange={(_nums, valid, cells) => { setHillValid(valid); setHillCells(cells) }}
                    />
                  )}
                  <span className="intg-note">{t('Laisse la clé vide pour qu’elle soit tirée au hasard.')}</span>
                </div>
              )}
            </div>
          )}

          {/* ce que A a réellement envoyé sur le canal */}
          {record && (
            <div className="intg-packet">
              <span className="tag-label intg-sent">{t('A envoie sur le canal')}</span>
              <div className="tag-box">
                <span className="tag-label">{record.method ? t('Message chiffré') : t('Message (en clair)')}</span>
                <code className="tag-hex">{record.secret}</code>
              </div>
              <AlgoKey rec={record} />
              {protect && sealTag && (
                <div className="tag-box">
                  <span className="tag-label">{record.method ? t('Étiquette HMAC (sur le chiffré)') : t('Étiquette HMAC (sur le message)')}</span>
                  <code className="tag-hex">{sealTag}</code>
                </div>
              )}
              {sealWarning && <div className="intg-note intg-warn">⚠ {t(sealWarning)}</div>}
            </div>
          )}
        </div>

        {showC && (
          <div className="party intg-card-c">
            <div className="party-head" style={{ color: 'var(--red)' }}>{t('Attaquant')}</div>
            <span className="tag-label">
              {record?.method ? t('Chiffré intercepté — modifie-le') : t('Message intercepté — modifie-le')}
            </span>
            <textarea ref={cRef} className="text-area" rows={2} value={tampered}
              disabled={phase !== 'atC'}
              onChange={(e) => setTampered(e.target.value)} />
            {phase === 'atC' && (
              <button className="btn btn-accent intg-sendc" onClick={sendFromC}>{t('Envoyer à B ↓')}</button>
            )}
            {record && <AlgoKey rec={record} />}
            {protect && sealTag && (
              <div className="tag-box">
                <span className="tag-label">{t('Étiquette interceptée')}</span>
                <code className="tag-hex">{sealTag}</code>
              </div>
            )}
            {protect && sealTag && phase === 'atC' && preview?.recomputed && (
              <div className="tag-box">
                <span className="tag-label">
                  {t('Étiquette que B recalculera pour ce texte')}
                  {preview.changeRate !== null && <b className="intg-live"> · {num(preview.changeRate, 1)} %</b>}
                </span>
                <code className={'tag-hex' + (preview.changeRate ? ' bad' : '')}>
                  <TagDiff sent={sealTag} got={preview.recomputed} />
                </code>
              </div>
            )}
            <span className="intg-note">
              {protect
                ? (record?.method
                  ? t('C voit tout ce qui voyage : le chiffré, l’algorithme, la clé et l’étiquette. Mais la clé HMAC ne voyage jamais : il ne peut pas fabriquer une étiquette valide pour son message modifié.')
                  : t('C voit tout ce qui voyage : le message et l’étiquette. Mais la clé HMAC ne voyage jamais : il ne peut pas fabriquer une étiquette valide pour son message modifié.'))
                : t('C voit tout ce qui voyage. Sans protection HMAC, il n’y a aucune étiquette : rien ne permettra à B de voir la modification.')}
            </span>
          </div>
        )}

        <div className="party" style={{ borderColor: 'color-mix(in srgb, var(--ub) 45%, var(--border))' }}>
          <div className="party-head" style={{ color: 'var(--ub)' }}>{t('Utilisateur B (destinataire)')}</div>
          {done && record && arrived !== null && (
            <>
              <div className="tag-box">
                <span className="tag-label">{record.method ? t('Chiffré reçu') : t('Message reçu')}</span>
                <code className="tag-hex"><TagDiff sent={record.secret} got={arrived} /></code>
              </div>
              <AlgoKey rec={record} />
            </>
          )}
          <span className="tag-label">{t('Message déchiffré par B')}</span>
          <div className="intg-msg">
            {!done
              ? <span className="intg-pending">{t('en attente…')}</span>
              : openResult!.decrypted === null
                ? <span className="intg-pending">{t('— déchiffrement impossible —')}</span>
                : openResult!.decrypted}
          </div>
          {protect ? (
            <>
              {done && sealTag && (
                <div className="tag-box">
                  <span className="tag-label">{t('Étiquette reçue (celle de A)')}</span>
                  <code className="tag-hex">{sealTag}</code>
                </div>
              )}
              <div className="tag-box">
                <span className="tag-label">{t('Étiquette recalculée par B')}</span>
                <code className={'tag-hex' + (done && !openResult!.valid ? ' bad' : '')}>
                  {done ? <TagDiff sent={sealTag} got={openResult!.recomputed ?? ''} /> : '…'}
                </code>
              </div>
            </>
          ) : (
            <div className="intg-note">{t('Protection désactivée : B ne vérifie rien, il affiche ce qu’il a déchiffré.')}</div>
          )}
        </div>
      </div>

      {done && protect && openResult!.changeRate !== null && record && arrived !== null &&
        <TagChange r={openResult!} sent={record.secret} got={arrived} clear={clear} />}

      {phase === 'done' && (
        <div className={'verdict ' + (bad ? 'bad' : 'ok')}>
          {!done ? t('⚠ B n’a pas pu ouvrir le canal.')
            : kind === 'broken' ? t('⚠ Le chiffré reçu est invalide : B ne peut même pas le déchiffrer.')
            : kind === 'unchecked' ? t('✓ B affiche le message comme « bien reçu » — mais SANS AUCUNE vérification : si le chiffré avait été altéré, B ne l’aurait jamais su.')
            : kind === 'intact' ? t('✓ Message intègre : les deux étiquettes sont identiques, le message n’a pas été modifié.')
            : t('✗ Message altéré : les étiquettes diffèrent, le message a été modifié en transit.')
              + (openResult!.broken ? ' ' + t('B ne peut d’ailleurs même pas le déchiffrer.') : '')}
        </div>
      )}
    </div>

    {/* historique : une carte à part, hors du cadre « Intégrité » */}
    <IntegrityHistory entries={history} onRemove={removeRun} onClear={clearHistory} />
    </>
  )
}
