import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import type { Algo, Operation, CipherResponse, Trace, HistoryEntry, HistoryDraft } from '../../types'
import { api, type CipherInput } from '../../api'
import { usePlayback } from './usePlayback'
import Playback from './Playback'
import CaesarViz from './CaesarViz'
import PlayfairViz from './PlayfairViz'
import HillViz from './HillViz'
import HillMatrixInput from './HillMatrixInput'
import History, { fmtTime } from './History'
import LimitsFlaws from './LimitsFlaws'
import { FilePicker, FileNotice, type FileNote } from './FilePick'
import { readTextFile, checkCaesarKey, checkPlayfairKey, checkHillKey, checkMessage } from './fileImport'
import { t, _t } from '../../i18n'

const ALGOS: { id: Algo; label: string }[] = [
  { id: 'caesar', label: _t('César') },
  { id: 'playfair', label: 'Playfair' },
  { id: 'hill', label: 'Hill' },
]

type Dir = 'right' | 'left'

// Tout ce qui definit « l'algorithme + la cle » d'une station.
interface Params {
  algo: Algo
  shift: string
  direction: Dir
  playfairKey: string
  matrix: string[][]
  matrixValid: boolean
}

// Metadonnees rangees a cote du chiffre (jamais dedans) pour restituer
// espaces / ponctuation (layout), X de bourrage (fillers), J (jmap) et minuscules (cases).
interface Meta {
  layout: [number, string][]
  fillers: number[]
  jmap: number[]
  cases: number[]
}

// Un chiffre produit dans la session : avec quelle cle, et ses metadonnees.
interface Entry {
  params: Params
  meta: Meta
}

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

// ---------------------------------------------------------------- helpers ----

// Saisie du message clair : accents retires, MAJUSCULES/minuscules gardees telles que tapees.
const stripAccents = (s: string) => s.normalize('NFD').replace(/[̀-ͯ]/g, '')
// Saisie d'un chiffre : toujours en majuscules.
const clean = (s: string) => stripAccents(s).toUpperCase()

const mod26 = (n: bigint) => ((n % 26n) + 26n) % 26n

// Identite « mathematique » d'une cle : deux cles differentes a l'ecran mais
// equivalentes (decalage 3 et 29, « MONARCHY » et « monarchy »…) donnent la meme.
function keyId(p: Params): string {
  try {
    if (p.algo === 'caesar') {
      const s = mod26(BigInt(p.shift || '0'))
      return 'c:' + (p.direction === 'right' ? s : mod26(-s))
    }
    if (p.algo === 'playfair') {
      const seen: string[] = []
      for (const ch of p.playfairKey.toUpperCase().replace(/J/g, 'I') + 'ABCDEFGHIKLMNOPQRSTUVWXYZ')
        if (/[A-Z]/.test(ch) && !seen.includes(ch)) seen.push(ch)
      return 'p:' + seen.join('')
    }
    return 'h:' + p.matrix.length + ':' + p.matrix.map((r) => r.map((v) => String(mod26(BigInt(v)))).join(',')).join(';')
  } catch {
    return 'x:' + JSON.stringify(p)
  }
}

// La cle en texte lisible, pour l'historique.
function keyLabel(p: Params): string {
  if (p.algo === 'caesar') return `${p.shift} (${p.direction === 'right' ? 'droite' : 'gauche'})`
  if (p.algo === 'playfair') return p.playfairKey.trim().toUpperCase()
  return '[' + p.matrix.map((r) => r.join(' ')).join(' ; ') + ']'
}

function validateParams(p: Params): string | null {
  if (p.algo === 'caesar' && !/^\d+$/.test(p.shift)) return 'Indique le décalage : un nombre entier positif.'
  if (p.algo === 'playfair' && !/[A-Z]/i.test(p.playfairKey)) return 'Indique la clé Playfair : au moins une lettre.'
  if (p.algo === 'hill' && !p.matrixValid) return 'Chaque case de la matrice doit contenir un nombre (positif ou négatif).'
  return null
}

function buildInput(p: Params, operation: Operation, message: string, meta?: Meta): CipherInput {
  const base: CipherInput =
    p.algo === 'caesar' ? { algo: p.algo, operation, message, shift: p.shift, direction: p.direction }
      : p.algo === 'playfair' ? { algo: p.algo, operation, message, key: p.playfairKey }
        : { algo: p.algo, operation, message, matrix: p.matrix }
  return meta ? { ...base, layout: meta.layout, fillers: meta.fillers, jmap: meta.jmap, cases: meta.cases } : base
}

// ------------------------------------------------------------------ hooks ----

// L'algorithme et la cle d'une station (les deux stations ont chacune la leur).
function useKeyParams() {
  const [algo, setAlgo] = useState<Algo>('caesar')
  // cles vides au depart : le champ affiche son exemple (« ex. 3 ») et la matrice ses points
  const [shift, setShift] = useState('')
  const [direction, setDirection] = useState<Dir>('right')
  const [playfairKey, setPlayfairKey] = useState('')
  // les cases restent en texte : un tres grand nombre garde tous ses chiffres jusqu'au backend
  const [matrix, setMatrix] = useState<string[][]>([['', ''], ['', '']])
  const [matrixValid, setMatrixValid] = useState(false)
  // HillMatrixInput ne lit ses cases qu'au montage : on le remonte quand on charge une matrice
  const [hillKey, setHillKey] = useState(0)

  const snapshot = (): Params => ({ algo, shift, direction, playfairKey, matrix, matrixValid })
  const load = (p: Params) => {
    setAlgo(p.algo); setShift(p.shift); setDirection(p.direction); setPlayfairKey(p.playfairKey)
    setMatrix(p.matrix); setMatrixValid(p.matrixValid); setHillKey((k) => k + 1)
  }
  return {
    algo, shift, direction, playfairKey, matrix, hillKey,
    setAlgo, setShift, setDirection, setPlayfairKey, setMatrix, setMatrixValid,
    snapshot, load,
  }
}
type KeyParams = ReturnType<typeof useKeyParams>

// Demonstration + resultat d'une station (animation, lecture pas a pas, flou).
function useDemo() {
  const [resp, setResp] = useState<CipherResponse | null>(null)
  const [revealed, setRevealed] = useState(false)
  const [feeding, setFeeding] = useState(false)       // dissolve + ripple en cours
  const [showResult, setShowResult] = useState(false) // resultat seulement quand il « sort »
  const [animKey, setAnimKey] = useState(0)
  const [input, setInput] = useState('')              // texte qui entre dans la demonstration
  const timers = useRef<number[]>([])

  const trace = resp && resp.ok ? resp.trace : undefined
  const total = trace ? trace.steps.length : 0
  const pb = usePlayback(total)
  const atEnd = pb.index >= total - 1
  // pendant l'animation : le resultat se construit lettre par lettre ; a la fin,
  // on affiche le resultat final du backend (dechiffrement = espaces retrouves)
  const liveOutput = trace ? runningOutput(trace, pb.index) : ''
  const output = atEnd && resp && resp.ok && resp.result != null ? resp.result : liveOutput

  const cancel = () => {
    timers.current.forEach((t) => window.clearTimeout(t))
    timers.current = []
  }
  const later = (fn: () => void, ms: number) => {
    timers.current.push(window.setTimeout(fn, ms))
  }
  useEffect(() => cancel, []) // eslint-disable-line react-hooks/exhaustive-deps

  const clear = () => {
    cancel()
    setResp(null); setRevealed(false); setFeeding(false); setShowResult(false)
  }
  const begin = (text: string) => {
    cancel()
    setInput(text); setRevealed(false); setShowResult(false); setFeeding(true)
    setAnimKey((k) => k + 1)
  }
  const fail = (error: string) => {
    cancel()
    setFeeding(false); setShowResult(false); setResp({ ok: false, error })
  }
  return {
    resp, setResp, revealed, setRevealed, feeding, setFeeding, showResult, setShowResult,
    animKey, input, trace, total, pb, atEnd, output, cancel, later, clear, begin, fail,
  }
}
type Demo = ReturnType<typeof useDemo>

// Flash vert d'un champ qui vient de recevoir un resultat, puis retour a la normale.
function useFlash(ms = 1700) {
  const [on, setOn] = useState(false)
  const t = useRef<number | null>(null)
  const fire = () => {
    setOn(true)
    if (t.current) window.clearTimeout(t.current)
    t.current = window.setTimeout(() => setOn(false), ms)
  }
  useEffect(() => () => { if (t.current) window.clearTimeout(t.current) }, [])
  return { on, fire }
}

// ------------------------------------------------------------- components ----

// Algorithme + cle : exactement les memes champs des deux cotes.
function KeyFields({ p, onEdit: onEditRaw }: { p: KeyParams; onEdit: () => void }) {
  // resultat du dernier fichier de cle choisi (ok ou refuse) ; il disparait des qu'on touche a la cle
  const [note, setNote] = useState<FileNote | null>(null)
  const onEdit = () => { setNote(null); onEditRaw() }
  useEffect(() => { setNote(null) }, [p.algo])

  // UN fichier : son contenu doit etre une cle valable pour l'algorithme choisi
  async function pickKeyFile(file: File) {
    const algo = p.algo
    const read = await readTextFile(file)
    if (!read.ok) return setNote({ ok: false, name: file.name, problem: read.problem })
    const base = p.snapshot()
    if (algo === 'caesar') {
      const r = checkCaesarKey(read.value)
      if (!r.ok) return setNote({ ok: false, name: file.name, problem: r.problem })
      p.load({ ...base, shift: r.value })
      setNote({ ok: true, name: file.name, info: r.info })
    } else if (algo === 'playfair') {
      const r = checkPlayfairKey(read.value)
      if (!r.ok) return setNote({ ok: false, name: file.name, problem: r.problem })
      p.load({ ...base, playfairKey: r.value })
      setNote({ ok: true, name: file.name, info: r.info })
    } else {
      const r = checkHillKey(read.value)
      if (!r.ok) return setNote({ ok: false, name: file.name, problem: r.problem })
      p.load({ ...base, matrix: r.value, matrixValid: true })
      setNote({ ok: true, name: file.name, info: r.info })
    }
    onEditRaw() // la cle a change : on remet la demonstration a zero
  }

  const keyName = p.algo === 'caesar' ? _t('clé César (un nombre positif)') : p.algo === 'playfair' ? _t('clé Playfair (des lettres)') : _t('clé Hill (une matrice)')

  return (
    <div className="cp-cfg">
      <div className="field">
        <span className="field-label">{t('Algorithme')}</span>
        <div className="segmented">
          {ALGOS.map((a) => (
            <button
              key={a.id} type="button" className={'seg' + (p.algo === a.id ? ' is-on' : '')}
              onClick={() => { if (p.algo !== a.id) { p.setAlgo(a.id); onEdit() } }}
            >
              {t(a.label)}
            </button>
          ))}
        </div>
      </div>

      {p.algo === 'caesar' && (
        <>
          <div className="field">
            <span className="field-label">{t('Direction')}</span>
            <div className="segmented">
              <button type="button" className={'seg' + (p.direction === 'right' ? ' is-on' : '')} onClick={() => { p.setDirection('right'); onEdit() }}>{t('Droite')}</button>
              <button type="button" className={'seg' + (p.direction === 'left' ? ' is-on' : '')} onClick={() => { p.setDirection('left'); onEdit() }}>{t('Gauche')}</button>
            </div>
          </div>
          <div className="field">
            <span className="field-label">{t('Décalage')}</span>
            {/* uniquement des chiffres ; le champ s'elargit avec le nombre, sans depasser la carte */}
            <input
              className="text-input" type="text" inputMode="numeric" autoComplete="off"
              placeholder={t('ex. 3')} value={p.shift}
              style={{ width: `calc(${Math.max(7, p.shift.length + 1)}ch + 24px)`, maxWidth: '100%', fontFamily: 'var(--mono)' }}
              onChange={(e) => {
                p.setShift(e.target.value.replace(/\D/g, '').replace(/^0+(?=\d)/, ''))
                onEdit()
              }}
            />
          </div>
        </>
      )}

      {p.algo === 'playfair' && (
        <div className="field grow">
          <span className="field-label">{t('Clé (lettres)')}</span>
          <input
            className="text-input" value={p.playfairKey}
            onChange={(e) => {
              p.setPlayfairKey(e.target.value.replace(/[^a-zA-Z ]/g, '').toUpperCase())
              onEdit()
            }}
            placeholder={t('ex. PLAYFAIR')}
          />
        </div>
      )}

      {p.algo === 'hill' && (
        <HillMatrixInput
          key={'h' + p.hillKey}
          matrix={[]}
          cells={p.matrix}
          fit
          onChange={(_nums, valid, cells) => {
            const changed = JSON.stringify(cells) !== JSON.stringify(p.matrix)
            p.setMatrix(cells)
            p.setMatrixValid(valid)
            if (changed) onEdit() // (a l'ouverture, la matrice reportee est identique : pas une modification)
          }}
        />
      )}

      <div className="field cp-file-field">
        <FilePicker
          label={_t('Clé depuis un fichier')}
          onFile={pickKeyFile}
        />
      </div>
      <FileNotice note={note} what={keyName} onClose={() => setNote(null)} />
    </div>
  )
}

interface StationProps {
  kind: 'enc' | 'dec'
  title: string
  p: KeyParams
  onEdit: () => void
  inputLabel: string
  inputPlaceholder?: string
  inputValue: string
  onInput: (v: string) => void
  inputFresh: boolean
  fileLabel: string
  actionLabel: string
  onAction: () => void
  demo: Demo
  outputLabel: string
  outputPlaceholder: string
  outputFresh: boolean
}

// Une station = le meme squelette des deux cotes, ligne par ligne :
// titre · algorithme+cle · champ d'entree · bouton · demonstration floutee · champ de sortie.
function Station({
  kind, title, p, onEdit, inputLabel, inputPlaceholder, inputValue, onInput, inputFresh, fileLabel,
  actionLabel, onAction, demo, outputLabel, outputPlaceholder, outputFresh,
}: StationProps) {
  const outRef = useRef<HTMLDivElement>(null)
  const [msgNote, setMsgNote] = useState<FileNote | null>(null)  // dernier fichier de message choisi
  const { resp, trace, showResult, revealed, feeding, pb, total, atEnd, output, animKey } = demo
  const hasOutput = !!trace && showResult

  // Glide the screen to the result as it emerges, so it is seen without scrolling.
  useEffect(() => {
    if (showResult) outRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [showResult])

  const copy = () => {
    if (output) navigator.clipboard?.writeText(output).catch(() => {})
  }

  // UN fichier : son contenu doit etre un message valable (texte, au moins une lettre A–Z)
  async function pickMessageFile(file: File) {
    const read = await readTextFile(file)
    if (!read.ok) return setMsgNote({ ok: false, name: file.name, problem: read.problem })
    const r = checkMessage(read.value, kind === 'enc')
    if (!r.ok) return setMsgNote({ ok: false, name: file.name, problem: r.problem })
    onInput(r.value)
    setMsgNote({ ok: true, name: file.name, info: r.info })
  }

  return (
    <section className={'cp-station is-' + kind} aria-label={t(title)}>
      <h3 className="cp-head">{kind === 'enc' ? '1' : '2'} · {t(title)}</h3>

      <KeyFields p={p} onEdit={onEdit} />

      <div className="field cp-input">
        <span className="field-label">{t(inputLabel)}</span>
        <textarea
          className={'text-area cp-io' + (inputFresh ? ' is-fresh' : '')}
          rows={2} value={inputValue} placeholder={inputPlaceholder && t(inputPlaceholder)}
          onChange={(e) => { setMsgNote(null); onInput(kind === 'enc' ? stripAccents(e.target.value) : clean(e.target.value)) }}
        />
        {/* icone « fichier » hors du champ, en bas a droite */}
        <div className="cp-file-row">
          <FilePicker label={fileLabel} onFile={pickMessageFile} />
        </div>
        <FileNotice note={msgNote} what={_t('message')} onClose={() => setMsgNote(null)} />
      </div>

      <div className="cp-act">
        <button className="btn btn-accent" onClick={onAction}>{t(actionLabel)}</button>
        {resp && !resp.ok && <div className="warn error" role="alert">⚠ {t(resp.error)}</div>}
        {resp && resp.ok && resp.warning && <div className="warn">⚠ {t(resp.warning)}</div>}
      </div>

      {trace ? (
        <div className={'demo-box cp-demo' + (revealed ? '' : ' blurred') + (feeding ? ' feeding' : '')}>
          <button
            className="blur-toggle"
            onClick={() => demo.setRevealed((r) => !r)}
            aria-label={revealed ? t('Flouter') : t('Déflouter')}
            title={revealed ? t('Flouter') : t('Déflouter')}
          >
            {revealed ? <EyeOff /> : <EyeOpen />}
          </button>

          {feeding && (
            <>
              <Letters key={'d' + animKey} className="msg-dissolve" text={(demo.input || ' ').toUpperCase()} />
              <div key={'r' + animKey} className="fog-ripple" />
            </>
          )}

          <div className="demo-content">
            {trace.kind === 'caesar' && <CaesarViz trace={trace} index={pb.index} showResult />}
            {trace.kind === 'playfair' && <PlayfairViz trace={trace} index={pb.index} original={demo.input} showResult />}
            {trace.kind === 'hill' && <HillViz trace={trace} index={pb.index} original={demo.input} showResult />}

            {revealed && (
              <>
                <Playback
                  playing={pb.playing} speed={pb.speed} setSpeed={pb.setSpeed}
                  play={pb.play} pause={pb.pause} step={pb.step} reset={pb.reset} atEnd={atEnd}
                />
                <div className="step-counter">{t('Étape {i} / {n}', { i: Math.max(0, pb.index + 1), n: total })}</div>
              </>
            )}
          </div>
        </div>
      ) : (
        <div className="demo-box cp-demo is-empty">{t('La démonstration pas à pas apparaîtra ici (floutée).')}</div>
      )}

      <div className="field cp-output">
        <div className="cp-label-row">
          <span className="field-label">{t(outputLabel)}</span>
          {hasOutput && resp && resp.ok && resp.time_us != null && (
            <span className="cp-time" title={t("Temps de calcul de l'algorithme (backend), hors animation et réseau")}>
              ⏱ {fmtTime(resp.time_us)}
            </span>
          )}
        </div>
        <div className={'cp-io cp-out' + (outputFresh ? ' is-fresh' : '')} ref={outRef}>
          {hasOutput
            ? <Letters key={'s' + animKey} className="result-text result-materialize" text={output || '—'} />
            : <span className="cp-placeholder">{t(outputPlaceholder)}</span>}
          <button className="btn tiny" onClick={copy} disabled={!hasOutput}>{t('Copier')}</button>
        </div>
      </div>
    </section>
  )
}

// ------------------------------------------------------------------ panel ----

export default function CipherPanel() {
  const [message, setMessage] = useState('BONJOUR')     // clair (station 1)
  const [cipherIn, setCipherIn] = useState('')          // chiffre recu (station 2)
  const left = useKeyParams()
  const right = useKeyParams()
  const enc = useDemo()
  const dec = useDemo()
  const stationsRef = useRef<HTMLDivElement>(null)
  const cipherFlash = useFlash()   // le chiffre arrive dans le champ de la station 2
  const encFlash = useFlash()      // le chiffre sort de la station 1
  const decFlash = useFlash()      // le clair sort de la station 2

  // Les champs de message (clair a gauche, chiffre a droite) grandissent avec le texte, comme dans
  // l'echange A↔B, et gardent TOUJOURS la meme hauteur des deux cotes pour que les stations restent alignees.
  useLayoutEffect(() => {
    const fit = () => {
      const tas = Array.from(stationsRef.current?.querySelectorAll<HTMLTextAreaElement>('.cp-input textarea') ?? [])
      tas.forEach((t) => { t.style.height = 'auto' })
      const h = Math.max(0, ...tas.map((t) => t.scrollHeight + 2))
      tas.forEach((t) => { t.style.height = `${h}px` })
    }
    fit()
    window.addEventListener('resize', fit)
    return () => window.removeEventListener('resize', fit)
  }, [message, cipherIn])

  // table des chiffres produits dans la session (cle = bloc chiffre, lettres seules) :
  // on y retrouve avec quel algo/cle il a ete fait + ses metadonnees (espaces, X, J).
  const memo = useRef<Map<string, Entry[]>>(new Map())

  // historique des operations reussies (la plus recente en premier), range dans un fichier du backend
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const localId = useRef(0) // numeros negatifs : lignes que le backend n'a pas pu enregistrer

  const reloadHistory = () =>
    api.historyList()
      .then((r) => { if (r.ok) setHistory(r.entries) })
      .catch(() => {})

  // au chargement : on retrouve l'historique deja enregistre
  useEffect(() => {
    let alive = true
    api.historyList()
      .then((r) => {
        if (!alive || !r.ok) return
        // (une ligne ajoutee entre-temps reste devant)
        setHistory((h) => {
          const known = new Set(h.map((e) => e.id))
          return [...h, ...r.entries.filter((e) => !known.has(e.id))]
        })
      })
      .catch(() => {})
    return () => { alive = false }
  }, [])

  const logOp = async (op: Operation, clear: string, cipher: string, p: Params, timeUs: number | null | undefined) => {
    const draft: HistoryDraft = {
      op, clear, cipher,
      algo: p.algo, algoLabel: ALGOS.find((a) => a.id === p.algo)!.label,
      key: keyLabel(p), timeUs: timeUs ?? null,
    }
    let entry: HistoryEntry
    try {
      const r = await api.historyAdd(draft)
      entry = r.ok ? r.entry : { ...draft, id: -(++localId.current) }
    } catch {
      entry = { ...draft, id: -(++localId.current) } // backend injoignable : la ligne reste visible, sans etre enregistree
    }
    setHistory((h) => [entry, ...h])
  }

  // supprime UNE ligne (a l'ecran tout de suite, puis dans le fichier)
  const removeOp = (id: number) => {
    setHistory((h) => h.filter((e) => e.id !== id))
    if (id > 0) api.historyRemove(id).then((r) => { if (!r.ok) reloadHistory() }).catch(reloadHistory)
  }
  const clearHistory = () => {
    setHistory([])
    api.historyClear().then((r) => { if (!r.ok) reloadHistory() }).catch(reloadHistory)
  }

  async function encrypt() {
    // memes garde-fous que l'echange : un champ vide affiche un message clair
    if (!/[A-Za-z]/.test(message)) return enc.fail('Écris un message (au moins une lettre).')
    const params = left.snapshot()
    const bad = validateParams(params)
    if (bad) return enc.fail(bad)

    const t0 = Date.now()
    enc.begin(message)
    let r: CipherResponse
    try {
      r = await api.cipher(buildInput(params, 'encrypt', message))
    } catch {
      return enc.fail('Backend injoignable. Lance le serveur Python.')
    }
    if (!r.ok || r.result == null) return enc.fail(r.error ?? 'Le chiffrement a échoué.')
    enc.setResp(r)

    // on retient, pour ce chiffre, de quoi le ramener exactement au clair
    const cipher = r.result
    const meta: Meta = { layout: r.layout ?? [], fillers: r.fillers ?? [], jmap: r.jmap ?? [], cases: r.cases ?? [] }
    const id = keyId(params)
    const others = (memo.current.get(cipher) ?? []).filter((e) => keyId(e.params) !== id)
    memo.current.set(cipher, [...others, { params, meta }])

    // le chiffre sort de la boite (1,15 s), puis « part » vers la station 2 :
    // meme algo + meme cle recopies (modifiables), flash vert, demonstration de droite remise a zero
    const wait = Math.max(0, 1150 - (Date.now() - t0))
    enc.later(() => {
      enc.setShowResult(true)
      encFlash.fire()
      logOp('encrypt', message, cipher, params, r.time_us)
      setCipherIn(cipher)
      right.load(params)
      dec.clear()
      cipherFlash.fire()
    }, wait)
    enc.later(() => enc.setFeeding(false), wait + 350)
  }

  async function decrypt() {
    const text = cipherIn
    const letters = text.replace(/[^A-Z]/g, '')
    if (!letters) return dec.fail("Il n'y a rien à déchiffrer : chiffre d'abord un message, ou colle un message chiffré.")
    const params = right.snapshot()
    const bad = validateParams(params)
    if (bad) return dec.fail(bad)

    // ce chiffre vient-il de cette session ? alors on sait avec quoi il a ete fait
    let meta: Meta | undefined
    const entries = memo.current.get(letters)
    if (entries) {
      const mine = keyId(params)
      const hit = entries.find((e) => keyId(e.params) === mine)
      if (!hit) {
        const made = entries[entries.length - 1].params
        return dec.fail(made.algo !== params.algo ? "Ce n'est pas le bon algorithme." : "Ce n'est pas la bonne clé.")
      }
      meta = hit.meta
    }
    // avec metadonnees : on dechiffre le bloc de lettres seul (les positions en dependent)
    const sent = meta ? letters : text

    const t0 = Date.now()
    dec.begin(sent)
    let r: CipherResponse
    try {
      r = await api.cipher(buildInput(params, 'decrypt', sent, meta))
    } catch {
      return dec.fail('Backend injoignable. Lance le serveur Python.')
    }
    if (!r.ok) return dec.fail(r.error ?? 'Le déchiffrement a échoué.')
    dec.setResp(r)

    const wait = Math.max(0, 1150 - (Date.now() - t0))
    dec.later(() => {
      dec.setShowResult(true); decFlash.fire()
      logOp('decrypt', r.result ?? '', sent, params, r.time_us)
    }, wait)
    dec.later(() => dec.setFeeding(false), wait + 350)
  }

  return (
    <div className="cp-page">
      <div className="panel">
        <h2 className="panel-title">{t('Chiffrement & déchiffrement')}</h2>

        <div className="cp-stations" ref={stationsRef}>
          <Station
            kind="enc" title="Chiffrer"
            p={left} onEdit={enc.clear}
            inputLabel="Message clair" inputValue={message} onInput={setMessage} inputFresh={false}
            fileLabel="Message depuis un fichier"
            actionLabel="Chiffrer ↓" onAction={encrypt}
            demo={enc}
            outputLabel="Message chiffré" outputPlaceholder="Le message chiffré apparaîtra ici." outputFresh={encFlash.on}
          />
          <Station
            kind="dec" title="Déchiffrer"
            p={right} onEdit={dec.clear}
            inputLabel="Message chiffré (reçu du chiffrement)"
            inputValue={cipherIn}
            onInput={(v) => { setCipherIn(v); dec.clear() }}
            inputFresh={cipherFlash.on}
            fileLabel="Chiffré depuis un fichier"
            actionLabel="Déchiffrer ↓" onAction={decrypt}
            demo={dec}
            outputLabel="Message déchiffré" outputPlaceholder="Le message déchiffré apparaîtra ici." outputFresh={decFlash.on}
          />
        </div>
      </div>

      <History entries={history} onRemove={removeOp} onClear={clearHistory} />
      <LimitsFlaws />
    </div>
  )
}
