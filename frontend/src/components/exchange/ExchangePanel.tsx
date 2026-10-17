import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { flushSync } from 'react-dom'
import type { Algo, CipherResponse, ExchangeParams, OpenResponse, RsaKey, SealResponse } from '../../types'
import { api, type CipherInput } from '../../api'
import HillMatrixInput from '../cipher/HillMatrixInput'
import { Fx } from './fx'
import {
  type U, type BoxView, OTHER, UP, NAME, keyText, keyShort, short, clip,
  KeyField, TraceView, Letters, UserIcon, Arrow, EyeOpen, EyeOff,
} from './parts'
import Chat, { type ChatMsg } from './Chat'

// Partie 2 — Échange entre deux personnes.
// Chaque utilisateur a une vraie paire de clés RSA (générée par le backend
// Python). Pour envoyer, l'expéditeur chiffre son message avec César, Playfair
// ou Hill, puis enferme l'algo, la clé et le chiffré dans la boîte publique du
// destinataire (RSA). Seul le destinataire l'ouvre, avec sa clé privée : il
// relit l'algo et la clé SORTIS DU COFFRE, et déchiffre avec eux.
// Pour générer de nouvelles clés, il suffit de rafraîchir la page.

const SIZES = [32, 64, 128, 512, 1024, 2048]
const ALGOS: Algo[] = ['caesar', 'playfair', 'hill']
const BACKEND_DOWN = 'Backend injoignable. Lance le serveur Python.'
const EMPTY_2X2 = [['', ''], ['', '']]
// Toute l'animation (coffre, clé, boîte) est ralentie d'autant : 1 = vitesse d'origine.
const SLOW = 1.25

interface Pending { params: ExchangeParams; cipher: string; plain: string }
interface UserState {
  algo: Algo
  shift: string               // César : uniquement des chiffres, vide au départ
  direction: 'right' | 'left'
  pfKey: string               // Playfair : vide au départ
  hillCells: string[][]       // Hill : cases vides au départ
  matrixValid: boolean
  clear: string
  enc: string                 // 2 · chiffré à envoyer
  pending: Pending | null     // ce qui partira au clic sur Envoyer
  warning: string | null
  error: string | null
  recv: string                // 4 · reçu (chiffré)
  ralgo: string               // algo relu dans le coffre
  rkey: string                // clé relue dans le coffre
  dec: string                 // 3 · reçu (déchiffré)
  box: BoxView | null         // démonstration affichée dans la boîte floutée
  boxN: number
  boxFrom: U                  // couleur de la boîte : l'auteur du message traité
  blurred: boolean
  feeding: boolean            // le brouillard remue
  feed: { n: number; text: string; step: number } | null      // lettres qui tombent dans la boîte
  emerge: { n: number; text: string; step: number; label: string; cipher: boolean } | null // résultat qui se condense
}

const initUser = (u: U): UserState => ({
  algo: u === 'a' ? 'caesar' : 'playfair',
  shift: '', direction: 'right', pfKey: '', hillCells: EMPTY_2X2, matrixValid: false,
  clear: u === 'a' ? 'BONJOUR' : 'COUCOU',
  enc: '', pending: null, warning: null, error: null,
  recv: '', ralgo: '', rkey: '', dec: '',
  box: null, boxN: 0, boxFrom: u, blurred: true, feeding: false, feed: null, emerge: null,
})

function paramsOf(s: UserState): ExchangeParams {
  if (s.algo === 'caesar') return { algo: 'caesar', shift: s.shift, direction: s.direction }
  if (s.algo === 'playfair') return { algo: 'playfair', key: s.pfKey }
  return { algo: 'hill', matrix: s.hillCells }
}
function cipherInput(p: ExchangeParams, operation: 'encrypt' | 'decrypt', message: string): CipherInput {
  return { algo: p.algo, operation, message, shift: p.shift, direction: p.direction, key: p.key, matrix: p.matrix }
}
const cleanMessage = (v: string) => v.normalize('NFD').replace(/[̀-ͯ]/g, '').toUpperCase()
const si = (i: number) => ({ '--i': i }) as CSSProperties // rang dans l'apparition en cascade

export default function ExchangePanel({ active }: { active: boolean }) {
  const [bits, setBits] = useState(1024)
  const [keys, setKeys] = useState<Record<U, RsaKey | null>>({ a: null, b: null })
  const [exchanged, setExchanged] = useState(false)
  const [started, setStarted] = useState(false)
  const [keysShown, setKeysShown] = useState(false)
  const [revealed, setRevealed] = useState(false)
  const [revealDone, setRevealDone] = useState(false)
  const [users, setUsers] = useState<Record<U, UserState>>(() => ({ a: initUser('a'), b: initUser('b') }))
  const [hid, setHid] = useState<Record<string, boolean>>({})
  const [busy, setBusyState] = useState(false)
  const [genError, setGenError] = useState<string | null>(null)
  const [lastSent, setLastSent] = useState<{ from: U; blocks: string[]; cipher: string } | null>(null)
  const [chat, setChat] = useState<ChatMsg[]>([])
  const [cipherView, setCipherView] = useState(false)
  const [protoOpen, setProtoOpen] = useState(false) // « Protocole RSA » : replié par défaut

  // Les animations sont asynchrones : elles lisent l'état le plus récent via ces refs.
  const usersRef = useRef(users)
  usersRef.current = users
  const keysRef = useRef(keys)
  keysRef.current = keys
  const revealedRef = useRef(revealed)
  revealedRef.current = revealed
  const busyRef = useRef(false)
  const startedRef = useRef(false)
  const token = useRef(0) // change à chaque interruption : les animations en cours s'arrêtent
  const stageRef = useRef<HTMLDivElement>(null)
  const fxRef = useRef<Fx | null>(null)
  const refs = useRef<Record<string, HTMLElement | null>>({})
  const regs = useRef<Record<string, (el: HTMLElement | null) => void>>({})
  const reg = (k: string) => (regs.current[k] ??= (node) => { refs.current[k] = node })
  const el = (k: string) => refs.current[k] as HTMLElement
  const fx = () => (fxRef.current ??= new Fx(stageRef.current!, () => SLOW))

  const upd = (u: U, patch: Partial<UserState>) =>
    setUsers((prev) => ({ ...prev, [u]: { ...prev[u], ...patch } }))
  const updNow = (u: U, patch: Partial<UserState>) => flushSync(() => upd(u, patch))
  const hideNow = (k: string, v: boolean) => flushSync(() => setHid((h) => ({ ...h, [k]: v })))
  const setBusy = (v: boolean) => {
    busyRef.current = v
    setBusyState(v)
  }

  // Tant que la messagerie est repliée, ses champs ne doivent pas recevoir le focus.
  useEffect(() => {
    for (const k of ['a-reveal', 'b-reveal', 'a-boxrev', 'b-boxrev']) refs.current[k]?.toggleAttribute('inert', !revealed)
  }, [revealed])

  // Le champ du message grandit avec le texte (un paragraphe entier tient dedans).
  useLayoutEffect(() => {
    for (const u of ['a', 'b'] as U[]) {
      const t = refs.current[`${u}-clear`] as HTMLTextAreaElement | null
      if (!t) continue
      t.style.height = 'auto'
      t.style.height = `${t.scrollHeight + 2}px`
    }
  }, [users.a.clear, users.b.clear, revealed])

  // Quitter la partie « Échange » au milieu d'une animation l'interrompt proprement.
  useEffect(() => {
    if (active || !busyRef.current) return
    if (!revealedRef.current) reset()
    else abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active])

  function abort() {
    token.current++
    fxRef.current?.clear()
    setHid({})
    const calm = { feeding: false, feed: null, emerge: null }
    setUsers((prev) => ({ a: { ...prev.a, ...calm }, b: { ...prev.b, ...calm } }))
    setBusy(false)
  }

  function reset() {
    token.current++
    fxRef.current?.clear()
    startedRef.current = false
    setBusy(false)
    setKeys({ a: null, b: null })
    setExchanged(false)
    setStarted(false)
    setKeysShown(false)
    setRevealed(false)
    setRevealDone(false)
    setUsers({ a: initUser('a'), b: initUser('b') })
    setHid({})
    setGenError(null)
    setLastSent(null)
    setChat([])
  }

  // ------------------------------------------- 1. génération + échange ----
  async function start() {
    if (busyRef.current || startedRef.current) return
    startedRef.current = true
    const my = token.current, ok = () => my === token.current
    setBusy(true)
    setStarted(true)
    setGenError(null)
    let ka: RsaKey, kb: RsaKey
    try {
      const [ra, rb] = await Promise.all([api.rsaKeygen(bits), api.rsaKeygen(bits)])
      if (!ra.ok || !ra.key || !rb.ok || !rb.key) throw new Error(ra.error || rb.error || 'Génération impossible.')
      ka = ra.key
      kb = rb.key
    } catch (e) {
      if (!ok()) return
      startedRef.current = false
      setStarted(false)
      setBusy(false)
      setGenError(e instanceof Error && !/fetch|network|JSON/i.test(e.message) ? e.message : BACKEND_DOWN)
      return
    }
    if (!ok()) return
    const F = fx()

    // les clés apparaissent dans leurs champs, publiques d'abord
    flushSync(() => {
      setKeys({ a: ka, b: kb })
      setKeysShown(true)
      setHid({ 'a-priv': true, 'b-priv': true })
    })
    await Promise.all([F.pop(el('a-pub')), F.pop(el('b-pub'))])
    if (!ok()) return
    hideNow('a-priv', false)
    hideNow('b-priv', false)
    await Promise.all([F.pop(el('a-priv')), F.pop(el('b-priv'))])
    if (!ok()) return
    await F.wait(700)
    if (!ok()) return

    // les clés publiques s'échangent : elles partent ensemble vers la carte opposée
    const pa = F.ctr(el('a-pub')), pb = F.ctr(el('b-pub'))
    const ca = F.clone(el('a-pub')), cb = F.clone(el('b-pub'))
    flushSync(() => setHid({ 'a-pub': true, 'b-pub': true }))
    await Promise.all([F.go(ca, pb, { arc: -46, ms: 1200 }), F.go(cb, pa, { arc: 46, ms: 1200 })])
    if (!ok()) return
    flushSync(() => {
      setExchanged(true)
      setHid({})
    })
    F.clear()
    await F.wait(400)
    if (!ok()) return

    // la messagerie apparaît
    setRevealed(true)
    window.setTimeout(() => ok() && setRevealDone(true), 1150)
    setBusy(false)
  }

  // ---------------------------------------- la boîte, comme avant ----
  // Même animation que la partie « Chiffrer un message » : les lettres tombent
  // une à une dans le brouillard, une onde le traverse, le brouillard remue, puis
  // le résultat se condense, dans la couleur de l'utilisateur (le vert reste dans la démonstration).
  // Renvoie la bande d'où le résultat repartira vers son champ.
  async function feedBox(u: U, author: U, view: BoxView, input: string, output: string, ok: () => boolean) {
    const F = fx()
    const n = usersRef.current[u].boxN + 1
    const inText = clip(input), outText = clip(output)
    updNow(u, {
      box: view, boxN: n, boxFrom: author, blurred: true, emerge: null,
      feeding: true, feed: { n, text: inText, step: Math.min(55, 1100 / Math.max(1, inText.length)) },
    })
    await F.wait(1150)
    if (!ok()) return null
    const step = Math.min(42, 900 / Math.max(1, outText.length))
    updNow(u, {
      emerge: { n, text: outText, step, label: view.op === 'encrypt' ? 'Message chiffré' : 'Message déchiffré', cipher: view.op === 'encrypt' },
    })
    await F.wait(350)
    if (!ok()) return null
    upd(u, { feeding: false, feed: null })
    await F.wait(600 + outText.length * step + 300)
    if (!ok()) return null
    return el(`${u}-emerge`)
  }

  // ----------------------------------------------------- 2. chiffrer ----
  function validate(s: UserState): string | null {
    if (!/[A-Z]/.test(s.clear)) return 'Écris un message (au moins une lettre).'
    if (s.algo === 'caesar' && !/^\d+$/.test(s.shift)) return 'Indique le décalage : un nombre entier positif.'
    if (s.algo === 'playfair' && !/[A-Z]/i.test(s.pfKey)) return 'Indique la clé Playfair : au moins une lettre.'
    if (s.algo === 'hill' && !s.matrixValid) return 'Remplis toutes les cases de la matrice avec des nombres entiers.'
    return null
  }

  async function doEncrypt(u: U) {
    if (busyRef.current) return
    const st = usersRef.current[u]
    const bad = validate(st)
    if (bad) {
      upd(u, { error: bad })
      return
    }
    const my = token.current, ok = () => my === token.current
    setBusy(true)
    upd(u, { error: null, warning: null })
    const params = paramsOf(st), text = st.clear
    let resp: CipherResponse
    try {
      resp = await api.cipher(cipherInput(params, 'encrypt', text))
    } catch {
      resp = { ok: false, error: BACKEND_DOWN }
    }
    if (!ok()) return
    if (!resp.ok || !resp.trace || resp.result == null) {
      upd(u, { error: resp.error ?? 'Chiffrement impossible.' })
      setBusy(false)
      return
    }
    const result = resp.result, trace = resp.trace
    upd(u, { warning: resp.warning ?? null })
    const F = fx()
    // la vue se cadre sur le champ du message et le haut de la boîte, puis le message part
    await F.look([el(`${u}-clear`), { el: el(`${u}-box`), h: 230 }])
    if (!ok()) return
    const tgt = F.topOf(el(`${u}-box`), 58)
    // le message quitte son champ et rejoint le haut de la boîte…
    const f1 = F.pill(clip(text, 48), u, false, F.ctr(el(`${u}-clear`)))
    await F.go(f1, tgt, { ms: 850 })
    if (!ok()) return
    f1.remove()
    // …où il se dissout dans le brouillard ; le chiffré s'y condense
    const strip = await feedBox(u, u, { op: 'encrypt', trace, original: text, params }, text, result, ok)
    if (!ok()) return
    if (!strip) {
      updNow(u, { enc: result, pending: { params, cipher: result, plain: text }, emerge: null })
      setBusy(false)
      return
    }
    // la vue remonte : on voit le champ « Chiffré à envoyer » en même temps que la bande qui en part
    await F.look([el(`${u}-enc`), strip])
    if (!ok()) return
    const f2 = F.pill(clip(result, 48), u, true, F.ctr(strip))
    updNow(u, { emerge: null })
    await F.go(f2, F.ctr(el(`${u}-enc`)), { ms: 850 })
    if (!ok()) return
    updNow(u, { enc: result, pending: { params, cipher: result, plain: text } })
    F.flash(el(`${u}-enc`))
    f2.remove()
    setBusy(false)
  }

  // ------------------------------------------------------ 3. envoyer ----
  async function doSend(u: U) {
    if (busyRef.current) return
    const st = usersRef.current[u], v = OTHER[u], kv = keysRef.current[v]
    if (!st.pending || !kv) return
    const p = st.pending
    const my = token.current, ok = () => my === token.current
    setBusy(true)
    upd(u, { error: null })

    // l'expéditeur enferme {algo, clé} avec la clé PUBLIQUE du destinataire (vrai RSA, en Python)
    let seal: SealResponse
    try {
      seal = await api.exchangeSeal(p.params, { n: kv.n, e: kv.e })
    } catch {
      seal = { ok: false, error: BACKEND_DOWN }
    }
    if (!ok()) return
    if (!seal.ok || !seal.blocks || seal.payload == null) {
      upd(u, { error: seal.error ?? 'Impossible de fermer le coffre.' })
      setBusy(false)
      return
    }
    const sealedBlocks = seal.blocks.map((b) => b.c)
    const F = fx(), mobile = window.matchMedia('(max-width: 640px)').matches
    // la vue se cadre sur la carte de l'expéditeur : de la boîte publique jusqu'au bouton Envoyer
    await F.look([el(`${u}-pubicon`), el(`${u}-send`)])
    if (!ok()) return

    // 1) la boîte publique du destinataire sort du champ « Clé publique » et s'ouvre par le haut
    const icon = el(`${u}-pubicon`), ic = F.ctr(icon)
    const ch = F.chest(v)
    const S = ch.offsetWidth
    F.setAt(ch, ic, 0, ic.w / S)
    hideNow(`${u}-pubicon`, true)
    await F.go(ch, { x: ic.x, y: ic.y - 34 }, { s1: 0.62, ms: 360, ease: 'cubic-bezier(.2,.8,.3,1.15)' })
    if (!ok()) return
    const rightU = mobile || u === 'a'
    const d1 = F.dock(el(`${u}-send`), el(`${u}-card`), S, rightU)
    await F.go(ch, d1, { s1: 1, arcX: rightU ? 34 : -34, ms: 650 })
    if (!ok()) return
    await F.lid(ch, true, d1.x > F.ctr(el(`${u}-send`)).x)
    if (!ok()) return

    // 2) l'algo utilisé, puis la clé, puis le message chiffré tombent dedans
    const algoBtn = el(`${u}-algo`).querySelector('.is-on') ?? el(`${u}-algo`)
    const ins: [string, Element, boolean][] = [
      [NAME[p.params.algo], algoBtn, false],
      [keyShort(p.params), el(`${u}-params`), false],
      [clip(p.cipher, 48), el(`${u}-enc`), true],
    ]
    await Promise.all(ins.map(([t, src, ci], i) => F.wait(i * 420).then(async () => {
      if (!ok()) return
      const f = F.pill(t, u, ci, F.ctr(src))
      await F.dropIn(f, ch)
      f.remove()
      F.thud(ch)
    })))
    if (!ok()) return
    await F.wait(120)
    if (!ok()) return
    await F.lid(ch, false)
    if (!ok()) return

    // 3) le coffre verrouillé traverse le canal (l'expéditeur garde la boîte publique : elle resservira)
    hideNow(`${u}-pubicon`, false)
    F.showIn(el(`${u}-pubicon`))
    setLastSent({ from: u, blocks: sealedBlocks, cipher: p.cipher })
    // le destinataire ouvre avec SA clé privée : le calcul part pendant le trajet
    const opening: Promise<OpenResponse> = api
      .exchangeOpen({ n: kv.n, d: kv.d }, sealedBlocks)
      .catch(() => ({ ok: false, error: BACKEND_DOWN }))
    // la vue se cadre sur les deux boutons « Envoyer » : on voit le coffre traverser
    await F.look([el(`${u}-send`), el(`${v}-send`)])
    if (!ok()) return
    const rightV = mobile || v === 'a'
    const d2 = F.dock(el(`${v}-send`), el(`${v}-card`), S, rightV)
    const vert = Math.abs(d2.y - d1.y) > Math.abs(d2.x - d1.x)
    await F.go(ch, d2, vert ? { arcX: 46, ms: 1100 } : { arc: -46, ms: 1050 })
    if (!ok()) return
    F.thud(ch)
    const opened = await opening
    if (!ok()) return
    if (!opened.ok || !opened.params) {
      F.clear()
      upd(v, { error: opened.error ?? 'Impossible d\'ouvrir le coffre.' })
      setBusy(false)
      return
    }
    const prm = opened.params
    // la vue remonte vers la clé privée du destinataire, avec la serrure dans le champ
    await F.look([el(`${v}-privicon`), el(`${v}-send`)])
    if (!ok()) return

    // 4) la clé privée du destinataire sort de son champ et entre dans la serrure
    const kicon = el(`${v}-privicon`), kc = F.ctr(kicon), h = F.hole(ch)
    const k = F.key(v)
    const KS = k.offsetWidth, KT = (KS * 10) / 24 // taille de la clé ; centre → pointe
    F.setAt(k, kc, -45, kc.w / KS)
    hideNow(`${v}-privicon`, true)
    await F.go(k, { x: kc.x, y: kc.y - 26 }, { s1: 1, ms: 320, ease: 'cubic-bezier(.2,.8,.3,1.15)' })
    if (!ok()) return
    await F.go(k, { x: h.x, y: h.y - KT - 14 }, { r1: 0, arc: -24, ms: 760 })
    if (!ok()) return
    await F.go(k, { x: h.x, y: h.y - KT + 3 }, { ms: 200, ease: 'ease-in' })
    if (!ok()) return
    await F.turnKey(k)
    if (!ok()) return
    F.glowHole(ch)
    // pendant que le couvercle s'ouvre, la vue s'élargit jusqu'aux champs où le contenu va sortir
    const cam = F.look([el(`${v}-privicon`), el(`${v}-send`), el(`${v}-rkey`)])
    await F.lid(ch, true, d2.x > F.ctr(el(`${v}-send`)).x)
    await cam
    if (!ok()) return
    // la clé retourne dans son champ pendant que le contenu sort
    const back = F.go(k, kc, { s1: kc.w / KS, r1: -45, arc: -24, ms: 700 }).then(() => {
      k.remove()
      if (ok()) {
        hideNow(`${v}-privicon`, false)
        F.showIn(el(`${v}-privicon`))
      }
    })

    // 5) le chiffré rejoint son champ ; l'algo et la clé RELUS dans le coffre se rangent juste en dessous
    const outs: [string, string, 'recv' | 'ralgo' | 'rkey', boolean][] = [
      [clip(p.cipher, 48), p.cipher, 'recv', true],
      [NAME[prm.algo], NAME[prm.algo], 'ralgo', false],
      [keyShort(prm), keyText(prm), 'rkey', false],
    ]
    await Promise.all([
      ...outs.map(([label, value, field, ci], i) => F.wait(i * 360).then(async () => {
        if (!ok()) return
        const f = await F.popOut(label, ch, u, ci, el(`${v}-${field}`))
        if (!ok()) return
        updNow(v, { [field]: value } as Partial<UserState>)
        F.flash(el(`${v}-${field}`))
        f.remove()
      })),
      back,
    ])
    if (!ok()) return
    await F.lid(ch, false)
    if (!ok()) return
    await F.go(ch, F.center(ch), { s1: 0.3, o1: 0, ms: 340, ease: 'ease-in' })
    if (!ok()) return
    ch.remove()

    // 6) le chiffré, l'algo et la clé rejoignent la boîte floutée ; le message déchiffré en ressort
    const decrypting: Promise<CipherResponse> = api
      .cipher(cipherInput(prm, 'decrypt', p.cipher))
      .catch(() => ({ ok: false, error: BACKEND_DOWN }))
    await F.look([el(`${v}-recv`), { el: el(`${v}-box`), h: 230 }])
    if (!ok()) return
    const tgt = F.topOf(el(`${v}-box`), 58)
    await Promise.all((['recv', 'ralgo', 'rkey'] as const).map((field, i) => F.wait(i * 90).then(async () => {
      if (!ok()) return
      const src = el(`${v}-${field}`)
      const main = field === 'recv' // le chiffré arrive entier, l'algo et la clé s'effacent dans la boîte
      const f = F.pill(field === 'rkey' ? keyShort(prm) : clip(src.textContent ?? '', 48), u, main, F.ctr(src))
      await F.go(f, tgt, main ? { ms: 760 } : { s1: 0.5, o1: 0, ms: 760 })
      f.remove()
    })))
    if (!ok()) return
    const dr = await decrypting
    if (!ok()) return
    if (!dr.ok || !dr.trace || dr.result == null) {
      upd(v, { error: dr.error ?? 'Déchiffrement impossible.' })
      setBusy(false)
      return
    }
    const plain = dr.result
    // déchiffrer : la boîte prend la couleur de l'autre utilisateur (l'auteur du message)
    const strip = await feedBox(v, u, { op: 'decrypt', trace: dr.trace, original: p.cipher, params: prm }, p.cipher, plain, ok)
    if (!ok()) return
    if (!strip) {
      updNow(v, { dec: plain, emerge: null })
      setBusy(false)
      return
    }
    await F.look([el(`${v}-dec`), strip])
    if (!ok()) return
    const f4 = F.pill(clip(plain, 48), u, false, F.ctr(strip))
    updNow(v, { emerge: null, error: null })
    await F.go(f4, F.ctr(el(`${v}-dec`)), { ms: 850 })
    if (!ok()) return
    updNow(v, { dec: plain })
    F.flash(el(`${v}-dec`))
    f4.remove()
    // le message rejoint la conversation
    setChat((c) => [...c, { id: Date.now(), from: u, plain: p.plain, cipher: p.cipher, params: p.params }])
    setBusy(false)
  }

  // ------------------------------------------------------------ rendu ----
  function renderCard(u: U) {
    const st = users[u], v = OTHER[u]
    const pubOwner: U = exchanged ? v : u
    const inval = { pending: null, enc: '' } // toute modification annule le chiffré prêt à partir
    const setAlgo = (a: Algo) => upd(u, { algo: a, ...inval, error: null, warning: null })
    return (
      <section className={`ex-card ex-from-${u}`} ref={reg(`${u}-card`)}>
        <h3 className="ex-card-title">
          <span className="ex-avatar"><UserIcon /></span>
          Utilisateur {UP(u)}
        </h3>
        <div className="ex-keys">
          <KeyField
            kind="pub" owner={pubOwner} k={keys[pubOwner]}
            hidden={!keysShown || !!hid[`${u}-pub`]} iconHidden={!!hid[`${u}-pubicon`]}
            fieldRef={reg(`${u}-pub`)} iconRef={reg(`${u}-pubicon`)}
          />
          <KeyField
            kind="priv" owner={u} k={keys[u]}
            hidden={!keysShown || !!hid[`${u}-priv`]} iconHidden={!!hid[`${u}-privicon`]}
            fieldRef={reg(`${u}-priv`)} iconRef={reg(`${u}-privicon`)}
          />
        </div>

        <div className={'ex-reveal' + (revealed ? ' is-open' : '') + (revealDone ? ' is-done' : '')} ref={reg(`${u}-reveal`)}>
          <div className="ex-reveal-inner">
            <div className="ex-msg ex-stagger">
              <div className="ex-msg-head" style={si(0)}>Messagerie de {UP(u)}</div>

              <fieldset className="ex-cfg" disabled={busy} style={si(1)}>
                <div className="segmented ex-algo" ref={reg(`${u}-algo`)}>
                  {ALGOS.map((a) => (
                    <button key={a} type="button" className={'seg' + (st.algo === a ? ' is-on' : '')} onClick={() => setAlgo(a)}>
                      {NAME[a]}
                    </button>
                  ))}
                </div>
                <div className="ex-params" ref={reg(`${u}-params`)}>
                  {st.algo === 'caesar' && (
                    <>
                      <label className="field">
                        <span className="field-label">Décalage</span>
                        {/* uniquement des chiffres ; le champ s'élargit avec le nombre, sans dépasser la carte */}
                        <input
                          className="text-input ex-tint ex-shift" type="text" inputMode="numeric" autoComplete="off"
                          placeholder="ex. 3" value={st.shift}
                          style={{ width: `calc(${Math.max(5, st.shift.length + 1)}ch + 24px)` }}
                          onChange={(e) => upd(u, { shift: e.target.value.replace(/\D/g, '').replace(/^0+(?=\d)/, ''), ...inval })}
                        />
                      </label>
                      <div className="field">
                        <span className="field-label">Direction</span>
                        <div className="segmented">
                          <button type="button" className={'seg' + (st.direction === 'right' ? ' is-on' : '')} onClick={() => upd(u, { direction: 'right', ...inval })}>Droite</button>
                          <button type="button" className={'seg' + (st.direction === 'left' ? ' is-on' : '')} onClick={() => upd(u, { direction: 'left', ...inval })}>Gauche</button>
                        </div>
                      </div>
                    </>
                  )}
                  {st.algo === 'playfair' && (
                    <label className="field grow">
                      <span className="field-label">Clé (lettres)</span>
                      <input
                        className="text-input ex-tint" value={st.pfKey} placeholder="ex. PLAYFAIR" autoComplete="off"
                        onChange={(e) => upd(u, { pfKey: e.target.value.replace(/[^a-zA-Z ]/g, '').toUpperCase(), ...inval })}
                      />
                    </label>
                  )}
                  {st.algo === 'hill' && (
                    <HillMatrixInput
                      key={u} matrix={[]} cells={st.hillCells} fit
                      onChange={(_, valid, cells) => upd(u, { hillCells: cells, matrixValid: valid, ...inval })}
                    />
                  )}
                </div>
                <div className="ex-mfield">
                  <span className="ex-mlabel">1 · Message clair (écrit par {UP(u)})</span>
                  <textarea
                    className="ex-minput ex-textarea" ref={reg(`${u}-clear`)} value={st.clear} rows={4} maxLength={2000}
                    spellCheck={false} autoComplete="off" placeholder="Écris ton message, une phrase ou un paragraphe…"
                    onChange={(e) => upd(u, { clear: cleanMessage(e.target.value), ...inval })}
                  />
                </div>
              </fieldset>

              {(st.error || st.warning) && (
                <div className={'warn' + (st.error ? ' error' : '')} style={si(2)}>{st.error ?? st.warning}</div>
              )}
              <button type="button" className="btn btn-accent ex-act" style={si(3)} onClick={() => doEncrypt(u)} disabled={busy}>
                Chiffrer ↓
              </button>
              <div className="ex-mfield" style={si(4)}>
                <span className="ex-mlabel">2 · Chiffré à envoyer</span>
                <span className="ex-val is-cipher" ref={reg(`${u}-enc`)}>{st.enc || '—'}</span>
              </div>
              {/* la flèche pointe vers le destinataire : B est à droite de A */}
              <button
                type="button" className="btn btn-accent ex-act ex-send" ref={reg(`${u}-send`)} style={si(5)}
                onClick={() => doSend(u)} disabled={busy || !st.pending}
              >
                {u === 'b' && <Arrow dir="left" />}
                Envoyer à {UP(v)}
                {u === 'a' && <Arrow dir="right" />}
              </button>
              <div className="ex-sep" style={si(6)} />
              <div className={`ex-mfield ex-from-${v}`} style={si(7)}>
                <span className="ex-mlabel">3 · Reçu de {UP(v)} (déchiffré)</span>
                <span className="ex-val" ref={reg(`${u}-dec`)}>{st.dec || '—'}</span>
              </div>
              <div className={`ex-mfield ex-from-${v}`} style={si(8)}>
                <span className="ex-mlabel">4 · Reçu de {UP(v)} (chiffré)</span>
                <span className="ex-val is-cipher" ref={reg(`${u}-recv`)}>{st.recv || '—'}</span>
              </div>
              <div className={`ex-meta ex-from-${v}`} style={si(9)}>
                <div className="ex-mfield">
                  <span className="ex-mlabel">Algo reçu</span>
                  <span className="ex-val" ref={reg(`${u}-ralgo`)}>{st.ralgo || '—'}</span>
                </div>
                <div className="ex-mfield">
                  <span className="ex-mlabel">Clé reçue</span>
                  <span className="ex-val" ref={reg(`${u}-rkey`)}>{st.rkey || '—'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    )
  }

  function renderBox(u: U) {
    const st = users[u]
    return (
      <div className={'ex-reveal' + (revealed ? ' is-open' : '') + (revealDone ? ' is-done' : '')} ref={reg(`${u}-boxrev`)}>
        <div className="ex-reveal-inner ex-stagger">
          <div
            className={`demo-box ex-box ex-from-${st.boxFrom}` + (st.blurred ? ' blurred' : '') + (st.feeding ? ' feeding' : '')}
            ref={reg(`${u}-box`)} style={si(10)}
          >
            <div className="ex-box-title">
              <span className={`ex-dot ex-from-${u}`} />
              {/* le titre suit l'opération en cours */}
              <span key={st.box?.op ?? 'idle'} className="ex-box-name">
                {st.box?.op === 'encrypt' ? 'Boîte de chiffrement' : st.box?.op === 'decrypt' ? 'Boîte de déchiffrement' : 'Boîte de chiffrement / déchiffrement'} de {UP(u)}
              </span>
            </div>
            <button
              type="button" className="blur-toggle" onClick={() => upd(u, { blurred: !st.blurred })}
              aria-label={st.blurred ? 'Déflouter' : 'Flouter'} title={st.blurred ? 'Déflouter' : 'Flouter'}
            >
              {st.blurred ? <EyeOpen /> : <EyeOff />}
            </button>

            {st.feed && (
              <>
                <Letters key={'d' + st.feed.n} className="msg-dissolve" text={st.feed.text} step={st.feed.step} />
                <div key={'r' + st.feed.n} className="fog-ripple" />
              </>
            )}
            {st.emerge && (
              <div className="ex-emerge" key={'e' + st.emerge.n}>
                <div className={'sortie' + (st.emerge.cipher ? ' is-cipher' : '')} ref={reg(`${u}-emerge`)}>
                  <span className="output-label">{st.emerge.label}</span>
                  <Letters className="result-text result-materialize" text={st.emerge.text} step={st.emerge.step} />
                </div>
              </div>
            )}

            <div className="demo-content">
              {st.box
                ? <TraceView key={st.boxN} view={st.box} />
                : <div className="ex-note">En attente : écris un message puis clique « Chiffrer ».</div>}
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="ex-panel">
      <div className="ex-scene" style={{ '--tm': SLOW } as CSSProperties}>
        <div className="ex-col">
          {renderCard('a')}
          {renderBox('a')}
        </div>

        <div className="ex-lane">
          {!keysShown ? (
            <div className="ex-gen">
              <label className="ex-size">
                <span>Clés RSA</span>
                <select value={bits} disabled={started} onChange={(e) => setBits(Number(e.target.value))}>
                  {SIZES.map((s) => (
                    <option key={s} value={s}>{s} bits</option>
                  ))}
                </select>
              </label>
              <button type="button" className="ex-genbtn" onClick={start} disabled={started}>
                {started ? 'Génération…' : 'Générer les clés'}
              </button>
              {genError && <span className="ex-gen-err">{genError}</span>}
            </div>
          ) : null}
        </div>

        <div className="ex-col">
          {renderCard('b')}
          {renderBox('b')}
        </div>

        <div className="ex-stage" ref={stageRef} />
      </div>

      <div className={'panel ex-proto' + (protoOpen ? ' is-open' : '')}>
        <h3 className="sub-title ex-proto-title">
          <button type="button" className="ex-proto-head" aria-expanded={protoOpen} aria-controls="ex-proto-body" onClick={() => setProtoOpen((o) => !o)}>
            Protocole RSA
            <svg className="ex-proto-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="m6 9 6 6 6-6" />
            </svg>
          </button>
        </h3>
        <div className="ex-proto-body" id="ex-proto-body">
          <div className="ex-proto-inner">
            <div className="ex-proto-content">
              <ol className="ex-steps">
                <li>
                  <b>Génération des clés</b>
                  Deux nombres premiers p et q (test de Miller-Rabin), n = p × q, φ(n) = (p − 1)(q − 1), e = 65537 et
                  d = e⁻¹ mod φ(n). Clé publique : (e, n). Clé privée : (d, n).
                </li>
                <li>
                  <b>Échange des clés publiques</b>
                  A et B s'envoient leurs clés publiques. Les clés privées ne quittent jamais leur propriétaire.
                </li>
                <li>
                  <b>Envoi</b>
                  L'expéditeur chiffre son message (César, Playfair ou Hill), puis enferme l'algo, la clé et le chiffré avec
                  la clé publique du destinataire : c = m<sup>e</sup> mod n.
                </li>
                <li>
                  <b>Réception</b>
                  Le destinataire ouvre le coffre avec sa clé privée (m = c<sup>d</sup> mod n), relit l'algo et la clé, puis
                  déchiffre le message.
                </li>
              </ol>
              <p className="ex-note">
                Tout est calculé par le backend Python (<code>rsa_crypto.py</code>). C'est le RSA « de manuel », sans
                remplissage : en pratique, on ajoute un remplissage aléatoire (OAEP) pour qu'un même message ne donne jamais
                le même chiffré. Pour générer de nouvelles clés, rafraîchis la page.
              </p>
              {lastSent && (
                <p className="ex-note">
                  Au dernier envoi, quelqu'un qui écoute le canal n'aurait vu passer qu'un coffre verrouillé
                  ({lastSent.blocks.length} bloc{lastSent.blocks.length > 1 ? 's' : ''}, c₁ = <code>{short(lastSent.blocks[0], 8)}</code>)
                  et le message chiffré « <code>{clip(lastSent.cipher, 60)}</code> ». Sans la clé privée de {UP(OTHER[lastSent.from])},
                  impossible de lire l'algo ou la clé.
                </p>
              )}
              {keys.a && keys.b && (
                <details className="ex-details">
                  <summary>Voir les clés complètes de A et B</summary>
                  <div className="ex-keyfull">
                    {(['a', 'b'] as U[]).map((u) => {
                      const k = keys[u]!
                      return (
                        <div key={u} className={`ex-keycard ex-from-${u}`}>
                          <div className="ex-sec-title">Utilisateur {UP(u)} · {k.bits} bits</div>
                          {(['p', 'q', 'n', 'phi', 'e', 'd'] as const).map((f) => (
                            <div key={f} className="ex-full">
                              <span className="ex-row-l">{f === 'phi' ? 'φ(n)' : f}</span>
                              <code>{k[f]}</code>
                            </div>
                          ))}
                        </div>
                      )
                    })}
                  </div>
                </details>
              )}
            </div>
          </div>
        </div>
      </div>

      <Chat msgs={chat} cipherView={cipherView} onToggle={() => setCipherView((c) => !c)} />
    </div>
  )
}
