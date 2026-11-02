import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { BruteResult, DictResult, CasesResponse, SpeedTable, Rules, Strength, PwHistoryEntry, PwHistoryDraft, PwResult, AttackSnapshot } from '../../types'
import { api } from '../../api'
import PwHistory from './PwHistory'
import { fmtDur, fmtTries } from './format'
import { t, _t, num, locale, plural, getLang } from '../../i18n'

// ---------------------------------------------------------------- constantes ----
const CASE_IDS = ['binaire', 'numerique', 'complexe'] as const
type CaseId = (typeof CASE_IDS)[number]
const CASE_LABEL: Record<CaseId, string> = { binaire: _t('Binaire'), numerique: _t('Numérique'), complexe: _t('Complexe') }
const FALLBACK_FULL =
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?/'
const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const DIGITS = '0123456789'
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?/'

const SCRAMBLE_MS = 55
const POLL_MS = 150                 // frequence de relecture de la progression REELLE cote serveur

const EMPTY_RULES: Rules = {
  require_lower: false, require_upper: false, require_digit: false, require_symbol: false, min_length: null,
}

// ---------------------------------------------------------------- helpers ----
const strengthClass = (s: Strength) => `is-${s}`
const WEAK: Strength[] = ['instant', 'faible', 'moyen']
const FAST_RATE_FALLBACK = 1e10     // repli le temps que /api/passwords/cases reponde
const YEAR_SECONDS = 31_536_000

// Port fidele de passwords.py human_time(seconds, compact=True) — memes seuils,
// memes mots, pour que la case « ta cible reelle » parle le meme langage que le
// reste du site (et que ce qui s'affichera apres une vraie attaque).
function humanTimeCompact(seconds: number): [string, Strength] {
  const s = seconds
  if (!isFinite(s)) return ['10^100+ ans', 'inviolable']
  if (s < 1e-3) return ['instantané', 'instant']
  if (s < 1) return ['< 1 s', 'instant']
  if (s < 60) return [`${Math.round(s)} s`, 'faible']
  if (s < 3600) return [`${Math.round(s / 60)} min`, 'faible']
  if (s < 86400) return [`${Math.round(s / 3600)} h`, 'moyen']
  if (s < 2_592_000) return [`${Math.round(s / 86400)} j`, 'moyen']
  if (s < YEAR_SECONDS) return [`${Math.round(s / 2_592_000)} mois`, 'moyen']
  const y = s / YEAR_SECONDS
  if (y < 100) { const n = Math.round(y); return [n === 1 ? '1 an' : `${n} ans`, 'fort'] }
  if (y < 1000) { const c = Math.round(y / 100); return [c === 1 ? '1 siècle' : `${c} siècles`, 'fort'] }
  if (y < 1_000_000) { const m = Math.round(y / 1000); return [m === 1 ? '1 millénaire' : `${m} millénaires`, 'inviolable'] }
  const k = Math.floor(Math.log10(y))
  return [`10^${k} ans`, 'inviolable']
}

function randStr(charset: string, len: number): string {
  let out = ''
  for (let i = 0; i < len; i++) out += charset[Math.floor(Math.random() * charset.length)]
  return out
}
// nombre affiche (1 234 en francais, 1,234 en anglais)
const fr = (n: number) => num(Math.round(n))
// nombre range dans l'historique : toujours en francais (traduit a l'affichage par t())
const frFR = (n: number) => Math.round(n).toLocaleString('fr-FR')
const dec = (p: number, d: number) => p.toLocaleString(locale(), { minimumFractionDigits: d, maximumFractionDigits: d })
function fmtPct(p: number): string {
  if (p <= 0) return '0'
  if (p >= 10) return Math.round(p).toString()
  if (p >= 0.1) return dec(p, 1)
  if (p >= 0.001) return dec(p, 3)
  return '< ' + dec(0.001, 3)
}

// n'autorise a la frappe que les caracteres du cas, et borne la longueur
function sanitize(v: string, caseId: CaseId, full: string): string {
  if (caseId === 'binaire') return v.replace(/[^01]/g, '').slice(0, 3)
  if (caseId === 'numerique') return v.replace(/[^1-4]/g, '').slice(0, 4)
  const allowed = new Set(full)
  return [...v].filter((c) => allowed.has(c)).join('').slice(0, 64)
}

// jeu de caracteres reellement present (cas complexe) — pour le scramble
function detectedCharset(target: string): string {
  let s = ''
  if (/[a-z]/.test(target)) s += LOWER
  if (/[A-Z]/.test(target)) s += UPPER
  if (/[0-9]/.test(target)) s += DIGITS
  if (/[^a-zA-Z0-9]/.test(target)) s += SYMBOLS
  return s
}

// libelle de composition pour la pastille (ce que l'attaque doit parcourir)
function composition(target: string, caseId: CaseId): string {
  if (caseId === 'binaire') return t('0 et 1')
  if (caseId === 'numerique') return t('chiffres 1 à 4')
  const parts: string[] = []
  if (/[a-z]/.test(target)) parts.push(t('minuscules'))
  if (/[A-Z]/.test(target)) parts.push(t('majuscules'))
  if (/[0-9]/.test(target)) parts.push(t('chiffres'))
  if (/[^a-zA-Z0-9]/.test(target)) parts.push(t('symboles'))
  if (parts.length === 0) return '—'
  if (parts.length === 1) return t('{x} uniquement', { x: parts[0] })
  return parts.join(', ')
}

// index de la colonne du tableau dont la taille d'alphabet est la plus proche
function colForSize(size: number, sizes: number[]): number {
  let best = sizes.length - 1
  let bd = Infinity
  sizes.forEach((s, i) => { const d = Math.abs(s - size); if (d < bd) { bd = d; best = i } })
  return best
}

// genere un mot de passe conforme (cas + politique active)
function generate(caseId: CaseId, len: number, full: string, rules: Rules | null): string {
  if (caseId === 'binaire') return randStr('01', 3)
  if (caseId === 'numerique') return randStr('1234', 4)
  let L = Math.max(1, len)
  const pools: string[] = []
  if (rules?.require_lower) pools.push(LOWER)
  if (rules?.require_upper) pools.push(UPPER)
  if (rules?.require_digit) pools.push(DIGITS)
  if (rules?.require_symbol) pools.push(SYMBOLS)
  if (rules?.min_length) L = Math.max(L, rules.min_length)
  L = Math.max(L, pools.length)
  const chars = pools.map((p) => p[Math.floor(Math.random() * p.length)])
  while (chars.length < L) chars.push(full[Math.floor(Math.random() * full.length)])
  for (let i = chars.length - 1; i > 0; i--) {   // melange de Fisher-Yates
    const j = Math.floor(Math.random() * (i + 1))
    ;[chars[i], chars[j]] = [chars[j], chars[i]]
  }
  return chars.join('')
}

// validite (cote client, retour instantane ; le backend re-verifie a l'attaque)
function checkValid(target: string, caseId: CaseId, rules: Rules | null): { valid: boolean; reasons: string[] } {
  const reasons: string[] = []
  if (caseId === 'binaire' || caseId === 'numerique') {
    const need = caseId === 'binaire' ? 3 : 4
    if (target.length !== need) reasons.push(t('il faut exactement {n} caractères', { n: need }))
    return { valid: reasons.length === 0, reasons }
  }
  if (target.length === 0) reasons.push(t('mot de passe vide'))
  if (rules) {
    if (rules.require_lower && !/[a-z]/.test(target)) reasons.push(t('il manque une minuscule'))
    if (rules.require_upper && !/[A-Z]/.test(target)) reasons.push(t('il manque une majuscule'))
    if (rules.require_digit && !/[0-9]/.test(target)) reasons.push(t('il manque un chiffre'))
    if (rules.require_symbol && !/[^a-zA-Z0-9]/.test(target)) reasons.push(t('il manque un symbole'))
    if (rules.min_length && target.length < rules.min_length)
      reasons.push(t('longueur minimale : {min} (actuelle : {n})', { min: rules.min_length, n: target.length }))
  }
  return { valid: reasons.length === 0, reasons }
}

// icones sobres
const DiceIcon = () => (
  <svg className="icon-btn-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="18" height="18" rx="4" /><circle cx="8.5" cy="8.5" r="1.1" fill="currentColor" stroke="none" />
    <circle cx="15.5" cy="15.5" r="1.1" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none" />
  </svg>
)
const CheckIcon = ({ cls = 'pw-ind-ico' }: { cls?: string }) => (
  <svg className={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
)
const CrossIcon = () => (
  <svg className="pw-ind-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18M6 6l12 12" /></svg>
)
const StopIcon = () => (
  <svg className="icon-btn-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="6" width="12" height="12" rx="2" /></svg>
)

// `sec` = duree de l'attaque, a la vitesse de l'attaquant (essais / vitesse)
type Outcome =
  | { kind: 'brute-found'; pw: string; tries: number; sec: number; strength: Strength }
  | { kind: 'brute-blocked'; limit: number; sec: number }
  | { kind: 'dict-found'; position: number; size: number; pw: string; sec: number }
  | { kind: 'dict-blocked'; limit: number; sec: number }
  | { kind: 'dict-resist'; size: number; sec: number }
  | { kind: 'interrupted'; sec: number; tries: number; pct: number; fullHuman: string | null }

type Meta = Omit<PwHistoryDraft, 'result' | 'tries' | 'timeSec'>
const RESULT_OF: Record<Exclude<Outcome['kind'], 'interrupted'>, PwResult> = {
  'brute-found': 'found', 'dict-found': 'found', 'brute-blocked': 'blocked', 'dict-blocked': 'blocked', 'dict-resist': 'resist',
}

// =============================================================================
export default function PasswordsPanel() {
  const [data, setData] = useState<CasesResponse | null>(null)
  const [caseId, setCaseId] = useState<CaseId>('binaire')
  const [target, setTarget] = useState('101')
  const [length, setLength] = useState(12)

  // protection
  const [protect, setProtect] = useState(false)
  const [rules, setRules] = useState<Rules>(EMPTY_RULES)
  const [limitOn, setLimitOn] = useState(false)      // « limiter les tentatives » (cas complexe)
  const [limitStr, setLimitStr] = useState('5')      // champ libre (entier positif)
  const [knowComposition, setKnowComposition] = useState(false)   // indice : l'attaquant connait la composition

  // attaque / verdict
  const [attacking, setAttacking] = useState<'brute' | 'dict' | null>(null)
  const [progress, setProgress] = useState(0)
  const [counter, setCounter] = useState(0)
  const [scramble, setScramble] = useState('')
  const [elapsed, setElapsed] = useState(0)           // duree ecoulee de l'attaque (secondes)
  const [history, setHistory] = useState<PwHistoryEntry[]>([])
  const localId = useRef(0)                           // numeros negatifs : lignes que le backend n'a pas pu enregistrer
  const [verdict, setVerdict] = useState<Outcome | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const anim = useRef<{
    poll?: number; scramble?: number
    attackId: string | null; runId: number; interrupted: boolean; meta: Meta | null
  }>({ attackId: null, runId: 0, interrupted: false, meta: null })

  const full = data?.fullCharset ?? FALLBACK_FULL
  const busy = !!attacking                            // pendant une attaque, rien ne se modifie : seul « Interrompre » l'arrete
  const isSmall = caseId !== 'complexe'
  const limitNum = Math.max(1, parseInt(limitStr, 10) || 1)

  const effRules: Rules | null = !isSmall && protect ? rules : null
  const effLimit: number | null =
    isSmall ? (protect ? limitNum : null) : (protect && limitOn ? limitNum : null)

  const validity = checkValid(target, caseId, effRules)

  useEffect(() => {
    api.cases().then(setData).catch(() => setData(null))
    reloadHistory()
    return () => cancelAnims()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function cancelAnims() {
    if (anim.current.poll) window.clearInterval(anim.current.poll)
    if (anim.current.scramble) window.clearInterval(anim.current.scramble)
    anim.current.poll = undefined
    anim.current.scramble = undefined
  }
  function resetAttack() {
    cancelAnims(); anim.current.runId++; anim.current.attackId = null
    setAttacking(null); setProgress(0); setCounter(0); setElapsed(0); setVerdict(null); setErr(null)
  }

  // ---- historique (fichier cote backend ; si le backend ne repond pas, la ligne reste a l'ecran) ----
  function reloadHistory() {
    api.pwHistoryList().then((r) => { if (r.ok) setHistory(r.entries) }).catch(() => { /* garde l'ecran */ })
  }
  async function record(draft: PwHistoryDraft) {
    let entry: PwHistoryEntry
    try {
      const r = await api.pwHistoryAdd(draft)
      entry = r.ok ? r.entry : { ...draft, id: -(++localId.current) }
    } catch {
      entry = { ...draft, id: -(++localId.current) }
    }
    setHistory((h) => [entry, ...h])
  }
  function removeRun(id: number) {
    setHistory((h) => h.filter((e) => e.id !== id))
    if (id > 0) api.pwHistoryRemove(id).then((r) => { if (!r.ok) reloadHistory() }).catch(reloadHistory)
  }
  function clearHistory() {
    setHistory([])
    api.pwHistoryClear().then((r) => { if (!r.ok) reloadHistory() }).catch(reloadHistory)
  }

  // resume des protections actives, pour l'historique (en francais, traduit a l'affichage)
  function protectionText(kind: 'brute' | 'dict'): string {
    const parts: string[] = []
    if (effLimit != null) parts.push(`${frFR(effLimit)} tentative${effLimit > 1 ? 's' : ''} max`)
    if (effRules) {
      const cl = ([['require_lower', 'a-z'], ['require_upper', 'A-Z'], ['require_digit', '0-9'], ['require_symbol', 'symboles']] as const)
        .filter(([k]) => effRules[k]).map(([, l]) => l)
      parts.push(...cl)
      if (effRules.min_length) parts.push(`long. min ${effRules.min_length}`)
    }
    if (kind === 'brute' && !isSmall && !knowComposition) parts.push('sans indice')
    return parts.length ? parts.join(' · ') : 'Aucune'
  }

  function changeCase(id: CaseId) {
    resetAttack()
    setCaseId(id)
    setProtect(false); setRules(EMPTY_RULES); setLimitOn(false)
    setTarget(id === 'binaire' ? '101' : id === 'numerique' ? '2413' : generate('complexe', length, full, null))
  }
  function onType(v: string) { resetAttack(); const s = sanitize(v, caseId, full); setTarget(s); if (!isSmall) setLength(s.length) }
  function onSlide(v: number) { resetAttack(); setLength(v); setTarget(generate('complexe', v, full, effRules)) }
  function regenerate() { resetAttack(); setTarget(generate(caseId, length, full, effRules)) }

  const minSlide = protect && rules.min_length ? rules.min_length : 1
  function setMinLen(v: number) {
    const nv = Math.max(1, Math.min(64, v))
    setRules((r) => ({ ...r, min_length: nv }))
    if (length < nv) { setLength(nv); setTarget(generate('complexe', nv, full, { ...rules, min_length: nv })) }
  }
  const toggleRule = (k: keyof Rules) => { resetAttack(); setRules((r) => ({ ...r, [k]: !r[k] })) }

  // ------------------------------------------------------------- attaque ----
  const scrambleSample = (kind: 'brute' | 'dict') => {
    if (kind === 'dict') return randStr(LOWER, 4 + Math.floor(Math.random() * 5))
    const cs = isSmall ? (caseId === 'binaire' ? '01' : '1234') : (detectedCharset(target) || full)
    const len = isSmall ? (caseId === 'binaire' ? 3 : 4) : Math.max(1, length)
    return randStr(cs, len)
  }

  // L'attaque tourne pour de VRAI cote serveur (un vrai thread qui boucle a la
  // vitesse reelle de cette machine) : cette fonction ne fait que relire sa
  // progression par polling et l'afficher telle quelle, sans rien simuler.
  // Elle ne s'arrete que quand la cible est trouvee, que la limite de tentatives
  // est atteinte (protection) ou que l'utilisateur clique sur « Interrompre »
  // (qui coupe vraiment le thread cote serveur, pas seulement l'affichage).
  function applySnapshot(snap: AttackSnapshot, kind: 'brute' | 'dict', runId: number) {
    const a = anim.current
    if (a.runId !== runId) return               // interrompu / reinitialise pendant l'attente
    if (!snap.ok) { resetAttack(); setErr(_t('Backend injoignable. Lance le serveur Python.')); return }
    setCounter(snap.pos)
    setProgress(snap.total > 0 ? (snap.pos / snap.total) * 100 : 0)
    setElapsed(snap.elapsed)
    if (!snap.done || !snap.result) return

    cancelAnims()
    let outcome: Outcome
    if (kind === 'brute') {
      const r = snap.result as Omit<BruteResult, 'ok' | 'error'>
      if (!r.valid) { resetAttack(); setErr(_t('Mot de passe non conforme à la politique.')); return }
      outcome = r.cracked
        ? { kind: 'brute-found', pw: target, tries: Number(r.rank ?? snap.pos), sec: r.findSeconds ?? snap.elapsed, strength: r.findStrength ?? 'inviolable' }
        : { kind: 'brute-blocked', limit: r.limit ?? 0, sec: snap.elapsed }
    } else {
      const r = snap.result as Omit<DictResult, 'ok'>
      outcome = r.found
        ? { kind: 'dict-found', position: r.position ?? 0, size: r.size, pw: target, sec: snap.elapsed }
        : r.stopped ? { kind: 'dict-blocked', limit: r.limit ?? 0, sec: snap.elapsed } : { kind: 'dict-resist', size: r.size, sec: snap.elapsed }
    }
    setVerdict(outcome)
    setAttacking(null)
    if (a.meta) record({ ...a.meta, result: RESULT_OF[outcome.kind], tries: snap.pos, timeSec: snap.elapsed })
  }

  async function pollTick(runId: number, kind: 'brute' | 'dict') {
    const a = anim.current
    if (a.runId !== runId || !a.attackId) return
    try {
      applySnapshot(await api.attackProgress(a.attackId), kind, runId)
    } catch {
      if (a.runId !== runId) return
      resetAttack(); setErr(_t('Backend injoignable. Lance le serveur Python.'))
    }
  }

  function interrupt() {
    const a = anim.current
    a.interrupted = true
    const stopId = a.attackId
    a.runId++                                  // une reponse du backend encore attendue sera ignoree
    cancelAnims()
    if (stopId) void api.attackStop(stopId).catch(() => undefined)   // coupe VRAIMENT le thread
    // on fige l'affichage sur les dernieres valeurs reelles connues (deja posees par le dernier poll)
    setVerdict({ kind: 'interrupted', sec: elapsed, tries: counter, pct: progress, fullHuman: null })
    setAttacking(null)
    if (a.meta) record({ ...a.meta, result: 'interrupted', tries: counter, timeSec: elapsed })
  }

  async function runAttack(kind: 'brute' | 'dict') {
    cancelAnims()
    setErr(null); setVerdict(null); setAttacking(kind); setProgress(0); setCounter(0); setElapsed(0)
    const a = anim.current
    const id = ++a.runId
    a.interrupted = false
    a.attackId = null
    a.meta = { attack: kind, case: caseId, password: target, protection: protectionText(kind) }
    a.scramble = window.setInterval(() => setScramble(scrambleSample(kind)), SCRAMBLE_MS)
    try {
      const started = await api.attackStart({
        kind, caseId: kind === 'brute' ? caseId : undefined, target,
        length: kind === 'brute' && !isSmall ? length : undefined,
        limit: effLimit, rules: effRules, knowComposition, lang: getLang(),
      })
      if (a.runId !== id) return               // interrompu / reinitialise pendant l'attente
      if (!started.ok) { resetAttack(); setErr(_t('Backend injoignable. Lance le serveur Python.')); return }
      a.attackId = started.id
      applySnapshot(started, kind, id)         // deja termine pour les cas instantanes (binaire, numerique…)
      if (a.runId === id && !started.done) a.poll = window.setInterval(() => pollTick(id, kind), POLL_MS)
    } catch {
      if (a.runId !== id) return
      resetAttack(); setErr(_t('Backend injoignable. Lance le serveur Python.'))
    }
  }

  const classChips = [['require_lower', 'a-z'], ['require_upper', 'A-Z'], ['require_digit', '0-9'], ['require_symbol', _t('Symboles')]] as const

  // mot de passe trouve : on le garde affiche au-dessus de la barre
  const foundPw = verdict && ((verdict.kind === 'brute-found' && WEAK.includes(verdict.strength)) || verdict.kind === 'dict-found')
    ? verdict.pw : null
  // colonne a entourer dans le tableau : celle du jeu detecte si l'indice est
  // actif, sinon la derniere (pire cas, jeu complet). Le tableau n'a que 5
  // colonnes figees (jeux CUMULATIFS : 10, 26, 52, 62, 86) : des que la cible
  // melange des classes autrement (ex. minuscules + chiffres + symboles, SANS
  // majuscules = 60), aucune colonne ne correspond exactement — on entoure la
  // plus proche en TAILLE, pas forcement la bonne composition. D'ou le calcul
  // exact juste en dessous (effSize/effHuman), affiche a part plutot que de
  // laisser croire que la case entouree est la valeur reelle.
  const tableCols = data?.table?.columns ?? []
  const highlightCol = tableCols.length
    ? (knowComposition ? colForSize(detectedCharset(target).length || 86, tableCols.map((c) => c.size)) : tableCols.length - 1)
    : 0
  // valeur EXACTE pour la cible actuelle (jeu reellement detecte + longueur reelle,
  // pas arrondie a une case du tableau) — meme rythme de reference que le tableau
  const effSize = knowComposition ? (detectedCharset(target).length || 86) : 86
  const effLabel = knowComposition ? composition(target, caseId) : t('pire cas (jeu complet)')
  const effRate = data?.table?.rate ?? data?.assumptions.fastRate ?? FAST_RATE_FALLBACK
  const [effHuman, effStrength] = humanTimeCompact(Math.pow(effSize, length) / effRate)

  // =============================================================================
  return (
    <>
    <div className="panel">
      <h2 className="panel-title">{t('Mots de passe — attaques & protection')}</h2>

      {/* --- choix du cas --- */}
      <div className="field">
        <span className="field-label">{t('Cas')}</span>
        <div className="segmented" role="group" aria-label={t('Type de mot de passe')}>
          {CASE_IDS.map((id) => (
            <button key={id} className={'seg' + (caseId === id ? ' is-on' : '')}
              aria-pressed={caseId === id} disabled={busy} onClick={() => changeCase(id)}>
              {t(CASE_LABEL[id])}
            </button>
          ))}
        </div>
      </div>

      {/* --- cible : champ (compteur a droite), puis Generer, puis le slider --- */}
      <div className="pw-target">
        <div className="pw-input-wrap">
          <input className={'text-input mono pw-input' + (isSmall ? '' : ' has-count')}
            value={target} onChange={(e) => onType(e.target.value)}
            aria-label={t('Mot de passe cible')} disabled={busy} spellCheck={false} autoComplete="off" />
          {!isSmall && <span className="pw-count" aria-hidden="true">{target.length}/64</span>}
        </div>
        <button className="btn pw-gen" onClick={regenerate} disabled={busy}><DiceIcon />{t('Générer')}</button>
        {!isSmall && (
          <label className="pw-slide-inline">
            <span className="pw-slide-cap">{t('long. {n}', { n: length })}</span>
            <input className="pw-slider" type="range" min={minSlide} max={64} value={length}
              aria-label={t('Longueur du mot de passe généré : {n}', { n: length })} disabled={busy}
              onChange={(e) => onSlide(parseInt(e.target.value, 10))} />
          </label>
        )}
      </div>

      {/* --- indicateur de validite --- */}
      <div className={'pw-validity ' + (validity.valid ? 'is-ok' : 'is-bad')} role="status">
        {validity.valid ? (<><CheckIcon /> {t('Mot de passe valide')}</>) : (<><CrossIcon /> {t('Invalide :')} {validity.reasons.join(' · ')}</>)}
      </div>

      {/* --- actions : indice (gauche) · attaques (centre) · protection (droite) --- */}
      <div className="pw-actions">
        <div className="pw-actions-side pw-actions-left">
          {!isSmall && (
            <button className={'pw-pill' + (knowComposition ? ' is-on' : '')} aria-pressed={knowComposition} disabled={busy}
              title={t("L'attaquant connaît-il la composition du mot de passe ? S'il la connaît, il restreint son jeu de caractères (sinon il suppose le pire cas).")}
              onClick={() => { resetAttack(); setKnowComposition((v) => !v) }}>
              <span className="pw-switch-dot" />
              {knowComposition ? <>{t('indice :')} {composition(target, caseId)}</> : <>{t('indice désactivé')}</>}
            </button>
          )}
        </div>
        <div className="pw-actions-mid">
          <button className="btn btn-accent" onClick={() => runAttack('brute')} disabled={!!attacking || !validity.valid}>{t('Force brute')}</button>
          <button className="btn btn-accent" onClick={() => runAttack('dict')} disabled={!!attacking || !validity.valid}>{t('Dictionnaire')}</button>
        </div>
        <div className="pw-actions-side pw-actions-right">
          <button className={'pw-protect-btn' + (protect ? ' is-on' : '')} aria-pressed={protect} disabled={busy}
            onClick={() => { resetAttack(); setProtect((v) => !v) }}>
            <span className="pw-switch-dot" />{protect ? t('Protection activée') : t('Activer la protection')}
          </button>
        </div>
      </div>

      {/* --- protection inline (sans section ni explications) --- */}
      {protect && (
        <div className="pw-protect-inline">
          {!isSmall && (
            <div className="pw-chips">
              {classChips.map(([k, lbl]) => (
                <button key={k} className={'pw-chip' + (rules[k] ? ' is-on' : '')} aria-pressed={!!rules[k]} disabled={busy} onClick={() => toggleRule(k)}>{t(lbl)}</button>
              ))}
            </div>
          )}
          <div className="pw-protect-row">
            {!isSmall && (
              <span className="pw-toggle-item">
                <button className={'pw-chip' + (rules.min_length != null ? ' is-on' : '')} aria-pressed={rules.min_length != null} disabled={busy}
                  onClick={() => { resetAttack(); setRules((r) => ({ ...r, min_length: r.min_length == null ? 12 : null })) }}>
                  {t('Longueur minimale')}
                </button>
                {rules.min_length != null && (
                  <input className="pw-num" type="number" min={1} max={64} value={rules.min_length}
                    aria-label={t('Longueur minimale')} disabled={busy}
                    onChange={(e) => setMinLen(parseInt(e.target.value, 10) || 1)} />
                )}
              </span>
            )}
            <span className="pw-toggle-item">
              {isSmall ? (
                <span className="pw-toggle-lbl">{t('Nombre de tentatives autorisées')}</span>
              ) : (
                <button className={'pw-chip' + (limitOn ? ' is-on' : '')} aria-pressed={limitOn} disabled={busy}
                  onClick={() => { resetAttack(); setLimitOn((v) => !v) }}>
                  {t('Limiter les tentatives')}
                </button>
              )}
              {(isSmall || limitOn) && (
                <input className="pw-num pw-num-grow" type="text" inputMode="numeric" value={limitStr}
                  aria-label={t('Nombre de tentatives autorisées')} disabled={busy}
                  style={{ width: `calc(${Math.max(4, limitStr.length + 1)}ch + 20px)`, maxWidth: '100%' }}
                  onChange={(e) => { resetAttack(); setLimitStr(e.target.value.replace(/[^0-9]/g, '')) }} />
              )}
            </span>
          </div>
        </div>
      )}

      {err && <div className="warn error">⚠ {t(err)}</div>}

      {/* --- progression (reste visible a l'arret) --- */}
      {(attacking || verdict) && (
        <div className="pw-stage">
          {attacking && (
            <div className="pw-stage-top">
              <span className="pw-stage-label">{attacking === 'brute' ? t('Force brute en cours…') : t('Dictionnaire en cours…')}</span>
              <button className="btn tiny pw-stop" onClick={interrupt}><StopIcon />{t('Interrompre')}</button>
            </div>
          )}
          {(attacking || foundPw) && (
            <div className={'pw-scramble' + (!attacking && foundPw ? ' pw-found' : '')}>
              {attacking ? scramble : foundPw}
            </div>
          )}
          <div className="pw-progress"><span style={{ width: Math.max(0, Math.min(100, progress)) + '%' }} /></div>
          <div className="pw-progress-meta">
            <span className="pw-pct">{t('{p} % des combinaisons', { p: fmtPct(progress) })}</span>
            <span className="pw-tried">{fmtTries(counter)} {t(plural(counter, 'essai', 'essais'))}</span>
          </div>
          <div className="pw-clock">
            {attacking ? t('Temps écoulé :') : t('Durée de l\'attaque :')} <strong>{fmtDur(elapsed)}</strong>
          </div>
        </div>
      )}

      {verdict && <Verdict o={verdict} />}


      {/* --- tableau des durees (complexe) --- */}
      {!isSmall && data?.table && (
        <>
          <div className="divider" />
          <h3 className="sub-title">{t('Combien de temps, selon la taille et le type')}</h3>
          <TimeTable table={data.table} currentLen={length} highlightCol={highlightCol} />
          <div className={'pw-table-exact ' + strengthClass(effStrength)}>
            {t('Ta cible réelle : {comp} ({n} caractères), longueur {len} → {time}', {
              comp: effLabel, n: effSize, len: length, time: t(effHuman),
            })}
            <span className="pw-table-exact-note">
              {t(' — pas forcément une case du tableau ci-dessus : ses 5 colonnes sont figées (10, 26, 52, 62, 86 caractères), la case entourée est la plus proche en taille, pas forcément la même composition.')}
            </span>
          </div>
        </>
      )}
    </div>

    {/* historique : une carte a part, hors du cadre « Mots de passe » */}
    <PwHistory entries={history} onRemove={removeRun} onClear={clearHistory} />
    </>
  )
}

// ---------------------------------------------------------- sous-composants ----
function Verdict({ o }: { o: Outcome }) {
  let cls: Strength = 'fort'
  let label = ''
  let detail: ReactNode = null
  const essais = (n: number) => `${fmtTries(n)} ${t(plural(n, 'essai', 'essais'))}`
  switch (o.kind) {
    case 'brute-found':
      cls = o.strength; label = t('Mot de passe cracké')
      detail = <><CheckIcon /> <strong className="mono">{o.pw}</strong> — {t('cracké en')} <strong>{fmtDur(o.sec)}</strong> ({essais(o.tries)})</>
      break
    case 'dict-found':
      cls = 'instant'; label = t('Trouvé dans le dictionnaire')
      detail = <><CheckIcon /> <strong className="mono">{o.pw}</strong> — {t('mot n° {i} sur {n}, cracké en', { i: fr(o.position), n: fr(o.size) })} <strong>{fmtDur(o.sec)}</strong></>
      break
    case 'brute-blocked':
    case 'dict-blocked':
      cls = 'fort'; label = t('Attaque bloquée')
      detail = <>{t('arrêtée après {n} {w} ({d}) — mot de passe non trouvé', { n: fr(o.limit), w: t(plural(o.limit, 'tentative', 'tentatives')), d: fmtDur(o.sec) })}</>
      break
    case 'dict-resist':
      cls = 'fort'; label = t('Résiste au dictionnaire')
      detail = <>{t('absent des {n} mots testés (parcourus en {d}) — le dictionnaire ne suffit pas', { n: fr(o.size), d: fmtDur(o.sec) })}</>
      break
    case 'interrupted':
      cls = 'moyen'; label = t('Attaque interrompue')
      detail = (
        <>
          {t("tu as arrêté l'attaque après")} <strong>{fmtDur(o.sec)}</strong> ({essais(o.tries)}, {t('{p} % des combinaisons', { p: fmtPct(o.pct) })})
          {o.fullHuman && <> — {t('il aurait fallu ~{d} pour trouver ce mot de passe', { d: t(o.fullHuman) })}</>}
        </>
      )
      break
  }
  return (
    <div className={'pw-verdict ' + strengthClass(cls)}>
      <div className="pw-verdict-label">{label}</div>
      <div className="pw-run">{detail}</div>
    </div>
  )
}

function TimeTable({ table, currentLen, highlightCol }: { table: SpeedTable; currentLen: number; highlightCol: number }) {
  const rows = table.rows
  const nearest = rows.reduce((a, b) => (Math.abs(b.length - currentLen) < Math.abs(a.length - currentLen) ? b : a), rows[0])
  return (
    <div className="pw-table-wrap">
      <table className="pw-table">
        <thead>
          <tr>
            <th className="pw-th-len">{t('Longueur')}</th>
            {table.columns.map((c) => <th key={c.name}>{t(c.name)}<span className="pw-th-sub">{t(c.detail)}</span></th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.length}>
              <th>{row.length}</th>
              {row.cells.map((cell, ci) => {
                const hot = row.length === nearest.length && ci === highlightCol
                return <td key={ci} className={strengthClass(cell.strength) + (hot ? ' is-current' : '')}>{t(cell.human)}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
