import { useEffect, useRef, useState } from 'react'
import type {
  BruteResult, DictResult, HashResult, CasesResponse, ProtectResult,
  Protections, Estimate, Strength,
} from '../../types'
import { api } from '../../api'

// ---------------------------------------------------------------- helpers ----
const CASE_IDS = ['binaire', 'numerique', 'complexe'] as const
const CASE_LABEL: Record<string, string> = {
  binaire: 'Binaire', numerique: 'Numérique', complexe: 'Complexe',
}
const FALLBACK_FULL =
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?/'
const YEAR = 31_536_000

// Compact French durations for the table, so every cell stays short.
function compactTime(seconds: number): { label: string; strength: Strength } {
  const s = seconds
  if (!isFinite(s)) return { label: 'millénaires', strength: 'inviolable' }
  if (s < 1e-3) return { label: 'instantané', strength: 'instant' }
  if (s < 1) return { label: '< 1 s', strength: 'instant' }
  if (s < 60) return { label: `${Math.round(s)} s`, strength: 'faible' }
  if (s < 3600) return { label: `${Math.round(s / 60)} min`, strength: 'faible' }
  if (s < 86400) return { label: `${Math.round(s / 3600)} h`, strength: 'moyen' }
  if (s < 2_592_000) return { label: `${Math.round(s / 86400)} j`, strength: 'moyen' }
  if (s < YEAR) return { label: `${Math.round(s / 2_592_000)} mois`, strength: 'moyen' }
  if (s < 1000 * YEAR) { const n = Math.round(s / YEAR); return { label: n === 1 ? '1 an' : `${n.toLocaleString('fr-FR')} ans`, strength: 'fort' } }
  if (s < 1e6 * YEAR) return { label: 'siècles', strength: 'fort' }
  return { label: 'millénaires', strength: 'inviolable' }
}

const strengthClass = (s: Strength) => `is-${s}`

function randStr(charset: string, len: number): string {
  let out = ''
  for (let i = 0; i < len; i++) out += charset[Math.floor(Math.random() * charset.length)]
  return out
}

function fmtMs(seconds: number): string {
  if (seconds < 1e-3) return `${(seconds * 1e6).toFixed(0)} µs`
  if (seconds < 1) return `${(seconds * 1e3).toFixed(1)} ms`
  return `${seconds.toFixed(2)} s`
}

function barPct(seconds: number | null): number {
  if (seconds == null || !isFinite(seconds)) return 100
  const l = Math.log10(Math.max(seconds, 1e-10))
  return Math.max(3, Math.min(100, ((l + 10) / 130) * 100))
}

// sober inline icons (no emoji), same spirit as the eye toggle of the cipher tab
const DiceIcon = () => (
  <svg className="icon-btn-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="18" height="18" rx="4" /><circle cx="8.5" cy="8.5" r="1.1" fill="currentColor" stroke="none" />
    <circle cx="15.5" cy="15.5" r="1.1" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none" />
  </svg>
)
const CheckIcon = () => (
  <svg className="pw-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 6 9 17l-5-5" />
  </svg>
)

// =============================================================================
export default function PasswordsPanel() {
  const [data, setData] = useState<CasesResponse | null>(null)
  const [caseId, setCaseId] = useState<string>('binaire')
  const [target, setTarget] = useState('101')
  const [length, setLength] = useState(8)

  const [brute, setBrute] = useState<BruteResult | null>(null)
  const [dict, setDict] = useState<DictResult | null>(null)
  const [attacking, setAttacking] = useState<'brute' | 'dict' | null>(null)
  const [counter, setCounter] = useState(0)
  const [scramble, setScramble] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const [protections, setProtections] = useState<Protections>({
    require_lower: false, require_upper: false, require_digit: false,
    require_symbol: false, min_length: null, limit_attempts: false, slow_hash: false,
  })
  const [protect, setProtect] = useState<ProtectResult | null>(null)

  const [hash, setHash] = useState<HashResult | null>(null)
  const [hashing, setHashing] = useState(false)

  const anim = useRef<{ scramble?: number; raf?: number; to?: number }>({})
  const fullCharset = data?.fullCharset ?? FALLBACK_FULL
  const info = data?.cases[caseId]
  const caseCharset = info?.charset ?? (caseId === 'binaire' ? '01' : caseId === 'numerique' ? '1234' : fullCharset)

  useEffect(() => {
    api.cases().then(setData).catch(() => setData(null))
    return () => cancelAnims()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Auto-detect the character classes present in the target → light up the
  // matching chips, so the protections reflect what the password already has.
  useEffect(() => {
    if (caseId !== 'complexe') return
    setProtections((p) => ({
      ...p,
      require_lower: /[a-z]/.test(target),
      require_upper: /[A-Z]/.test(target),
      require_digit: /[0-9]/.test(target),
      require_symbol: /[^a-zA-Z0-9]/.test(target),
    }))
  }, [caseId, target])

  // Recompute the sans/avec comparison on any change (cheap, lightly debounced).
  useEffect(() => {
    if (caseId !== 'complexe') { setProtect(null); return }
    const t = window.setTimeout(() => {
      api.protect(target, protections).then(setProtect).catch(() => {})
    }, 120)
    return () => window.clearTimeout(t)
  }, [caseId, target, protections])

  function cancelAnims() {
    if (anim.current.scramble) window.clearInterval(anim.current.scramble)
    if (anim.current.raf) cancelAnimationFrame(anim.current.raf)
    if (anim.current.to) window.clearTimeout(anim.current.to)
  }

  function genTarget(id: string, len: number): string {
    if (id === 'binaire') return randStr('01', 3)
    if (id === 'numerique') return randStr('1234', 4)
    return randStr(fullCharset, Math.max(0, len))
  }

  function changeCase(id: string) {
    cancelAnims(); setAttacking(null); setCaseId(id)
    setBrute(null); setDict(null); setErr(null); setHash(null)
    setTarget(id === 'binaire' ? '101' : id === 'numerique' ? '2413' : genTarget('complexe', length))
  }
  function onSlide(v: number) { setLength(v); setTarget(genTarget('complexe', v)); setBrute(null); setDict(null) }
  function onType(v: string) { setTarget(v); if (caseId === 'complexe') setLength(v.length); setBrute(null); setDict(null) }
  function regenerate() { setTarget(genTarget(caseId, length)); setBrute(null); setDict(null) }

  const delay = (ms: number) => new Promise<void>((r) => { anim.current.to = window.setTimeout(r, ms) })
  const tween = (to: number, ms: number) =>
    new Promise<void>((resolve) => {
      const start = performance.now()
      const step = (now: number) => {
        const t = Math.min(1, (now - start) / ms)
        setCounter(Math.round(to * (1 - Math.pow(1 - t, 3))))
        if (t < 1) anim.current.raf = requestAnimationFrame(step)
        else resolve()
      }
      anim.current.raf = requestAnimationFrame(step)
    })

  async function settle(t0: number) {
    const elapsed = performance.now() - t0
    await delay(Math.max(0, 850 - elapsed))
    if (anim.current.scramble) window.clearInterval(anim.current.scramble)
  }

  async function runAttack(kind: 'brute' | 'dict') {
    cancelAnims(); setErr(null); setAttacking(kind); setCounter(0)
    if (kind === 'brute') setBrute(null); else setDict(null)
    const sCharset = kind === 'brute' ? caseCharset : 'abcdefghijklmnopqrstuvwxyz'
    const sLen = kind === 'brute' ? (caseId === 'complexe' ? Math.max(1, length) : caseCharset === '01' ? 3 : 4) : 8
    anim.current.scramble = window.setInterval(() => setScramble(randStr(sCharset, sLen)), 55)
    const t0 = performance.now()
    try {
      if (kind === 'brute') {
        const res = await api.bruteforce(caseId, target, caseId === 'complexe' ? length : undefined)
        await settle(t0); setCounter(res.attempts); await tween(res.attempts, 650); setBrute(res)
      } else {
        const res = await api.dictionary(target)
        await settle(t0); setCounter(res.attempts); await tween(res.attempts, 650); setDict(res)
      }
    } catch {
      setErr('Backend injoignable. Lance le serveur Python.')
    } finally {
      if (anim.current.scramble) window.clearInterval(anim.current.scramble)
      setAttacking(null)
    }
  }

  async function runHash() {
    setHashing(true)
    try { setHash(await api.hashPassword(target)) } finally { setHashing(false) }
  }

  const toggle = (k: keyof Protections) => setProtections((p) => ({ ...p, [k]: !p[k] }))
  const toggleMinLen = () => setProtections((p) => ({ ...p, min_length: p.min_length == null ? 12 : null }))
  const setMinLen = (v: number) => setProtections((p) => ({ ...p, min_length: Math.max(8, Math.min(32, v)) }))

  const classChips: { k: keyof Protections; label: string }[] = [
    { k: 'require_lower', label: 'a-z' }, { k: 'require_upper', label: 'A-Z' },
    { k: 'require_digit', label: '0-9' }, { k: 'require_symbol', label: 'Symboles' },
  ]
  const keyText = caseId === 'complexe' ? `${caseCharset.length}^${length}` : (info?.keyspaceText ?? '')

  return (
    <div className="panel">
      <h2 className="panel-title">Mots de passe — attaques &amp; protection</h2>
      <p className="panel-sub">
        Un seul principe : <strong>temps = espace de clés ÷ vitesse de l'attaquant</strong>.
        On attaque les trois cas de l'énoncé, puis on active des protections et on
        regarde le temps grimper. Attaquant de référence : ~10 milliards d'essais/s.
      </p>

      <div className="field">
        <span className="field-label">Cas</span>
        <div className="segmented">
          {CASE_IDS.map((id) => (
            <button key={id} className={'seg' + (caseId === id ? ' is-on' : '')} onClick={() => changeCase(id)}>
              {CASE_LABEL[id]}
            </button>
          ))}
        </div>
      </div>

      {info && (
        <p className="pw-caption">
          {info.label} · <span className="mono">{keyText}</span> combinaisons
        </p>
      )}

      <div className="controls">
        <div className="field grow">
          <span className="field-label">Mot de passe cible</span>
          <input className="text-input mono" value={target} onChange={(e) => onType(e.target.value)} />
        </div>
        <button className="btn" onClick={regenerate}><DiceIcon />Générer</button>
      </div>

      {caseId === 'complexe' && (
        <div className="field">
          <span className="field-label">Longueur : {length}</span>
          <input className="pw-slider" type="range" min={0} max={64} value={length}
            onChange={(e) => onSlide(parseInt(e.target.value, 10))} />
        </div>
      )}

      <div className="btn-row cipher-actions">
        <button className="btn btn-accent" onClick={() => runAttack('brute')} disabled={!!attacking}>Force brute</button>
        <button className="btn btn-accent" onClick={() => runAttack('dict')} disabled={!!attacking}>Dictionnaire</button>
      </div>

      {err && <div className="warn error">⚠ {err}</div>}

      {attacking && (
        <div className="pw-stage">
          <div className="pw-stage-label">Cassage en cours…</div>
          <div className="pw-counter">{counter.toLocaleString('fr-FR')}</div>
          <div className="pw-counter-sub">essais</div>
          <div className="pw-scramble">{scramble}</div>
        </div>
      )}

      {!attacking && brute && <BruteCard res={brute} />}
      {!attacking && dict && <DictCard res={dict} />}

      <div className="divider" />

      {caseId === 'complexe' ? (
        <>
          <h3 className="sub-title">Protections (politique sur le mot de passe complexe)</h3>
          <p className="panel-sub">
            Les classes allumées sont celles <strong>détectées dans ton mot de passe</strong> ;
            ajoute-en pour agrandir l'espace, retires-en pour voir l'attaque devenir
            plus rapide. Limiter les tentatives et le hachage lent <strong>ralentissent
            l'attaquant</strong>. Le temps « avec protection » se compare en direct au
            temps « sans protection ».
          </p>

          <div className="pw-protect-groups">
            <div className="pw-group">
              <span className="pw-group-label">Jeu de caractères (détecté, modifiable)</span>
              <div className="pw-chips">
                {classChips.map((c) => (
                  <button key={c.k} className={'pw-chip' + (protections[c.k] ? ' is-on' : '')} onClick={() => toggle(c.k)}>
                    {c.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="pw-group">
              <span className="pw-group-label">Longueur minimale</span>
              <div className="pw-chips">
                <button className={'pw-chip' + (protections.min_length != null ? ' is-on' : '')} onClick={toggleMinLen}>
                  {protections.min_length != null ? `≥ ${protections.min_length}` : 'Activer'}
                </button>
                {protections.min_length != null && (
                  <span className="pw-stepper">
                    <button className="pw-step" onClick={() => setMinLen((protections.min_length ?? 12) - 1)}>−</button>
                    <span className="pw-step-val">{protections.min_length}</span>
                    <button className="pw-step" onClick={() => setMinLen((protections.min_length ?? 12) + 1)}>+</button>
                  </span>
                )}
              </div>
            </div>

            <div className="pw-group">
              <span className="pw-group-label">Ralentir l'attaquant</span>
              <div className="pw-chips">
                <button className={'pw-chip' + (protections.limit_attempts ? ' is-on' : '')} onClick={() => toggle('limit_attempts')}>
                  Limiter les tentatives
                </button>
                <button className={'pw-chip' + (protections.slow_hash ? ' is-on' : '')} onClick={() => toggle('slow_hash')}>
                  Hachage lent
                </button>
              </div>
            </div>
          </div>

          {protect && <Compare r={protect} />}

          <div className="pw-hash-block">
            <div className="controls">
              <div className="field grow">
                <span className="field-label">Hachage concret du mot de passe (PBKDF2)</span>
                <p className="pw-hint">
                  « Hachage lent » ci-dessus, en vrai : on ne stocke jamais le mot de
                  passe, seulement cette empreinte salée. Chaque essai de l'attaquant
                  coûte alors le temps ci-dessous.
                </p>
              </div>
              <button className="btn" onClick={runHash} disabled={hashing}>{hashing ? '…' : 'Hacher'}</button>
            </div>
            {hash && (
              <div className="hash-card">
                <Row label="Algorithme" value={hash.algo} />
                <Row label="Sel (aléatoire)" value={hash.salt} mono />
                <Row label="Itérations" value={hash.iterations.toLocaleString('fr-FR')} />
                <Row label="Empreinte" value={hash.hash} mono />
                <Row label="Coût / essai" value={`${(hash.secondsPerGuess * 1000).toFixed(1)} ms`} />
              </div>
            )}
          </div>

          <div className="divider" />
          <h3 className="sub-title">Combien de temps, selon la taille et le type</h3>
          <TimeTable fullSize={fullCharset.length} currentLen={length} />
        </>
      ) : (
        <>
          <h3 className="sub-title">Protection d'un si petit espace</h3>
          <p className="panel-sub">
            Avec seulement <strong>{info?.keyspaceText}</strong> combinaisons, aucun
            hachage ne sauve : l'attaquant les épuise quand même. La seule défense qui
            tient, c'est <strong>limiter les tentatives</strong> (verrouillage après
            quelques essais). Les protections par politique (classes, longueur) n'ont
            de sens que sur le mot de passe <em>complexe</em>.
          </p>
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------- sub-components ----
function BruteCard({ res }: { res: BruteResult }) {
  const e = res.estimate
  return (
    <div className={'pw-verdict ' + strengthClass(e.strength)} key={'b' + e.human + res.attempts}>
      <div className="pw-verdict-label">Force brute — temps estimé (attaquant rapide)</div>
      <div className="pw-time">{e.human}</div>
      <div className="pw-verdict-meta">{res.keyspaceText} combinaisons · alphabet {e.alphabet}, longueur {e.length}</div>
      <div className="pw-run">
        {res.found ? (
          <><CheckIcon /> mot de passe trouvé : <strong className="mono">{res.password}</strong> — {res.attempts.toLocaleString('fr-FR')} essais, {fmtMs(res.seconds)}</>
        ) : res.stopped ? (
          <>on a testé {res.attempts.toLocaleString('fr-FR')} combinaisons en direct sans l'atteindre (plafond de la démo) — d'où l'estimation ci-dessus</>
        ) : (
          <>non trouvé ({res.attempts.toLocaleString('fr-FR')} essais)</>
        )}
      </div>
    </div>
  )
}

function DictCard({ res }: { res: DictResult }) {
  return (
    <div className={'pw-verdict ' + (res.found ? 'is-instant' : 'is-fort')} key={'d' + res.attempts}>
      <div className="pw-verdict-label">Dictionnaire (anglais + français, {res.size.toLocaleString('fr-FR')} mots réels)</div>
      <div className="pw-time">{res.found ? 'instantané' : 'résiste au dictionnaire'}</div>
      <div className="pw-run">
        {res.found ? (
          <><CheckIcon /> mot de passe trouvé : <strong className="mono">{res.password}</strong> — mot n°{res.attempts.toLocaleString('fr-FR')} ({fmtMs(res.seconds)})</>
        ) : (
          <>absent des {res.size.toLocaleString('fr-FR')} mots courants testés ({fmtMs(res.seconds)})</>
        )}
      </div>
    </div>
  )
}

function Compare({ r }: { r: ProtectResult }) {
  return (
    <div className="pw-compare">
      <CompareCard title="Sans protection" e={r.unprotected} />
      <div className="pw-compare-mid">
        <div className="pw-arrow">→</div>
        {r.factorText && <div className={'pw-factor ' + r.direction}>{r.factorText}</div>}
      </div>
      <CompareCard title="Avec protection" e={r.protected} highlight />
    </div>
  )
}

function CompareCard({ title, e, highlight }: { title: string; e: Estimate; highlight?: boolean }) {
  return (
    <div className={'pw-cc ' + strengthClass(e.strength) + (highlight ? ' is-highlight' : '')}>
      <div className="pw-cc-title">{title}</div>
      <div className="pw-time small" key={e.human}>{e.human}</div>
      <div className="pw-bar"><span style={{ width: barPct(e.seconds) + '%' }} /></div>
      <div className="pw-cc-meta">
        alphabet {e.alphabet} · longueur {e.length}
        {e.rateNotes && e.rateNotes.length > 0 && <> · {e.rateNotes.join(', ')}</>}
      </div>
    </div>
  )
}

function TimeTable({ fullSize, currentLen }: { fullSize: number; currentLen: number }) {
  const rows = [4, 6, 8, 10, 12, 16]
  const cols = [
    { name: 'Chiffres', sub: '0-9', size: 10 },
    { name: 'Minuscules', sub: 'a-z', size: 26 },
    { name: '+ Majusc.', sub: 'a-z A-Z', size: 52 },
    { name: '+ Chiffres', sub: 'a-z A-Z 0-9', size: 62 },
    { name: '+ Symboles', sub: 'complet', size: fullSize },
  ]
  const nearest = rows.reduce((a, b) => (Math.abs(b - currentLen) < Math.abs(a - currentLen) ? b : a), rows[0])
  return (
    <div className="pw-table-wrap">
      <table className="pw-table">
        <thead>
          <tr>
            <th className="pw-th-len">Longueur</th>
            {cols.map((c) => <th key={c.name}>{c.name}<span className="pw-th-sub">{c.sub}</span></th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((len) => (
            <tr key={len}>
              <th>{len}</th>
              {cols.map((c) => {
                const { label, strength } = compactTime(Math.pow(c.size, len) / 1e10)
                const hot = len === nearest && c.name === '+ Symboles'
                return <td key={c.name} className={strengthClass(strength) + (hot ? ' is-current' : '')}>{label}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="pw-hint">Durée estimée pour épuiser l'espace à ~10 milliards d'essais/s. La case entourée suit ta longueur actuelle.</p>
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="kv">
      <span className="kv-label">{label}</span>
      <span className={'kv-value' + (mono ? ' mono' : '')}>{value}</span>
    </div>
  )
}
