import { useEffect, useState } from 'react'
import type { BruteResult, DictResult, HashResult, CaseInfo } from '../../types'
import { api } from '../../api'

const SAMPLE: Record<string, string> = { bin3: '101', num4: '2413', full: 'Rba+' }

export default function PasswordsPanel() {
  const [cases, setCases] = useState<Record<string, CaseInfo> | null>(null)
  const [caseId, setCaseId] = useState('bin3')
  const [target, setTarget] = useState('101')
  const [length, setLength] = useState(4)
  const [brute, setBrute] = useState<BruteResult | null>(null)
  const [dict, setDict] = useState<DictResult | null>(null)
  const [busy, setBusy] = useState(false)

  const [pwd, setPwd] = useState('sunshine')
  const [hash, setHash] = useState<HashResult | null>(null)

  useEffect(() => {
    api.cases().then((r) => setCases(r.cases)).catch(() => setCases(null))
  }, [])

  const pickCase = (id: string) => {
    setCaseId(id)
    setTarget(SAMPLE[id] ?? '')
    setBrute(null)
    setDict(null)
  }

  const runBrute = async () => {
    setBusy(true)
    setBrute(null)
    try {
      setBrute(await api.bruteforce(caseId, target, caseId === 'full' ? length : undefined))
    } finally {
      setBusy(false)
    }
  }

  const runDict = async () => {
    setBusy(true)
    setDict(null)
    try {
      setDict(await api.dictionary(target))
    } finally {
      setBusy(false)
    }
  }

  const runHash = async () => setHash(await api.hashPassword(pwd))

  const info = cases?.[caseId]

  return (
    <div className="panel">
      <h2 className="panel-title">Mots de passe — attaques &amp; protection</h2>
      <p className="panel-sub">
        On attaque les trois cas de l'énoncé, puis on montre la bonne défense.
        Les attaques et le hachage tournent côté Python.
      </p>

      <div className="field">
        <span className="field-label">Cas</span>
        <div className="segmented">
          {['bin3', 'num4', 'full'].map((id) => (
            <button key={id} className={'seg' + (caseId === id ? ' is-on' : '')} onClick={() => pickCase(id)}>
              {id === 'bin3' ? '3× {0,1}' : id === 'num4' ? '4× {1..4}' : 'a-z A-Z 0-9 +*'}
            </button>
          ))}
        </div>
      </div>

      {info && (
        <div className="keyspace-badge">
          Espace de clés : <strong>{info.keyspace.toLocaleString('fr-FR')}</strong> combinaisons
          {caseId === 'full' && <span className="muted"> (longueur {length})</span>}
        </div>
      )}

      <div className="controls">
        <div className="field grow">
          <span className="field-label">Mot de passe cible</span>
          <input className="text-input" value={target} onChange={(e) => setTarget(e.target.value)} />
        </div>
        {caseId === 'full' && (
          <div className="field">
            <span className="field-label">Longueur</span>
            <div className="segmented">
              {[3, 4].map((l) => (
                <button key={l} className={'seg' + (length === l ? ' is-on' : '')} onClick={() => setLength(l)}>
                  {l}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="btn-row">
        <button className="btn btn-accent" onClick={runBrute} disabled={busy}>Force brute</button>
        <button className="btn" onClick={runDict} disabled={busy}>Dictionnaire</button>
      </div>

      {brute && (
        <div className={'attack-card ' + (brute.found ? 'cracked' : 'safe')}>
          <div className="attack-head">Force brute — {brute.found ? 'MOT DE PASSE TROUVÉ' : brute.stopped ? 'arrêtée (trop de combinaisons)' : 'non trouvé'}</div>
          <div className="attack-stats">
            <Stat label="Essais" value={brute.attempts.toLocaleString('fr-FR')} />
            <Stat label="Temps" value={fmtTime(brute.seconds)} />
            <Stat label="Espace" value={brute.keyspace.toLocaleString('fr-FR')} />
          </div>
        </div>
      )}

      {dict && (
        <div className={'attack-card ' + (dict.found ? 'cracked' : 'safe')}>
          <div className="attack-head">Dictionnaire — {dict.found ? 'TROUVÉ' : 'absent du dictionnaire'}</div>
          <div className="attack-stats">
            <Stat label="Essais" value={String(dict.attempts)} />
            <Stat label="Temps" value={fmtTime(dict.seconds)} />
            <Stat label="Taille dict." value={String(dict.size)} />
          </div>
        </div>
      )}

      <div className="divider" />

      <h3 className="sub-title">Protection</h3>
      <p className="panel-sub">
        Un hachage lent et salé (PBKDF2) rend chaque essai coûteux. Mais pour les
        cas minuscules (8 ou 256 combinaisons), aucun hachage ne suffit : seule la
        <strong> limitation des tentatives</strong> protège vraiment.
      </p>
      <div className="controls">
        <div className="field grow">
          <span className="field-label">Mot de passe à protéger</span>
          <input className="text-input" value={pwd} onChange={(e) => setPwd(e.target.value)} />
        </div>
        <button className="btn btn-accent" onClick={runHash}>Hacher (PBKDF2)</button>
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
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <div className="stat-val">{value}</div>
      <div className="stat-label">{label}</div>
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

function fmtTime(s: number): string {
  if (s < 1e-3) return `${(s * 1e6).toFixed(0)} µs`
  if (s < 1) return `${(s * 1e3).toFixed(1)} ms`
  return `${s.toFixed(2)} s`
}
