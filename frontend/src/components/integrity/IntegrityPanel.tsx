import { useEffect, useState } from 'react'
import type { IntegrityDemo } from '../../types'
import { api } from '../../api'

// Part 4 — Integrity / Authenticity with HMAC-SHA256.
// A sends (message, tag). The message may be altered in transit. B recomputes
// the tag on what it received and compares: a mismatch reveals the tampering.
export default function IntegrityPanel() {
  const [key, setKey] = useState('cle-partagee')
  const [original, setOriginal] = useState('Virement de 100 DA vers le compte B')
  const [received, setReceived] = useState('Virement de 100 DA vers le compte B')
  const [demo, setDemo] = useState<IntegrityDemo | null>(null)

  useEffect(() => {
    const id = window.setTimeout(() => {
      api.integrityDemo(key, original, received).then(setDemo).catch(() => setDemo(null))
    }, 200)
    return () => window.clearTimeout(id)
  }, [key, original, received])

  const tamper = () => setReceived('Virement de 900 DA vers le compte E')
  const restore = () => setReceived(original)

  return (
    <div className="panel">
      <h2 className="panel-title">Authenticité / Intégrité (HMAC-SHA256)</h2>
      <p className="panel-sub">
        Le chiffrement cache un message mais ne détecte pas qu'on l'a modifié en
        route. Le HMAC ajoute une étiquette calculée à partir du message <em>et</em>{' '}
        d'une clé secrète partagée : si le message change, l'étiquette ne
        correspond plus.
      </p>

      <div className="field">
        <span className="field-label">Clé secrète partagée (A et B)</span>
        <input className="text-input" value={key} onChange={(e) => setKey(e.target.value)} />
      </div>

      <div className="channel">
        <div className="party">
          <div className="party-head">A — expéditeur</div>
          <label className="field-label">Message envoyé</label>
          <textarea className="text-area" rows={2} value={original} onChange={(e) => setOriginal(e.target.value)} />
          <div className="tag-box">
            <span className="tag-label">Étiquette HMAC</span>
            <code className="tag-hex">{demo?.tag ?? '…'}</code>
          </div>
        </div>

        <div className="arrow-col">
          <div className="arrow">→</div>
          <div className="channel-label">canal</div>
          <div className="btn-row vertical">
            <button className="btn tiny" onClick={tamper}>Altérer</button>
            <button className="btn tiny" onClick={restore}>Rétablir</button>
          </div>
        </div>

        <div className="party">
          <div className="party-head">B — destinataire</div>
          <label className="field-label">Message reçu (modifiable)</label>
          <textarea className="text-area" rows={2} value={received} onChange={(e) => setReceived(e.target.value)} />
          <div className="tag-box">
            <span className="tag-label">Étiquette recalculée</span>
            <code className={'tag-hex' + (demo && !demo.valid ? ' bad' : '')}>{demo?.recomputed ?? '…'}</code>
          </div>
        </div>
      </div>

      {demo && (
        <div className={'verdict ' + (demo.valid ? 'ok' : 'bad')}>
          {demo.valid
            ? '✓ Message intègre : les étiquettes correspondent, le message n\'a pas été modifié.'
            : '✗ Message altéré : les étiquettes diffèrent, le message a été modifié en transit.'}
        </div>
      )}
    </div>
  )
}
