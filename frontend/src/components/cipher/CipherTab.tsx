import CipherPanel from './CipherPanel'
import ExchangePanel from '../exchange/ExchangePanel'
import { t } from '../../i18n'

export type Part = 'simple' | 'exchange'

// L'onglet Chiffrement en deux parties : chiffrer un message (la partie
// d'origine, inchangée) et l'échange entre deux personnes, où RSA transporte
// l'algorithme et la clé. Les deux restent montées : passer de l'une à l'autre
// ne perd rien. La partie affichée est mémorisée dans l'adresse (voir App).
export default function CipherTab({ part, onPart }: { part: Part; onPart: (p: Part) => void }) {
  return (
    <div className="cipher-tab">
      <div className="subtabs" role="tablist" aria-label={t('Parties du chiffrement')}>
        <button
          role="tab" aria-selected={part === 'simple'}
          className={'subtab' + (part === 'simple' ? ' is-active' : '')}
          onClick={() => onPart('simple')}
        >
          {t('Chiffrer un message')}
        </button>
        <button
          role="tab" aria-selected={part === 'exchange'}
          className={'subtab' + (part === 'exchange' ? ' is-active' : '')}
          onClick={() => onPart('exchange')}
        >
          {t('Échange entre deux personnes')}
        </button>
      </div>

      <div hidden={part !== 'simple'}>
        <CipherPanel />
      </div>
      <div hidden={part !== 'exchange'}>
        <ExchangePanel active={part === 'exchange'} />
      </div>
    </div>
  )
}
