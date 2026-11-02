import CipherPanel from './CipherPanel'
import ExchangePanel from '../exchange/ExchangePanel'
import { t } from '../../i18n'

export type Part = 'simple' | 'exchange'

// L'onglet Chiffrement en deux parties : chiffrer un message (la partie
// d'origine, inchangee) et l'echange entre deux personnes, ou RSA transporte
// l'algorithme et la cle. Les deux restent montees : passer de l'une a l'autre
// ne perd rien. La partie affichee est memorisee dans l'adresse (voir App).
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
