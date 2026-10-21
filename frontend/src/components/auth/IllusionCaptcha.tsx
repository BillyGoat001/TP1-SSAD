// Captcha « illusion de contour » : quatre caractères dessinés par des rayures.
//
// Dans les caractères, les rayures sont décalées d'une demi-période (et un peu penchées).
// La couleur moyenne est la même partout : réduite ou floutée, l'image n'est qu'un aplat.
// À taille réelle, l'œil humain voit une rupture le long du contour des lettres et la
// complète, comme dans l'illusion du contour de Kanizsa. L'image est affichée à sa taille
// exacte, sans lissage : l'agrandir ou la réduire ferait disparaître l'effet.
import type { Challenge } from '../../types'

export default function IllusionCaptcha({ ch }: { ch: Challenge }) {
  return (
    <div className="cap-illusion">
      <img
        src={ch.image} width={ch.width} height={ch.height} alt="" draggable={false}
        style={{ imageRendering: 'pixelated' }}
      />
    </div>
  )
}
