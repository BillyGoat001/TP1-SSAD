// Captcha « illusion de contour » : quatre caracteres dessines par des rayures.
//
// Dans les caracteres, les rayures sont decalees d'une demi-periode (et un peu penchees).
// La couleur moyenne est la meme partout : reduite ou floutee, l'image n'est qu'un aplat.
// A taille reelle, l'oeil humain voit une rupture le long du contour des lettres et la
// complete, comme dans l'illusion du contour de Kanizsa. L'image est affichee a sa taille
// exacte, sans lissage : l'agrandir ou la reduire ferait disparaitre l'effet.
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
