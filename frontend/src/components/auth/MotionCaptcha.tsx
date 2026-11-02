// Captcha « mouvement » : quatre caracteres caches dans un nuage de points.
//
// Chaque point monte ou descend. A l'interieur des caracteres les points vont dans un
// sens, a l'exterieur dans l'autre. A tout instant, une image fixe est du bruit : les
// points ont partout la meme densite et la meme taille. L'oeil humain, lui, regroupe sans
// effort les points qui bougent ensemble, et lit les caracteres. (Un modele qui regarde
// des captures d'ecran n'a qu'un instant fige du bruit.)
// Une petite part de points bouge au hasard, et chaque point change de place de temps
// en temps : il n'existe aucun « point qui trahit le dessin ».
import { useEffect, useRef } from 'react'
import type { Challenge } from '../../types'

export default function MotionCaptcha({ ch }: { ch: Challenge }) {
  const ref = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const cv = ref.current
    if (!cv || !ch.mask || !ch.width || !ch.height) return
    const W = ch.width, H = ch.height
    const dpr = Math.min(2, window.devicePixelRatio || 1)
    cv.width = W * dpr
    cv.height = H * dpr
    const ctx = cv.getContext('2d')
    if (!ctx) return
    ctx.scale(dpr, dpr)

    // le masque : 1 bit par pixel, range ligne par ligne (160×56, agrandi ×2)
    const { w: mw, h: mh } = ch.mask
    const raw = atob(ch.mask.bits)
    const bit = (i: number) => (raw.charCodeAt(i >> 3) >> (7 - (i & 7))) & 1
    const inside = (x: number, y: number) => {
      const i = Math.min(mh - 1, Math.max(0, (y / 2) | 0)) * mw + Math.min(mw - 1, Math.max(0, (x / 2) | 0))
      return bit(i)
    }
    // Les pixels des deux regions : un point qui change de region n'est pas « bloque » au
    // bord (ca y ferait une file de points, visible sur une image fixe), il reapparait
    // au hasard DANS SA PROPRE region. La densite reste donc identique dedans et dehors :
    // seule la direction du mouvement distingue les caracteres.
    const fgPix: number[] = [], bgPix: number[] = []
    for (let i = 0; i < mw * mh; i++) (bit(i) ? fgPix : bgPix).push(i)
    const fgShare = fgPix.length / (mw * mh)

    const N = ch.dots ?? 2500
    const speed = ch.speed ?? 55
    const fg = ch.fg_dir ?? 1
    const noise = ch.noise ?? 0.12
    const xs = new Float32Array(N), ys = new Float32Array(N)
    const life = new Int16Array(N), reg = new Uint8Array(N), ang = new Float32Array(N), tone = new Uint8Array(N)
    // reg : 1 = dans un caractere, 0 = dehors, 2 = point « fou » (marche au hasard, partout)
    const place = (i: number) => {
      if (reg[i] === 2) { xs[i] = Math.random() * W; ys[i] = Math.random() * H; return }
      const list = reg[i] === 1 ? fgPix : bgPix
      const p = list[(Math.random() * list.length) | 0]
      xs[i] = (p % mw) * 2 + Math.random() * 2
      ys[i] = ((p / mw) | 0) * 2 + Math.random() * 2
    }
    const respawn = (i: number) => {
      reg[i] = Math.random() < noise ? 2 : Math.random() < fgShare ? 1 : 0
      place(i)
      life[i] = 18 + ((Math.random() * 40) | 0)
      ang[i] = Math.random() * Math.PI * 2
      tone[i] = 150 + ((Math.random() * 105) | 0)
    }
    for (let i = 0; i < N; i++) { respawn(i); life[i] = (Math.random() * 40) | 0 }

    let raf = 0
    let last = performance.now()
    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000)
      last = now
      ctx.fillStyle = '#15121f'
      ctx.fillRect(0, 0, W, H)
      for (let i = 0; i < N; i++) {
        if (--life[i] <= 0) respawn(i)
        if (reg[i] === 2) {
          xs[i] += Math.cos(ang[i]) * speed * dt
          ys[i] += Math.sin(ang[i]) * speed * dt
          if (xs[i] < 0) xs[i] += W; else if (xs[i] >= W) xs[i] -= W
          if (ys[i] < 0) ys[i] += H; else if (ys[i] >= H) ys[i] -= H
        } else {
          ys[i] += (reg[i] ? fg : -fg) * speed * dt
          if (ys[i] < 0) ys[i] += H; else if (ys[i] >= H) ys[i] -= H
          if (inside(xs[i], ys[i]) !== reg[i]) place(i)            // sorti de sa region : retour au hasard dedans
        }
        const v = tone[i]
        ctx.fillStyle = `rgb(${v},${v},${Math.min(255, v + 12)})`
        ctx.fillRect(xs[i], ys[i], 2, 2)
      }
      raf = requestAnimationFrame(frame)
    }
    raf = requestAnimationFrame(frame)
    return () => cancelAnimationFrame(raf)
  }, [ch])

  return (
    <canvas
      ref={ref} className="cap-canvas" role="img"
      style={{ width: ch.width, height: ch.height, aspectRatio: `${ch.width} / ${ch.height}` }}
    />
  )
}
