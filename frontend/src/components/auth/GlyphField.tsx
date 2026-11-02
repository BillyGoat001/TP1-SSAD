// Des caracteres caches dans le fond de la page de connexion : ils n'apparaissent que la
// ou la lumiere du curseur passe. Sous la lumiere ils scintillent, certains changent de
// signe d'un eclair, puis ils retombent dans le noir des que la lumiere s'eloigne.
//
// Un seul <canvas> : on ne dessine que les cases proches de la lumiere (quelques centaines),
// donc le cout reste negligeable. Aucune boucle ne tourne quand l'onglet est cache.
import { useEffect, useRef } from 'react'

const GLYPHS = Array.from('0123456789ABCDEF0123456789ABCDEFGHJKLMNPQRSTUVWXYZ⊕⊗λΣπ∂∞√#$%&@§<>{}[]/\\|=+*~?!')
const CELL_W = 24
const CELL_H = 30
const FONT_PX = 17
const RADIUS = 250                 // rayon de la lumiere, en pixels

type Rgb = [number, number, number]

// « #6d4aff » → [109, 74, 255] (les variables du theme sont des couleurs hexadecimales)
function parseHex(v: string): Rgb | null {
  const m = /^#([0-9a-f]{6})$/i.exec(v.trim())
  if (!m) return null
  const n = parseInt(m[1], 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}
const mix = (a: Rgb, b: Rgb, k: number) => a.map((v, i) => Math.round(v + (b[i] - v) * k)) as Rgb
const css = (c: Rgb) => `rgb(${c[0]},${c[1]},${c[2]})`

export default function GlyphField() {
  const ref = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const cv = ref.current
    const ctx = cv?.getContext('2d')
    if (!cv || !ctx) return
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

    let W = 0, H = 0, cols = 0, rows = 0
    let glyph = new Uint8Array(0), flash = new Float32Array(0)
    let phase = new Float32Array(0), rate = new Float32Array(0), next = new Float32Array(0)
    let tone = css([154, 124, 255]), spark = '#ffffff', font = ''
    let lx = 0, ly = 0, tx = 0, ty = 0          // la lumiere (suit le curseur avec un peu d'inertie)
    let gain = 0.5, targetGain = 0.5            // 0.5 avant le premier geste : la lumiere dort au repos
    let moved = false
    let root: HTMLElement | null = null
    let blocked = false                         // le curseur est sur la carte ou un bouton
    let raf = 0, last = performance.now(), frames = 0

    const readTheme = () => {
      const st = getComputedStyle(document.documentElement)
      const accent = parseHex(st.getPropertyValue('--accent')) ?? [154, 124, 255]
      const dark = document.documentElement.getAttribute('data-theme') === 'dark'
        || (document.documentElement.getAttribute('data-theme') !== 'light' && !!window.matchMedia?.('(prefers-color-scheme: dark)').matches)
      tone = css(accent)
      spark = css(dark ? mix(accent, [255, 255, 255], 0.78) : mix(accent, [18, 8, 60], 0.55))
      font = `600 ${FONT_PX}px ${st.getPropertyValue('--mono').trim() || 'ui-monospace, Menlo, monospace'}`
    }

    const resize = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1)
      W = cv.clientWidth
      H = cv.clientHeight
      cv.width = Math.round(W * dpr)
      cv.height = Math.round(H * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      cols = Math.ceil(W / CELL_W)
      rows = Math.ceil(H / CELL_H)
      const n = cols * rows
      glyph = new Uint8Array(n); flash = new Float32Array(n)
      phase = new Float32Array(n); rate = new Float32Array(n); next = new Float32Array(n)
      for (let i = 0; i < n; i++) {
        glyph[i] = (Math.random() * GLYPHS.length) | 0
        phase[i] = Math.random() * Math.PI * 2
        rate[i] = 1.3 + Math.random() * 3.2
        next[i] = performance.now() / 1000 + Math.random() * 4
      }
      if (!moved) { lx = tx = W * 0.5; ly = ty = H * 0.34 }
    }

    const onMove = (e: PointerEvent) => {
      const r = cv.getBoundingClientRect()
      tx = e.clientX - r.left
      ty = e.clientY - r.top
      // La carte et les boutons (data-blocker) bloquent la lumiere : quand le curseur est dessus,
      // elle s'eteint entierement (halo, grille et caracteres) et revient des qu'il en sort.
      blocked = !!(e.target as Element | null)?.closest?.('[data-blocker]')
      targetGain = blocked ? 0 : 1
      if (root) { if (blocked) root.setAttribute('data-blocked', ''); else root.removeAttribute('data-blocked') }
      if (!moved) { moved = true; lx = tx; ly = ty }
    }
    const onLeave = () => { targetGain = 0 }

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000)
      last = now
      const t = now / 1000
      if (frames++ % 45 === 0) readTheme()
      lx += (tx - lx) * Math.min(1, dt * 14)
      ly += (ty - ly) * Math.min(1, dt * 14)
      gain += (targetGain - gain) * Math.min(1, dt * 5)

      ctx.clearRect(0, 0, W, H)
      if (gain > 0.01) {
        const R = RADIUS * (1 + 0.05 * Math.sin(t * 1.6))   // la lumiere « respire »
        const c0 = Math.max(0, Math.floor((lx - R) / CELL_W)), c1 = Math.min(cols - 1, Math.floor((lx + R) / CELL_W))
        const r0 = Math.max(0, Math.floor((ly - R) / CELL_H)), r1 = Math.min(rows - 1, Math.floor((ly + R) / CELL_H))
        ctx.font = font
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        for (let r = r0; r <= r1; r++) {
          const cy = r * CELL_H + CELL_H / 2
          for (let c = c0; c <= c1; c++) {
            const cx = c * CELL_W + CELL_W / 2
            const dx = cx - lx, dy = cy - ly
            const d2 = dx * dx + dy * dy
            if (d2 >= R * R) continue
            let f = 1 - Math.sqrt(d2) / R
            f = f * f * (3 - 2 * f)                                 // fondu doux vers le bord
            const i = r * cols + c
            if (!reduced && t > next[i]) {                          // la case change de signe d'un eclair
              glyph[i] = (Math.random() * GLYPHS.length) | 0
              next[i] = t + 0.6 + Math.random() * 3.4
              flash[i] = 1
            }
            const fl = flash[i]
            if (fl > 0) flash[i] = Math.max(0, fl - dt * 1.7)
            const tw = reduced ? 0.75 : 0.3 + 0.7 * (0.5 + 0.5 * Math.sin(t * rate[i] + phase[i]))
            const a = (f * tw + fl * f * 0.55) * gain
            if (a < 0.03) continue
            ctx.globalAlpha = Math.min(0.95, a)
            ctx.fillStyle = fl > 0.25 ? spark : tone
            ctx.fillText(GLYPHS[glyph[i]], cx, cy)
          }
        }
        ctx.globalAlpha = 1
      }
      raf = requestAnimationFrame(frame)
    }

    root = cv.closest<HTMLElement>('.login')
    readTheme()
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(cv)
    window.addEventListener('pointermove', onMove, { passive: true })
    window.addEventListener('pointerdown', onMove, { passive: true })
    document.addEventListener('mouseleave', onLeave)
    raf = requestAnimationFrame(frame)
    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerdown', onMove)
      document.removeEventListener('mouseleave', onLeave)
    }
  }, [])

  return <canvas ref={ref} className="glyph-field" aria-hidden="true" />
}
