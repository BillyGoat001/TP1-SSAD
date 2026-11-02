// Moteur d'animation de l'echange A ↔ B (Web Animations API, aucune dependance).
// Les « flotteurs » sont des elements poses dans une scene absolue au-dessus des
// cartes : ils volent d'un champ a l'autre, puis disparaissent. React ne touche
// jamais a cette scene, il ne gere que les champs.

export type Pt = { x: number; y: number }
export type Box = Pt & { w: number; h: number }
export type Floater = HTMLDivElement & { _r: number; _s: number; _o: number }
/** Ce que la camera garde a l'ecran : un element, ou seulement ses `h` premiers px (elements tres hauts). */
export type Focus = Element | null | undefined | { el: Element | null | undefined; h: number }

export interface GoOptions {
  s1?: number      // echelle d'arrivee
  r1?: number      // rotation d'arrivee (degres)
  o1?: number      // opacite d'arrivee
  arc?: number     // bosse verticale de la trajectoire (px, negatif = vers le haut)
  arcX?: number    // bosse horizontale
  ms?: number
  ease?: string
}

const LID = 78 // angle du couvercle ouvert (il bascule cote canal)

// Le coffre = la boite publique RSA du destinataire (corps, sangles, serrure, couvercle bombe).
export const CHEST_SVG =
  '<svg viewBox="0 0 24 24"><rect class="ch-mouth" x="4.2" y="9.4" width="15.6" height="2.6" rx="1.2"/>' +
  '<path class="ch-fill" d="M3 11.5h18V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path class="ch-band" d="M7 11.5v9.5M17 11.5v9.5"/>' +
  '<circle class="ch-hole" cx="12" cy="15.2" r="1.6"/><path class="ch-stem" d="M12 16v2.3"/><circle class="ch-glow" cx="12" cy="16" r="3"/>' +
  '<g class="ch-lid"><path class="ch-fill" d="M3 11.5V10.2C3 7.3 7 5.2 12 5.2s9 2.1 9 5v1.3z"/></g></svg>'

// La cle privee, verticale (anneau en haut, panneton en bas) : elle entre dans la serrure.
export const KEY_SVG =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
  '<circle cx="12" cy="5.8" r="3.6"/><path d="M12 9.4V22"/><path d="M12 17.2h3.2M12 20.6h2.6"/></svg>'

export class Fx {
  private stage: HTMLElement
  private speed: () => number

  constructor(stage: HTMLElement, speed: () => number) {
    this.stage = stage
    this.speed = speed
  }

  get reduce(): boolean {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  }
  dur(ms: number) {
    return ms * this.speed()
  }
  wait(ms: number) {
    return new Promise<void>((r) => window.setTimeout(r, this.dur(ms)))
  }
  clear() {
    this.stage.replaceChildren()
  }

  // ---------------------------------------------------------- geometrie ----
  /** Centre (et taille) d'un element, dans le repere de la scene. */
  ctr(el: Element): Box {
    const r = el.getBoundingClientRect()
    const s = this.stage.getBoundingClientRect()
    return { x: r.left - s.left + r.width / 2, y: r.top - s.top + r.height / 2, w: r.width, h: r.height }
  }
  /** Un point pres du haut d'un element haut (la boite floutee peut etre grande). */
  topOf(el: Element, dy: number): Pt {
    const b = this.ctr(el)
    return { x: b.x, y: b.y - b.h / 2 + Math.min(dy, b.h / 2) }
  }
  center(f: Floater): Pt {
    return { x: parseFloat(f.style.left) + f.offsetWidth / 2, y: parseFloat(f.style.top) + f.offsetHeight / 2 }
  }
  private tf(x: number, y: number, r: number, s: number) {
    return `translate(${x}px,${y}px) rotate(${r}deg) scale(${s})`
  }

  // ---------------------------------------------------------- flotteurs ----
  make(cls: string, html = ''): Floater {
    const f = document.createElement('div') as Floater
    f.className = 'ex-float ' + cls
    f.innerHTML = html
    f._r = 0
    f._s = 1
    f._o = 1
    this.stage.appendChild(f)
    return f
  }
  setAt(f: Floater, p: Pt, r = 0, s = 1): Floater {
    f.style.left = p.x - f.offsetWidth / 2 + 'px'
    f.style.top = p.y - f.offsetHeight / 2 + 'px'
    f._r = r
    f._s = s
    f.style.transform = this.tf(0, 0, r, s)
    return f
  }
  fade(f: Floater, o: number): Floater {
    f._o = o
    f.style.opacity = String(o)
    return f
  }
  /** Une etiquette de texte (message, algo, cle) aux couleurs de son auteur. */
  pill(text: string, author: string, cipher: boolean, at: Pt): Floater {
    const f = this.make('ex-item')
    const p = document.createElement('div')
    p.className = `ex-pill ex-from-${author}` + (cipher ? ' is-cipher' : '')
    const t = document.createElement('span')
    t.className = 't'
    t.textContent = text
    p.appendChild(t)
    f.appendChild(p)
    return this.setAt(f, at)
  }
  /** Copie conforme d'un champ (meme taille), pour le faire voyager. */
  clone(el: HTMLElement): Floater {
    const b = this.ctr(el)
    const f = this.make('ex-lift')
    f.style.width = b.w + 'px'
    const c = el.cloneNode(true) as HTMLElement
    c.classList.remove('is-hidden')
    f.appendChild(c)
    return this.setAt(f, b)
  }

  // -------------------------------------------------------- mouvements ----
  /** Vol centre a centre le long d'une courbe, avec echelle, rotation et opacite. */
  go(f: Floater, to: Pt, o: GoOptions = {}): Promise<void> {
    const c = this.center(f)
    const dx = to.x - c.x
    const dy = to.y - c.y
    const s0 = f._s, s1 = o.s1 ?? s0
    const r0 = f._r, r1 = o.r1 ?? r0
    const a0 = f._o, a1 = o.o1 ?? a0
    const cx = dx / 2 + 2 * (o.arcX ?? 0)
    const cy = dy / 2 + 2 * (o.arc ?? 0)
    const kf: Keyframe[] = []
    for (let i = 0; i <= 14; i++) {
      const t = i / 14, m = 1 - t
      kf.push({
        offset: t,
        opacity: a0 + (a1 - a0) * t,
        transform: this.tf(2 * m * t * cx + t * t * dx, 2 * m * t * cy + t * t * dy, r0 + (r1 - r0) * t, s0 + (s1 - s0) * t),
      })
    }
    const commit = () => {
      f.getAnimations().forEach((a) => a.cancel())
      this.setAt(f, to, r1, s1)
      this.fade(f, a1)
    }
    if (this.reduce) {
      commit()
      return Promise.resolve()
    }
    return f
      .animate(kf, { duration: this.dur(o.ms ?? 800), easing: o.ease ?? 'cubic-bezier(.45,0,.25,1)', fill: 'forwards' })
      .finished.then(commit, commit)
  }

  /** Un vrai champ apparait en « pop ». */
  pop(el: Element | null, ms = 440): Promise<void> {
    if (!el || this.reduce) return Promise.resolve()
    return el
      .animate(
        [{ transform: 'scale(.7)', opacity: 0 }, { transform: 'scale(1.05)', offset: 0.7 }, { transform: 'scale(1)', opacity: 1 }],
        { duration: this.dur(ms), easing: 'ease', fill: 'backwards' },
      )
      .finished.then(() => undefined, () => undefined)
  }
  /** Halo bref sur un champ qui vient de recevoir sa valeur. */
  flash(el: Element | null) {
    if (!el || this.reduce) return
    el.classList.remove('is-flash')
    void (el as HTMLElement).offsetWidth
    el.classList.add('is-flash')
  }
  showIn(el: Element | null) {
    if (!el || this.reduce) return
    el.animate([{ opacity: 0, transform: 'scale(.5)' }, { opacity: 1, transform: 'scale(1)' }], {
      duration: this.dur(320),
      easing: 'ease-out',
    })
  }
  // ------------------------------------------------------------- camera ----
  /**
   * Cadre la vue sur l'endroit ou ca se passe. Si tout tient a l'ecran, l'ensemble est centre (et
   * on ne bouge pas si c'est deja bien en vue) ; sinon c'est le DERNIER element — la destination —
   * qui prime. Se resout quand le defilement est termine.
   */
  look(items: Focus[], pad = 22): Promise<void> {
    const rs: { top: number; bottom: number }[] = []
    for (const it of items) {
      const spec = it && 'el' in it ? it : { el: it as Element | null | undefined, h: Infinity }
      if (!spec.el) continue
      const r = spec.el.getBoundingClientRect()
      if (r.width === 0 && r.height === 0) continue // pas affiche (onglet quitte, par exemple)
      rs.push({ top: r.top, bottom: Math.min(r.bottom, r.top + spec.h) })
    }
    if (!rs.length) return Promise.resolve()
    const vh = window.innerHeight
    const top = Math.min(...rs.map((r) => r.top)), bottom = Math.max(...rs.map((r) => r.bottom))
    let d = 0
    if (bottom - top <= vh - 2 * pad) {
      if (top < pad || bottom > vh - pad) d = (top + bottom) / 2 - vh / 2
    } else {
      const last = rs[rs.length - 1]
      if (last.bottom - last.top >= vh - 2 * pad) d = last.top - pad
      else if (last.bottom > vh - pad) d = last.bottom - (vh - pad)
      else if (last.top < pad) d = last.top - pad
    }
    return this.scrollBy(d)
  }
  private scrollBy(d: number): Promise<void> {
    const max = Math.max(0, document.documentElement.scrollHeight - window.innerHeight)
    const from = window.scrollY
    const to = Math.max(0, Math.min(max, from + d))
    if (Math.abs(to - from) < 3) return Promise.resolve()
    if (this.reduce) {
      window.scrollTo(0, to)
      return Promise.resolve()
    }
    window.scrollTo({ top: to, behavior: 'smooth' })
    return new Promise<void>((resolve) => {
      const t0 = performance.now()
      let prev = from, still = 0
      const tick = () => {
        const y = window.scrollY
        still = Math.abs(y - prev) < 0.5 ? still + 1 : 0
        prev = y
        if (Math.abs(y - to) < 1.5 || still >= 8 || performance.now() - t0 > 1500) resolve()
        else requestAnimationFrame(tick)
      }
      requestAnimationFrame(tick)
    })
  }

  // ------------------------------------------------------------- coffre ----
  chest(owner: string): Floater {
    return this.make(`ex-chest ex-from-${owner}`, CHEST_SVG)
  }
  key(owner: string): Floater {
    return this.make(`ex-keyf ex-from-${owner}`, KEY_SVG)
  }
  /** Ouvre / ferme le couvercle, charniere du cote `right` (a l'oppose du trafic). */
  lid(ch: Floater, open: boolean, right = false): Promise<void> {
    const g = ch.querySelector('.ch-lid') as SVGGElement
    if (open) {
      ch.dataset.hinge = right ? 'r' : 'l'
      g.style.transformOrigin = right ? '100% 100%' : '0% 100%'
    }
    const ang = ch.dataset.hinge === 'r' ? LID : -LID
    const a = open ? 0 : ang, b = open ? ang : 0
    const commit = () => {
      g.getAnimations().forEach((x) => x.cancel())
      g.style.transform = `rotate(${b}deg)`
    }
    if (this.reduce) {
      commit()
      return Promise.resolve()
    }
    return g
      .animate([{ transform: `rotate(${a}deg)` }, { transform: `rotate(${b}deg)` }], {
        duration: this.dur(open ? 460 : 300),
        easing: open ? 'cubic-bezier(.3,1.45,.55,1)' : 'cubic-bezier(.55,0,.75,1)',
        fill: 'forwards',
      })
      .finished.then(commit, commit)
  }
  thud(ch: Floater) {
    if (this.reduce) return
    ch.firstElementChild?.animate([{ transform: 'scale(1)' }, { transform: 'scale(1.07,.92)' }, { transform: 'scale(1)' }], {
      duration: this.dur(240),
      easing: 'ease-out',
    })
  }
  glowHole(ch: Floater) {
    if (this.reduce) return
    ch.querySelector('.ch-glow')?.animate(
      [{ opacity: 0, transform: 'scale(.6)' }, { opacity: 0.95, transform: 'scale(1.2)', offset: 0.35 }, { opacity: 0, transform: 'scale(2.4)' }],
      { duration: this.dur(560), easing: 'ease-out' },
    )
  }
  /** La cle tourne dans la serrure (vue de face : elle s'aplatit puis revient). */
  turnKey(k: Floater): Promise<void> {
    const svg = k.firstElementChild
    if (this.reduce || !svg) return Promise.resolve()
    return svg
      .animate([{ transform: 'scaleX(1)' }, { transform: 'scaleX(.14)', offset: 0.5 }, { transform: 'scaleX(1)' }], {
        duration: this.dur(420),
        easing: 'ease-in-out',
      })
      .finished.then(() => undefined, () => undefined)
  }
  mouth(ch: Floater): Pt {
    return { x: this.center(ch).x, y: parseFloat(ch.style.top) + (ch.offsetHeight * 10.6) / 24 }
  }
  hole(ch: Floater): Pt {
    return { x: this.center(ch).x, y: parseFloat(ch.style.top) + (ch.offsetHeight * 15.6) / 24 }
  }
  /** Point d'attente du coffre : a cote du bouton Envoyer, du cote `right` ou gauche. */
  dock(send: Element, card: Element, size: number, right: boolean): Pt {
    const c = this.ctr(card), b = this.ctr(send), R = size / 2 + 8
    const bl = b.x - b.w / 2, br = b.x + b.w / 2, cl = c.x - c.w / 2, cr = c.x + c.w / 2
    return { x: right ? Math.max(br + R, (br + cr) / 2) : Math.min(bl - R, (cl + bl) / 2), y: b.y }
  }
  /** Un element saute puis tombe dans la bouche du coffre (il passe derriere la face avant). */
  async dropIn(f: Floater, ch: Floater) {
    const m = this.mouth(ch), w = f.offsetWidth
    await this.go(f, { x: m.x, y: m.y - 30 }, { s1: Math.min(0.66, 56 / w), arc: -46, ms: 640 })
    await this.go(f, { x: m.x, y: m.y + 15 }, { s1: Math.min(0.38, 36 / w), o1: 0, ms: 260, ease: 'cubic-bezier(.55,0,.9,.55)' })
  }
  /** Un element ressort par la bouche du coffre, contourne le coffre cote oppose au couvercle, et file vers `target`. */
  async popOut(text: string, ch: Floater, author: string, cipher: boolean, target: Element): Promise<Floater> {
    const m = this.mouth(ch)
    const f = this.pill(text, author, cipher, { x: m.x, y: m.y + 15 })
    this.setAt(f, { x: m.x, y: m.y + 15 }, 0, Math.min(0.38, 36 / f.offsetWidth))
    this.fade(f, 0)
    await this.go(f, { x: m.x, y: m.y - 38 }, { s1: 0.85, o1: 1, ms: 320, ease: 'cubic-bezier(.2,.7,.3,1)' })
    await this.go(f, this.ctr(target), { s1: 1, arc: -10, arcX: (ch.dataset.hinge === 'r' ? -1 : 1) * 62, ms: 700 })
    return f
  }
}
