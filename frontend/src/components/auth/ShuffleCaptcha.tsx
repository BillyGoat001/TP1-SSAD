// Captcha « la clé et les cadenas » : continuité d'un objet dans le temps.
//
// Une clé se montre au-dessus d'un cadenas, se range dedans, puis les cadenas
// s'échangent deux par deux (l'un passe par le haut, l'autre par le bas). Il faut suivre
// des yeux le cadenas qui garde la clé, puis le désigner. Aucune capture d'écran isolée
// ne contient la réponse : elle n'existe que dans la suite des mouvements.
// Tout est décidé par le serveur (quel cadenas, quels échanges, quelles durées) ; la
// page ne fait que jouer l'animation et rapporter l'emplacement choisi.
import { useEffect, useRef, useState } from 'react'
import type { Challenge } from '../../types'
import { t } from '../../i18n'

const GAP = 66

type Phase = 'intro' | 'reveal' | 'hide' | 'shuffle' | 'pick'
type KeyState = 'hidden' | 'up' | 'drop'

const Padlock = () => (
  <svg viewBox="0 0 40 50" className="pad-svg" aria-hidden="true">
    <path className="pad-shackle" d="M11 23V15a9 9 0 0 1 18 0v8" fill="none" strokeWidth="4.6" strokeLinecap="round" />
    <rect className="pad-body" x="3.5" y="22" width="33" height="25" rx="6.5" />
    <circle className="pad-hole" cx="20" cy="32.5" r="3.6" />
    <rect className="pad-hole" x="18.4" y="33" width="3.2" height="8" rx="1.4" />
  </svg>
)

const KeyIcon = () => (
  <svg viewBox="0 0 44 22" className="shuf-key-svg" aria-hidden="true">
    <circle cx="9" cy="11" r="7" fill="none" strokeWidth="3.6" />
    <path d="M16 11h25M33 11v6M39 11v5" fill="none" strokeWidth="3.4" strokeLinecap="round" />
  </svg>
)

export default function ShuffleCaptcha({ ch, onPick, locked, picked }: {
  ch: Challenge
  onPick: (slot: number) => void
  locked: boolean
  picked: number | null
}) {
  const n = ch.slots ?? 5
  const [phase, setPhase] = useState<Phase>('intro')
  const [keyState, setKeyState] = useState<KeyState>('hidden')
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const slotOf = useRef<number[]>(Array.from({ length: n }, (_, i) => i))   // slotOf[cadenas] = emplacement

  useEffect(() => {
    let alive = true
    const anims: Animation[] = []
    const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))
    const at = (slot: number) => `translateX(${slot * GAP}px)`
    slotOf.current = Array.from({ length: n }, (_, i) => i)
    refs.current.forEach((el, i) => { if (el) el.style.transform = at(i) })
    setPhase('intro'); setKeyState('hidden')

    ;(async () => {
      await sleep(550); if (!alive) return
      setPhase('reveal'); setKeyState('up')
      await sleep(ch.reveal_ms ?? 1700); if (!alive) return
      setPhase('hide'); setKeyState('drop')
      await sleep(520); if (!alive) return
      setKeyState('hidden'); setPhase('shuffle')
      await sleep(250)
      let flip = 1
      for (const [a, b, ms] of ch.swaps ?? []) {
        if (!alive) return
        const la = slotOf.current.indexOf(a), lb = slotOf.current.indexOf(b)   // les cadenas qui sont aux emplacements a et b
        const ea = refs.current[la], eb = refs.current[lb]
        if (!ea || !eb) return
        const lift = 24 * flip
        flip = -flip
        const arc = (from: number, to: number, dy: number) => ({
          transform: [at(from), `translate(${((from + to) / 2) * GAP}px, ${dy}px)`, at(to)], offset: [0, 0.5, 1],
        })
        const mk = (el: HTMLElement, from: number, to: number, dy: number) => {
          const k = arc(from, to, dy)
          return el.animate(
            k.transform.map((tr, i) => ({ transform: tr, offset: k.offset[i] })),
            { duration: ms, easing: 'cubic-bezier(.45,.05,.55,.95)', fill: 'forwards' },
          )
        }
        const A = mk(ea, a, b, -lift), B = mk(eb, b, a, lift)
        anims.push(A, B)
        await Promise.all([A.finished, B.finished]).catch(() => undefined)
        if (!alive) return
        ea.style.transform = at(b); eb.style.transform = at(a)
        A.cancel(); B.cancel()
        slotOf.current[la] = b; slotOf.current[lb] = a
      }
      await sleep(200); if (!alive) return
      setPhase('pick')
    })()

    return () => { alive = false; anims.forEach((a) => a.cancel()) }
  }, [ch, n])

  const caption =
    phase === 'intro' ? t('Prépare-toi…')
      : phase === 'reveal' ? t('Mémorise le cadenas qui reçoit la clé.')
        : phase === 'hide' ? t('La clé est rangée.')
          : phase === 'shuffle' ? t('Suis-le des yeux…')
            : t('Où est la clé ? Clique sur le bon cadenas.')

  return (
    <div className={'shuf is-' + phase}>
      <div className="shuf-stage" style={{ width: n * GAP - 12 }}>
        <div className={'shuf-key is-' + keyState} style={{ left: (ch.start ?? 0) * GAP + 2 }} aria-hidden="true"><KeyIcon /></div>
        {Array.from({ length: n }, (_, i) => (
          <button
            key={i} type="button" ref={(el) => { refs.current[i] = el }}
            className={'shuf-lock' + (keyState === 'up' && ch.start === i ? ' is-open' : '') + (picked !== null && slotOf.current[i] === picked ? ' is-picked' : '')}
            style={{ animationDelay: `${i * 70}ms` }}
            disabled={phase !== 'pick' || locked}
            aria-label={t('Cadenas {n}', { n: slotOf.current[i] + 1 })}
            onClick={() => onPick(slotOf.current[i])}
          >
            <Padlock />
          </button>
        ))}
      </div>
      <p className="shuf-caption" aria-live="polite">{caption}</p>
    </div>
  )
}
