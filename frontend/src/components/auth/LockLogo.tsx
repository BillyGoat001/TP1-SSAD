// Le logo de la page de connexion : le bouclier + cadenas de l'appli, anime.
//   idle      repos : le cadenas respire, un halo pulse doucement
//   checking  verification : un anneau en pointilles tourne autour du logo
//   error     refus : le logo tremble et le bouclier rougit un instant
//   open      acces accorde : l'anse se leve et pivote, le trou de serrure passe au vert,
//             deux ondes et quelques etincelles partent du bouclier
export type LockState = 'idle' | 'checking' | 'error' | 'open'

const SPARKS = 10

export default function LockLogo({ state }: { state: LockState }) {
  return (
    <div className={'lock-mark is-' + state} aria-hidden="true">
      <span className="lock-ring" />
      <span className="lock-wave w1" />
      <span className="lock-wave w2" />
      <svg className="lock-scan" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="47" fill="none" strokeWidth="2.2" strokeLinecap="round" strokeDasharray="22 14 5 14" />
      </svg>
      <span className="lock-tile">
        <svg viewBox="3 1.5 18 21.2" className="lock-svg">
          <path className="lk-shield" fill="currentColor" d="M12 1.8 3.5 4.6V11c0 5.4 3.5 9.4 8.5 11.4 5-2 8.5-6 8.5-11.4V4.6z" />
          <path className="lk-inner" d="M12 3.9 5.6 6.1V11c0 4.2 2.6 7.4 6.4 9.2 3.8-1.8 6.4-5 6.4-9.2V6.1z" />
          <path className="lk-shackle" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"
                d="M10.2 10.6V9.3a1.8 1.8 0 0 1 3.6 0v1.3" />
          <rect className="lk-body" x="9" y="10.6" width="6" height="4.8" rx="1" fill="currentColor" />
          <circle className="lk-hole" cx="12" cy="12.6" r="0.8" />
          <rect className="lk-hole" x="11.65" y="12.9" width="0.7" height="1.5" rx="0.3" />
        </svg>
      </span>
      {Array.from({ length: SPARKS }, (_, i) => (
        <i key={i} className="lock-spark" style={{ ['--a' as string]: `${(360 / SPARKS) * i + (i % 2 ? 12 : -6)}deg`, ['--d' as string]: `${i % 3 === 0 ? 74 : 62}px` }} />
      ))}
    </div>
  )
}
