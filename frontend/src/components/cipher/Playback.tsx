// Reusable playback control bar: Reset / Step / Play-Pause + speed slider.

interface Props {
  playing: boolean
  speed: number
  setSpeed: (s: number) => void
  play: () => void
  pause: () => void
  step: () => void
  reset: () => void
  atEnd: boolean
}

export default function Playback({
  playing, speed, setSpeed, play, pause, step, reset, atEnd,
}: Props) {
  return (
    <div className="playback">
      <button className="btn" onClick={reset} title="Revenir au début">⏮ Début</button>
      <button className="btn" onClick={step} disabled={atEnd} title="Étape suivante">
        Étape ⏭
      </button>
      {playing ? (
        <button className="btn btn-accent" onClick={pause}>⏸ Pause</button>
      ) : (
        <button className="btn btn-accent" onClick={play}>▶ Lecture</button>
      )}
      <label className="speed">
        Vitesse
        <input
          type="range" min={0.5} max={4} step={0.5}
          value={speed}
          onChange={(e) => setSpeed(Number(e.target.value))}
        />
        <span className="speed-val">{speed}×</span>
      </label>
    </div>
  )
}
