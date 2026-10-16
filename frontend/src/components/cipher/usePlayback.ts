import { useEffect, useRef, useState } from 'react'

// Drives a step-by-step animation: an index from -1 (nothing shown) to total-1
// (everything shown). Play / pause / step / reset, with an adjustable speed.
export function usePlayback(total: number) {
  const [index, setIndex] = useState(total - 1) // start fully revealed (tool at rest)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const timer = useRef<number | null>(null)

  // A new trace (different length) resets the view to the final state.
  useEffect(() => {
    setIndex(total - 1)
    setPlaying(false)
  }, [total])

  useEffect(() => {
    if (!playing) return
    if (index >= total - 1) {
      setPlaying(false)
      return
    }
    const delay = 950 / speed
    timer.current = window.setTimeout(
      () => setIndex((i) => Math.min(i + 1, total - 1)),
      delay,
    )
    return () => {
      if (timer.current) window.clearTimeout(timer.current)
    }
  }, [playing, index, total, speed])

  const play = () => {
    if (index >= total - 1) setIndex(-1) // replay from the start
    setPlaying(true)
  }
  const pause = () => setPlaying(false)
  const step = () => {
    setPlaying(false)
    setIndex((i) => Math.min(i + 1, total - 1))
  }
  const reset = () => {
    setPlaying(false)
    setIndex(-1)
  }

  return { index, playing, speed, setSpeed, play, pause, step, reset }
}
