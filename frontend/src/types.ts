// Shapes returned by the Python backend (see backend/traces.py).

export type Operation = 'encrypt' | 'decrypt'
export type Algo = 'caesar' | 'playfair' | 'hill'

export interface CaesarStep {
  type: 'map' | 'skip'
  char: string
  out?: string
  index?: number
}
export interface CaesarTrace {
  kind: 'caesar'
  shift: number
  alphabetIn: string[]
  alphabetOut: string[]
  steps: CaesarStep[]
  result: string
}

export interface PlayfairStep {
  a: string
  b: string
  rule: 'row' | 'col' | 'rect'
  aPos: [number, number]
  bPos: [number, number]
  outA: string
  outB: string
  outAPos: [number, number]
  outBPos: [number, number]
}
export interface PlayfairTrace {
  kind: 'playfair'
  grid: string[][]
  steps: PlayfairStep[]
  result: string
}

export interface HillStep {
  blockIndex: number
  rowIndex: number
  row: number[]
  values: number[]
  terms: [number, number][]
  sum: number
  mod: number
  outChar: string
  outIndex: number
}
export interface HillBlock {
  letters: string[]
  values: number[]
}
export interface HillTrace {
  kind: 'hill'
  n: number
  matrix: number[][]
  cleaned: string
  blocks: HillBlock[]
  steps: HillStep[]
  result: string
}

export type Trace = CaesarTrace | PlayfairTrace | HillTrace

export interface CipherResponse {
  ok: boolean
  error?: string
  result?: string
  warning?: string | null
  trace?: Trace
}

export interface BruteResult {
  ok: boolean
  found: boolean
  password?: string
  attempts: number
  seconds: number
  keyspace: number
  label: string
  stopped: boolean
}

export interface DictResult {
  ok: boolean
  found: boolean
  password?: string
  attempts: number
  seconds: number
  size: number
}

export interface HashResult {
  ok: boolean
  algo: string
  salt: string
  iterations: number
  hash: string
  secondsPerGuess: number
}

export interface CaseInfo {
  label: string
  charset: string
  length: number
  keyspace: number
}

export interface IntegrityDemo {
  ok: boolean
  tag: string
  recomputed: string
  tampered: boolean
  valid: boolean
}
