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

// Les entiers trop grands pour JavaScript (au-delà de 2^53) arrivent en texte.
type Big = number | string

export interface HillStep {
  blockIndex: number
  rowIndex: number
  row: Big[]
  values: number[]
  terms: [Big, number][]
  sum: Big
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
  matrix: Big[][]
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

// ---- Échange de clés RSA (Partie 2) — voir backend/rsa_crypto.py ----
// Les grands nombres arrivent en texte : un nombre JavaScript perd sa précision au-delà de 2^53.
export interface RsaKey {
  bits: number
  p: string
  q: string
  n: string
  phi: string
  e: string
  d: string
  ms: number
}
export interface KeygenResponse {
  ok: boolean
  error?: string
  key?: RsaKey
}
/** Le « mode d'emploi » d'un message : l'algorithme et sa clé.
 *  Les nombres voyagent en texte pour garder tous leurs chiffres (Python les relit exactement). */
export interface ExchangeParams {
  algo: Algo
  shift?: number | string
  direction?: 'right' | 'left'
  key?: string
  matrix?: (number | string)[][]
}
export interface SealBlock {
  text: string
  m: string
  c: string
}
export interface SealResponse {
  ok: boolean
  error?: string
  payload?: string
  blockBytes?: number
  blocks?: SealBlock[]
}
export interface OpenBlock {
  c: string
  m: string
  text: string
}
export interface OpenResponse {
  ok: boolean
  error?: string
  payload?: string
  blocks?: OpenBlock[]
  params?: ExchangeParams
}

export type Strength = 'instant' | 'faible' | 'moyen' | 'fort' | 'inviolable'

export interface Estimate {
  alphabet: number
  length: number
  keyspace: number | null
  keyspaceText: string
  seconds: number | null
  human: string
  strength: Strength
  rate: number
  rateNotes?: string[]
}

export interface BruteResult {
  ok: boolean
  found: boolean
  stopped: boolean
  password?: string | null
  attempts: number
  seconds: number
  keyspace: number | null
  keyspaceText: string
  charsetSize: number
  length: number
  label: string
  estimate: Estimate
}

export interface DictResult {
  ok: boolean
  found: boolean
  password?: string
  attempts: number
  seconds: number
  size: number
}

export interface ProtectResult {
  ok: boolean
  unprotected: Estimate
  protected: Estimate
  factorText: string | null
  direction: 'longer' | 'shorter' | 'equal'
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
  keyspaceText: string
}

export interface ClassSizes {
  lower: number
  upper: number
  digit: number
  symbol: number
}

export interface Assumptions {
  fastRate: number
  slowHashRate: number
  lockoutAttempts: number
  lockoutWindow: number
  maxAttempts: number
}

export interface CasesResponse {
  ok: boolean
  cases: Record<string, CaseInfo>
  fullCharset: string
  classSizes: ClassSizes
  dictionarySize: number
  assumptions: Assumptions
}

export interface Protections {
  require_lower: boolean
  require_upper: boolean
  require_digit: boolean
  require_symbol: boolean
  min_length: number | null
  limit_attempts: boolean
  slow_hash: boolean
}

export interface IntegrityDemo {
  ok: boolean
  tag: string
  recomputed: string
  tampered: boolean
  valid: boolean
}
