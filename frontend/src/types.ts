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

// Les entiers trop grands pour JavaScript (au-dela de 2^53) arrivent en texte.
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

// Mise en forme renvoyee au chiffrement, a reporter au dechiffrement pour
// retrouver les espaces : layout = [position, caractere] des non-lettres ;
// fillers = positions des X ajoutes par Playfair/Hill.
export type Layout = [number, string][]

export interface CipherResponse {
  ok: boolean
  error?: string
  result?: string
  warning?: string | null
  trace?: Trace
  layout?: Layout
  fillers?: number[]
  jmap?: number[]
  cases?: number[]         // positions des lettres ecrites en minuscules
  time_us?: number | null  // temps de calcul de l'algorithme, en microsecondes
}

// ---- Echange de cles RSA (Partie 2) — voir backend/rsa_crypto.py ----
// Les grands nombres arrivent en texte : un nombre JavaScript perd sa precision au-dela de 2^53.
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
/** Le « mode d'emploi » d'un message : l'algorithme et sa cle.
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

// Politique appliquee au mot de passe complexe (chaque regle active = condition
// de validite). min_length = null quand la regle de longueur est desactivee.
export interface Rules {
  require_lower: boolean
  require_upper: boolean
  require_digit: boolean
  require_symbol: boolean
  min_length: number | null
}

export interface ValidateResult {
  ok: boolean
  valid: boolean
  reasons: string[]       // ce qui manque (vide si valide)
}

// Force brute : le backend donne les faits (espace, rang exact de la cible,
// estimation pire-cas) ; le front anime la progression. rank = numero d'essai
// auquel on tombe sur la cible (peut etre un tres grand entier -> string).
export interface BruteResult {
  ok: boolean
  error?: string
  valid: boolean
  reasons: string[]
  charset: string
  charsetSize: number
  length: number
  label: string
  keyspace: number | null
  keyspaceText: string
  rate: number
  rateText: string
  worstCaseSeconds: number | null
  worstCaseHuman: string
  strength: Strength
  rank: number | string | null   // essais pour atteindre la cible
  findSeconds: number | null      // temps pour atteindre la cible
  findHuman: string | null
  findStrength: Strength | null
  reallyLooped: boolean           // true = boucle reelle (petit espace)
  limit: number | null            // limite de tentatives active
  cracked: boolean
}

export interface DictResult {
  ok: boolean
  found: boolean
  stopped: boolean                // arrete par la limite de tentatives
  password?: string
  position: number | null         // rang du mot trouve
  scanned: number                 // mots reellement parcourus
  size: number                    // taille totale du dictionnaire
  limit: number | null
}

// Attaque en tache de fond (force brute « complexe » + dictionnaire) : le serveur
// boucle pour de vrai, la progression est relue par polling (attackProgress).
export interface AttackStartInput {
  kind: 'brute' | 'dict'
  caseId?: string
  target: string
  length?: number
  limit?: number | null
  rules?: Rules | null
  knowComposition?: boolean
  lang?: 'fr' | 'en'          // ordre de lecture du dictionnaire (langue de l'interface en tete)
}

export interface AttackSnapshot {
  ok: boolean
  error?: string
  id: string
  pos: number                 // essais / mots REELLEMENT parcourus jusqu'ici
  total: number                // taille de l'espace / du dictionnaire
  done: boolean
  elapsed: number               // secondes REELLES ecoulees depuis le depart
  rate: number                   // essais/s REELS observes (pos ÷ elapsed)
  result: (Omit<BruteResult, 'ok' | 'error'> | Omit<DictResult, 'ok'>) | null
}

export interface SpeedTable {
  columns: { name: string; detail: string; size: number }[]
  rows: { length: number; cells: { human: string; strength: Strength }[] }[]
  rate: number
  rateText: string
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
  fastRateText: string
  liveLoopMax: number
}

export interface CasesResponse {
  ok: boolean
  cases: Record<string, CaseInfo>
  fullCharset: string
  classSizes: ClassSizes
  dictionarySize: number
  table: SpeedTable
  assumptions: Assumptions
}

export interface IntegrityDemo {
  ok: boolean
  tag: string
  recomputed: string
  tampered: boolean
  valid: boolean
}

// ---- canal A -> B reel (voir backend/integrity.py : seal / open_channel) ----
// Le message est vraiment chiffre (Cesar/Playfair/Hill tires au hasard, comme
// pour un mot de passe) ; `record.secret` EST le chiffre — c'est lui que
// l'attaquant C peut modifier avant que B n'ouvre le canal.
export interface CipherRecordKey {
  shift?: number          // Cesar
  key?: string            // Playfair
  matrix?: number[][]     // Hill
}
export interface CipherRecord {
  method: Algo | null             // null = le message a voyage EN CLAIR (chiffrement desactive)
  key: CipherRecordKey
  secret: string                 // ce qui « voyage » — modifiable par C pour simuler une alteration
  layout: [number, string][]
  fillers: number[]
  jmap: number[]
  cases: number[]
}
export interface IntegritySealResult {
  ok: boolean
  error?: string
  tag: string             // etiquette HMAC calculee sur le CLAIR, avant chiffrement
  record: CipherRecord
}
export interface IntegrityOpenResult {
  ok: boolean
  error?: string
  decrypted: string | null
  valid: boolean | null    // null si la protection est desactivee (aucune verification faite)
  recomputed: string | null
  broken: boolean          // dechiffrement impossible (ex. longueur invalide apres alteration)
}

// ---- Fichiers de stockage (voir backend/storage.py) ----
// Une ligne de l'historique des chiffrements : une operation reussie.
export interface HistoryEntry {
  id: number          // numero attribue par le backend (negatif = ligne non enregistree, gardee a l'ecran seulement)
  at?: string         // date d'enregistrement (ISO)
  op: Operation
  clear: string       // message clair
  cipher: string      // message chiffre
  algo: Algo
  algoLabel: string
  key: string         // la cle, en texte lisible
  timeUs: number | null // temps de calcul de l'algorithme, en microsecondes
}
export type HistoryDraft = Omit<HistoryEntry, 'id' | 'at'>

// Une ligne de l'historique des attaques (page Mots de passe) : une attaque terminee ou interrompue.
export type PwResult = 'found' | 'blocked' | 'resist' | 'interrupted'
export interface PwHistoryEntry {
  id: number          // negatif = ligne non enregistree (backend injoignable), gardee a l'ecran seulement
  at?: string
  attack: 'brute' | 'dict'
  case: 'binaire' | 'numerique' | 'complexe'
  password: string
  protection: string  // « Aucune », « 5 tentatives max »…
  result: PwResult
  tries: number       // essais effectues
  timeSec: number     // duree de l'attaque a la vitesse de l'attaquant (secondes)
}
export type PwHistoryDraft = Omit<PwHistoryEntry, 'id' | 'at'>

// Un message de la conversation A ↔ B, tel qu'il est range dans son fichier.
export interface ChatRecord {
  id: number
  at?: string
  from: 'a' | 'b'
  plain: string
  cipher: string
  params: ExchangeParams
}

// ---- connexion et captcha (voir backend/captcha.py)
export type CaptchaKind = 'motion' | 'illusion' | 'shuffle'
export interface Challenge {
  id: string
  kind: CaptchaKind
  ttl: number                                   // secondes de validite
  prompt: string                                // la consigne, en francais
  pow: { challenge: string; bits: number }      // la preuve de travail a fournir
  // motion : un nuage de points dont le mouvement dessine 4 caracteres
  width?: number; height?: number
  mask?: { w: number; h: number; bits: string }
  fg_dir?: number; speed?: number; dots?: number; noise?: number
  // illusion : une image de rayures
  image?: string
  // shuffle : la cle et les cadenas
  slots?: number; start?: number; swaps?: [number, number, number][]; reveal_ms?: number
}
export interface LoginResult {
  ok: boolean
  status: number
  user?: string
  error?: 'captcha' | 'credentials' | 'locked' | 'blocked' | 'setup' | 'exists' | 'username' | 'policy' | string
  reason?: string
  message?: string
  retry_after?: number
  remaining?: number            // mots de passe errones encore permis avant le blocage du compte
}
export interface AuthStatus {
  ok: boolean
  authenticated: boolean
  user: string | null
  auth_required: boolean
  configured: boolean
}
