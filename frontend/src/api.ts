// Thin client over the FastAPI backend. All crypto logic lives in Python;
// these functions just send inputs and receive results + animation traces.

import type {
  Algo, Operation, CipherResponse, BruteResult, DictResult,
  CasesResponse, ValidateResult, Rules, IntegrityDemo,
  KeygenResponse, ExchangeParams, SealResponse, OpenResponse,
  HistoryEntry, HistoryDraft, ChatRecord, PwHistoryEntry, PwHistoryDraft,
  Challenge, LoginResult, AuthStatus, AttackStartInput, AttackSnapshot,
  CipherRecord, IntegritySealResult, IntegrityOpenResult,
} from './types'

// Session expiree (le serveur repond 401) : l'appli revient sur la page de connexion.
let onUnauthorized: (() => void) | null = null
export const setUnauthorizedHandler = (fn: (() => void) | null) => { onUnauthorized = fn }
const guard = (res: Response) => { if (res.status === 401) onUnauthorized?.() }

async function post<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  guard(res)
  return (await res.json()) as T
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url)
  guard(res)
  return (await res.json()) as T
}

async function del<T>(url: string): Promise<T> {
  const res = await fetch(url, { method: 'DELETE' })
  guard(res)
  return (await res.json()) as T
}

interface AuthPayload {
  username: string; password: string; captcha_id: string; answer: string | number; nonce: number
  human: { ms: number; events: number }
}

async function sendAuth(url: string, payload: AuthPayload): Promise<LoginResult> {
  const res = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  })
  let body: Partial<LoginResult> = {}
  try { body = await res.json() } catch { /* reponse vide */ }
  return { ok: false, ...body, status: res.status } as LoginResult
}

export interface CipherInput {
  algo: Algo
  operation: Operation
  message: string
  shift?: number | string        // un texte de chiffres garde la valeur exacte
  direction?: 'right' | 'left'
  key?: string
  matrix?: (number | string)[][]
  // dechiffrement : metadonnees de mise en forme pour retrouver les espaces
  layout?: [number, string][]
  fillers?: number[]
  jmap?: number[]                // Playfair : positions des J d'origine (J→I)
  cases?: number[]               // positions des minuscules (le chiffre est en majuscules)
}

export const api = {
  // ---- connexion (le cookie de session est HttpOnly : le JavaScript ne le voit jamais)
  authStatus: async () => (await (await fetch('/api/auth/status')).json()) as AuthStatus,
  authCaptcha: async (exclude?: string) => {
    const res = await fetch('/api/auth/captcha' + (exclude ? `?exclude=${encodeURIComponent(exclude)}` : ''))
    const body = await res.json()
    if (!res.ok || !body.ok) throw new Error(body.error || 'captcha')
    return body.challenge as Challenge
  },
  // le defi est abandonne (fenetre fermee, defi remplace) : le serveur le detruit
  authDiscard: (id: string) => {
    try {
      void fetch('/api/auth/captcha/discard', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }), keepalive: true,
      }).catch(() => undefined)
    } catch { /* ignore */ }
  },
  login: (payload: AuthPayload) => sendAuth('/api/auth/login', payload),
  // inscription : memes champs et memes protections que la connexion
  register: (payload: AuthPayload) => sendAuth('/api/auth/register', payload),
  logout: async () => { try { await fetch('/api/auth/logout', { method: 'POST' }) } catch { /* ignore */ } },

  cipher: (input: CipherInput) => post<CipherResponse>('/api/cipher', input),

  // Echange A ↔ B : vraie paire de cles RSA, coffre ferme avec la cle publique
  // du destinataire, ouvert avec sa cle privee (tout le calcul est en Python).
  rsaKeygen: (bits: number) => post<KeygenResponse>('/api/rsa/keygen', { bits }),

  exchangeSeal: (params: ExchangeParams, pub: { n: string; e: string }) =>
    post<SealResponse>('/api/exchange/seal', { ...params, n: pub.n, e: pub.e }),

  exchangeOpen: (priv: { n: string; d: string }, blocks: string[]) =>
    post<OpenResponse>('/api/exchange/open', { n: priv.n, d: priv.d, blocks }),

  // limit = limite de tentatives ; rules = politique ; knowComposition = l'attaquant
  // connait la composition (jeu de caracteres restreint) ou suppose le pire cas
  bruteforce: (caseId: string, target: string, length?: number, limit?: number | null, rules?: Rules | null, knowComposition = true) =>
    post<BruteResult>('/api/passwords/bruteforce', { case: caseId, target, length, limit, rules, know_composition: knowComposition }),

  dictionary: (target: string, limit?: number | null) =>
    post<DictResult>('/api/passwords/dictionary', { target, limit }),

  // attaque en tache de fond : vraie boucle cote serveur, a relire par polling
  // (attackProgress) pour une barre de progression REELLE, interruptible pour de
  // vrai (attackStop coupe le thread, pas seulement l'affichage).
  attackStart: (input: AttackStartInput) =>
    post<AttackSnapshot>('/api/passwords/attack/start', {
      kind: input.kind, case: input.caseId, target: input.target, length: input.length,
      limit: input.limit, rules: input.rules, know_composition: input.knowComposition, lang: input.lang,
    }),
  attackProgress: (id: string) => get<AttackSnapshot>(`/api/passwords/attack/progress/${id}`),
  attackStop: (id: string) => post<{ ok: boolean; stopped: boolean }>(`/api/passwords/attack/stop/${id}`, {}),

  validate: (caseId: string, target: string, length?: number, rules?: Rules | null) =>
    post<ValidateResult>('/api/passwords/validate', { case: caseId, target, length, rules }),

  cases: async () => {
    const res = await fetch('/api/passwords/cases')
    guard(res)
    return (await res.json()) as CasesResponse
  },

  // Fichiers du backend : l'historique des chiffrements et la conversation A ↔ B
  historyList: () => get<{ ok: boolean; entries: HistoryEntry[] }>('/api/history'),
  historyAdd: (entry: HistoryDraft) => post<{ ok: boolean; entry: HistoryEntry }>('/api/history', entry),
  historyRemove: (id: number) => del<{ ok: boolean; deleted: boolean }>(`/api/history/${id}`),
  historyClear: () => del<{ ok: boolean; deleted: number }>('/api/history'),
  pwHistoryList: () => get<{ ok: boolean; entries: PwHistoryEntry[] }>('/api/pw-history'),
  pwHistoryAdd: (entry: PwHistoryDraft) => post<{ ok: boolean; entry: PwHistoryEntry }>('/api/pw-history', entry),
  pwHistoryRemove: (id: number) => del<{ ok: boolean; deleted: boolean }>(`/api/pw-history/${id}`),
  pwHistoryClear: () => del<{ ok: boolean; deleted: number }>('/api/pw-history'),
  conversationList: () => get<{ ok: boolean; messages: ChatRecord[] }>('/api/conversation'),
  conversationClear: () => del<{ ok: boolean; deleted: number }>('/api/conversation'),
  conversationAdd: (msg: ChatRecord) => post<{ ok: boolean; duplicate: boolean }>('/api/conversation', msg),

  integrityDemo: (key: string, original: string, received: string) =>
    post<IntegrityDemo>('/api/integrity/demo', { key, original, received }),

  // canal A -> B reel : A chiffre (algo tire au hasard) + signe le clair ; B ouvre
  // ce qui est arrive (potentiellement altere par C dans record.secret) et, si la
  // protection est active, verifie l'etiquette.
  integritySeal: (key: string, message: string, encrypt: boolean) =>
    post<IntegritySealResult>('/api/integrity/seal', { key, message, encrypt }),
  integrityOpen: (key: string, record: CipherRecord, protect: boolean, tag: string | null) =>
    post<IntegrityOpenResult>('/api/integrity/open', { key, record, protect, tag }),
}
