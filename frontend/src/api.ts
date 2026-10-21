// Thin client over the FastAPI backend. All crypto logic lives in Python;
// these functions just send inputs and receive results + animation traces.

import type {
  Algo, Operation, CipherResponse, BruteResult, DictResult,
  CasesResponse, ValidateResult, Rules, IntegrityDemo,
  KeygenResponse, ExchangeParams, SealResponse, OpenResponse,
  HistoryEntry, HistoryDraft, ChatRecord, PwHistoryEntry, PwHistoryDraft,
} from './types'

async function post<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return (await res.json()) as T
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url)
  return (await res.json()) as T
}

async function del<T>(url: string): Promise<T> {
  const res = await fetch(url, { method: 'DELETE' })
  return (await res.json()) as T
}

export interface CipherInput {
  algo: Algo
  operation: Operation
  message: string
  shift?: number | string        // un texte de chiffres garde la valeur exacte
  direction?: 'right' | 'left'
  key?: string
  matrix?: (number | string)[][]
  // déchiffrement : métadonnées de mise en forme pour retrouver les espaces
  layout?: [number, string][]
  fillers?: number[]
  jmap?: number[]                // Playfair : positions des J d'origine (J→I)
  cases?: number[]               // positions des minuscules (le chiffré est en majuscules)
}

export const api = {
  cipher: (input: CipherInput) => post<CipherResponse>('/api/cipher', input),

  // Échange A ↔ B : vraie paire de clés RSA, coffre fermé avec la clé publique
  // du destinataire, ouvert avec sa clé privée (tout le calcul est en Python).
  rsaKeygen: (bits: number) => post<KeygenResponse>('/api/rsa/keygen', { bits }),

  exchangeSeal: (params: ExchangeParams, pub: { n: string; e: string }) =>
    post<SealResponse>('/api/exchange/seal', { ...params, n: pub.n, e: pub.e }),

  exchangeOpen: (priv: { n: string; d: string }, blocks: string[]) =>
    post<OpenResponse>('/api/exchange/open', { n: priv.n, d: priv.d, blocks }),

  // limit = limite de tentatives ; rules = politique ; knowComposition = l'attaquant
  // connaît la composition (jeu de caractères restreint) ou suppose le pire cas
  bruteforce: (caseId: string, target: string, length?: number, limit?: number | null, rules?: Rules | null, knowComposition = true) =>
    post<BruteResult>('/api/passwords/bruteforce', { case: caseId, target, length, limit, rules, know_composition: knowComposition }),

  dictionary: (target: string, limit?: number | null) =>
    post<DictResult>('/api/passwords/dictionary', { target, limit }),

  validate: (caseId: string, target: string, length?: number, rules?: Rules | null) =>
    post<ValidateResult>('/api/passwords/validate', { case: caseId, target, length, rules }),

  cases: async () => {
    const res = await fetch('/api/passwords/cases')
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
}
