// Thin client over the FastAPI backend. All crypto logic lives in Python;
// these functions just send inputs and receive results + animation traces.

import type {
  Algo, Operation, CipherResponse, BruteResult, DictResult, HashResult,
  CasesResponse, ProtectResult, Protections, IntegrityDemo,
  KeygenResponse, ExchangeParams, SealResponse, OpenResponse,
} from './types'

async function post<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
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

  bruteforce: (caseId: string, target: string, length?: number) =>
    post<BruteResult>('/api/passwords/bruteforce', { case: caseId, target, length }),

  dictionary: (target: string) =>
    post<DictResult>('/api/passwords/dictionary', { target }),

  protect: (password: string, protections: Protections) =>
    post<ProtectResult>('/api/passwords/protect', { password, ...protections }),

  hashPassword: (password: string) =>
    post<HashResult>('/api/passwords/hash', { password }),

  cases: async () => {
    const res = await fetch('/api/passwords/cases')
    return (await res.json()) as CasesResponse
  },

  integrityDemo: (key: string, original: string, received: string) =>
    post<IntegrityDemo>('/api/integrity/demo', { key, original, received }),
}
