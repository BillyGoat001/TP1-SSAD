// Thin client over the FastAPI backend. All crypto logic lives in Python;
// these functions just send inputs and receive results + animation traces.

import type {
  Algo, Operation, CipherResponse, BruteResult, DictResult, HashResult,
  CaseInfo, IntegrityDemo,
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
  shift?: number
  direction?: 'right' | 'left'
  key?: string
  matrix?: number[][]
}

export const api = {
  cipher: (input: CipherInput) => post<CipherResponse>('/api/cipher', input),

  bruteforce: (caseId: string, target: string, length?: number) =>
    post<BruteResult>('/api/passwords/bruteforce', { case: caseId, target, length }),

  dictionary: (target: string) =>
    post<DictResult>('/api/passwords/dictionary', { target }),

  hashPassword: (password: string) =>
    post<HashResult>('/api/passwords/hash', { password }),

  cases: async () => {
    const res = await fetch('/api/passwords/cases')
    return (await res.json()) as {
      ok: boolean
      cases: Record<string, CaseInfo>
      dictionary: string[]
      fullCharset: string
    }
  },

  integrityDemo: (key: string, original: string, received: string) =>
    post<IntegrityDemo>('/api/integrity/demo', { key, original, received }),
}
