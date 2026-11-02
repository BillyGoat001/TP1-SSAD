// Preuve de travail du captcha : trouver un nombre n tel que sha256("<defi>:<n>") commence
// par `bits` zeros (voir backend/captcha.py). Le navigateur y passe quelques dixiemes de
// seconde ; un robot qui enchaine des milliers de connexions, lui, paie chaque essai.
//
// Le calcul tourne dans un Worker (la page reste fluide). Le message tient dans un seul
// bloc SHA-256 (moins de 56 octets), donc une seule compression par essai.

/** Cherche un nonce dans [start, start + count[. Renvoie -1 si aucun n'y est.
 *  Fonction AUTONOME (rien d'exterieur) : son texte est aussi injecte tel quel dans le Worker. */
export function powSearch(challenge: string, bits: number, start: number, count: number): number {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ])
  const w = new Uint32Array(64)
  const buf = new Uint8Array(64)
  const head = challenge + ':'
  const hl = head.length
  for (let i = 0; i < hl; i++) buf[i] = head.charCodeAt(i)
  const shift = 32 - bits
  for (let n = start; n < start + count; n++) {
    const digits = String(n)
    const len = hl + digits.length
    buf.fill(0, hl)
    for (let i = 0; i < digits.length; i++) buf[hl + i] = digits.charCodeAt(i)
    buf[len] = 0x80
    const bitLen = len * 8
    buf[62] = (bitLen >>> 8) & 255
    buf[63] = bitLen & 255
    for (let i = 0; i < 16; i++) w[i] = (buf[4 * i] << 24) | (buf[4 * i + 1] << 16) | (buf[4 * i + 2] << 8) | buf[4 * i + 3]
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2]
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
    }
    let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a
    let e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
      const mj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + mj) | 0
      h = g; g = f; f = e; e = (d + t1) | 0
      d = c; c = b; b = a; a = (t1 + t2) | 0
    }
    // seul le premier mot du hachage nous interesse : IV[0] + a
    const first = (0x6a09e667 + a) >>> 0
    if (first >>> shift === 0) return n
  }
  return -1
}

export interface PowJob {
  promise: Promise<number>
  cancel: () => void
}

const CHUNK = 20000

/** Lance la recherche en arriere-plan. `cancel()` l'arrete (captcha ferme ou remplace). */
export function solvePow(challenge: string, bits: number): PowJob {
  let stopped = false
  let worker: Worker | null = null
  let url: string | null = null
  const promise = new Promise<number>((resolve, reject) => {
    const fallback = () => {          // pas de Worker : on cherche par petites tranches sur la page
      let n = 0
      const step = () => {
        if (stopped) return reject(new Error('cancelled'))
        const r = powSearch(challenge, bits, n, CHUNK)
        if (r >= 0) return resolve(r)
        n += CHUNK
        setTimeout(step, 0)
      }
      step()
    }
    try {
      const src = `${powSearch.toString()}
        onmessage = (e) => {
          const { challenge, bits } = e.data
          let n = 0
          for (;;) {
            const r = powSearch(challenge, bits, n, ${CHUNK})
            if (r >= 0) { postMessage(r); return }
            n += ${CHUNK}
          }
        }`
      url = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }))
      worker = new Worker(url)
      worker.onmessage = (e) => resolve(e.data as number)
      worker.onerror = () => { worker?.terminate(); worker = null; fallback() }
      worker.postMessage({ challenge, bits })
    } catch {
      fallback()
    }
  })
  const cleanup = () => {
    worker?.terminate(); worker = null
    if (url) { URL.revokeObjectURL(url); url = null }
  }
  promise.then(cleanup, cleanup)
  return { promise, cancel: () => { stopped = true; cleanup() } }
}
