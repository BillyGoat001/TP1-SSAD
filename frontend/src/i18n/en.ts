// Dictionnaire francais → anglais, une partie par page (voir i18n/en/*.ts),
// + les regles pour les messages qui contiennent des valeurs (PATTERNS).
import cipher from './en/cipher'
import files from './en/files'
import limits from './en/limits'
import exchange from './en/exchange'
import passwords from './en/passwords'
import integrity from './en/integrity'
import auth from './en/auth'
import backend, { BACKEND_PATTERNS } from './en/backend'

export const EN: Record<string, string> = {
  ...cipher, ...files, ...limits, ...exchange, ...passwords, ...integrity, ...auth, ...backend,
}

export const PATTERNS: [RegExp, (m: RegExpMatchArray) => string][] = [...BACKEND_PATTERNS]
