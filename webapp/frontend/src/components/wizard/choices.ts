/** The fixed choices of the wizard's options, shared by the options step, the wizard and the terminal theme. */
import type { OptionsState } from './types'

export interface Choice { value: string; label: string }

export const LEVELS: Choice[] = [
  { value: 'B', label: 'B – Basic' },
  { value: 'T', label: 'B-T – Time-stamped' },
  { value: 'LT', label: 'B-LT – Long-term' },
  { value: 'LTA', label: 'B-LTA – Long-term with archive' },
]
export const PACKAGINGS: Choice[] = [
  { value: 'DETACHED', label: 'Detached' },
  { value: 'ENVELOPING', label: 'Enveloping' },
]
export const DIGESTS: Choice[] = [
  { value: 'SHA256', label: 'SHA-256' },
  { value: 'SHA384', label: 'SHA-384' },
  { value: 'SHA512', label: 'SHA-512' },
]
export const REPORT_FORMATS: Choice[] = [
  { value: 'simple', label: 'Simple – compact summary' },
  { value: 'full', label: 'Full – ETSI XML validation report' },
]

export const CREDENTIAL_SOURCES: Choice[] = [
  { value: 'keystore', label: 'Combined keystore (.p12)' },
  { value: 'separate', label: 'Separate signer and TSA files' },
  { value: 'generate', label: 'Generate a new keystore' },
]

/** The options that take one of a fixed set of values, and those values. */
export const OPTION_CHOICES = {
  signatureLevel: LEVELS,
  packaging: PACKAGINGS,
  digest: DIGESTS,
  reportFormat: REPORT_FORMATS,
  credentialSource: CREDENTIAL_SOURCES,
} as const satisfies Partial<Record<keyof OptionsState, Choice[]>>

/** The choice `value` names, by its value or the start of its label, ignoring case; e.g. "b-lt" or "lt" finds LT. */
export function findChoice(choices: readonly Choice[], value: string): Choice | undefined {
  const v = value.trim().toLowerCase()
  if (!v) return undefined
  return choices.find(c => c.value.toLowerCase() === v)
    ?? choices.find(c => c.label.toLowerCase().replace(/[^a-z0-9]/g, '') === v.replace(/[^a-z0-9]/g, ''))
    ?? choices.find(c => c.label.toLowerCase().startsWith(v))
}
