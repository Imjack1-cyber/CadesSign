/**
 * Parses the signer's self-check, which the CLI prints after signing and judges against the
 * requested level (only the properties that level promises are listed):
 *
 *   Self-check:
 *     - Level requested    : CAdES-BASELINE-T
 *     - Level reached      : CAdES-BASELINE-T
 *     - Signature intact?  : true
 *     - Timestamped?       : true
 *     - Passed?            : true (validation INDETERMINATE, expected without embedded revocation data)
 */

export interface SelfCheckRow {
  label: string
  /** The value as printed, with CAdES-BASELINE-X shortened to B-X. */
  value: string
  /** true / false for yes-no checks; undefined for plain values such as the level. */
  ok?: boolean
  /** Text in brackets after a yes-no value, e.g. the DSS indication. */
  note?: string
}

export interface SelfCheck {
  requested: string | null
  reached: string | null
  /** The overall verdict for the requested level; null when the output has no "Passed?" line. */
  passed: boolean | null
  rows: SelfCheckRow[]
}

/** CAdES-BASELINE-LT → B-LT, CAdES-BASELINE-B → B. */
export const shortLevel = (level: string) =>
  level.replace(/^CAdES-BASELINE-/, '').replace(/^(T|LT|LTA)$/, 'B-$1')

const LINE = /^\s*-\s*(.+?)\s*:\s*(.+?)\s*$/

export function parseSelfCheck(output: string | undefined): SelfCheck | null {
  if (!output || !/^Self-check:/m.test(output)) return null
  const rows: SelfCheckRow[] = []
  for (const line of output.split('\n')) {
    const match = LINE.exec(line)
    if (!match) continue
    const label = match[1].replace(/\?$/, '')
    const [, flag, note] = /^(true|false)\b\s*(?:\((.*)\))?$/.exec(match[2]) ?? []
    rows.push(flag
      ? { label, value: flag === 'true' ? 'Yes' : 'No', ok: flag === 'true', note }
      : { label, value: shortLevel(match[2]) })
  }
  const find = (label: string) => rows.find(r => r.label === label)
  const passed = find('Passed')
  return {
    requested: find('Level requested')?.value ?? null,
    reached: find('Level reached')?.value ?? null,
    passed: passed ? passed.ok ?? null : null,
    rows,
  }
}
