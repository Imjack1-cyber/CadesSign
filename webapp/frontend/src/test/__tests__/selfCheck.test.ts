import { describe, it, expect } from 'vitest'
import { parseSelfCheck, shortLevel } from '../../components/wizard/selfCheck'

describe('parseSelfCheck', () => {
  it('reads the requested level, the checks and the verdict', () => {
    const check = parseSelfCheck([
      'Self-check:',
      '  - Level requested    : CAdES-BASELINE-T',
      '  - Level reached      : CAdES-BASELINE-T',
      '  - Timestamped?       : true',
      '  - Passed?            : true (validation INDETERMINATE, expected without embedded revocation data)',
    ].join('\n'))
    expect(check).toEqual({
      requested: 'B-T',
      reached: 'B-T',
      passed: true,
      rows: [
        { label: 'Level requested', value: 'B-T' },
        { label: 'Level reached', value: 'B-T' },
        { label: 'Timestamped', value: 'Yes', ok: true, note: undefined },
        { label: 'Passed', value: 'Yes', ok: true, note: 'validation INDETERMINATE, expected without embedded revocation data' },
      ],
    })
  })

  it('returns null for anything that is not a self-check', () => {
    expect(parseSelfCheck(undefined)).toBeNull()
    expect(parseSelfCheck('Verification result:\n  - Passed? : true')).toBeNull()
  })

  it('shortens CAdES baseline levels', () => {
    expect(['B', 'T', 'LT', 'LTA'].map(l => shortLevel(`CAdES-BASELINE-${l}`))).toEqual(['B', 'B-T', 'B-LT', 'B-LTA'])
  })
})
