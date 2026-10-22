import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import passedXml from '../fixtures/report-passed.xml?raw'
import indeterminateXml from '../fixtures/report-indeterminate.xml?raw'
import { algorithmLabel, parseValidationReport } from '../../components/wizard/validationReport'
import { Step5Result } from '../../components/wizard/Step5Result'

// Both fixtures are real `verify --report full` outputs for one signature with a FreeTSA timestamp:
// verified against the demo keystore (passed) and against the system trust store (indeterminate).

describe('parseValidationReport', () => {
  it('extracts the signature result, signer, times and chain', () => {
    const report = parseValidationReport(passedXml)!
    expect(report.signatures).toHaveLength(1)
    const [signature] = report.signatures
    expect(signature.result).toMatchObject({ outcome: 'passed', main: 'total-passed' })
    expect(signature.signer).toBe('CAdES Demo Signer')
    expect(signature.signingTime).toBe('2026-10-20T11:14:19Z')
    expect(signature.timestampTimes).toEqual(['2026-10-20T11:14:20Z'])
    expect(signature.process).toBe('Validation with long-term and archival data')
    expect(signature.crypto).toMatchObject({ algorithm: 'RSA with SHA-256', secure: true })
    expect(signature.chain.map(c => c.role)).toEqual(['Signing certificate', 'Trust anchor'])
    expect(signature.chain[0].name).toBe('CAdES Demo Signer')
    expect(signature.checks.map(c => c.label)).toContain('Cryptographic verification')
  })

  it('names and groups the validation objects', () => {
    const report = parseValidationReport(passedXml)!
    const timestamp = report.objects.find(o => o.kind === 'timestamp')!
    expect(timestamp.name).toBe('Timestamp by www.freetsa.org')
    expect(timestamp.timestampTime).toBe('2026-10-20T11:14:20Z')
    expect(report.objects.filter(o => o.kind === 'revocation').map(o => o.type).sort())
      .toEqual(['CRL', 'OCSP response', 'OCSP response'])
  })

  it('explains an indeterminate result and keeps its messages', () => {
    const [signature] = parseValidationReport(indeterminateXml)!.signatures
    expect(signature.result).toMatchObject({ outcome: 'indeterminate', sub: 'NO_CERTIFICATE_CHAIN_FOUND' })
    expect(signature.result?.explanation).toMatch(/trust anchor/)
    expect(signature.messages).toEqual([
      { level: 'error', text: 'The certificate chain for signature is not trusted, it does not contain a trust anchor.' },
    ])
  })

  it('returns null for anything that is not a validation report', () => {
    expect(parseValidationReport('Verification result:\n  - Passed? : true')).toBeNull()
    expect(parseValidationReport('<other/>')).toBeNull()
    expect(parseValidationReport('<ValidationReport><broken')).toBeNull()
  })

  it('labels algorithm URIs', () => {
    expect(algorithmLabel('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512')).toBe('ECDSA with SHA-512')
  })
})

describe('full report display', () => {
  const renderResult = (output: string) => render(
    <Step5Result
      action="verify"
      result={{ kind: 'warning', title: 'Validation indeterminate', output }}
      fullReport={null}
      reportIsFull
      loading={false}
      onFetchFullReport={() => {}}
      onDownloadXml={() => {}}
      onBackToSummary={() => {}}
      onChangeOptions={() => {}}
      onStartOver={() => {}}
    />,
  )

  it('shows the report structured, with the raw XML one toggle away', () => {
    renderResult(indeterminateXml)
    expect(screen.getByText('Signature by CAdES Demo Signer')).toBeInTheDocument()
    // Shown for the signature, its FreeTSA timestamp and the checks that failed on it
    expect(screen.getAllByText('NO CERTIFICATE CHAIN FOUND').length).toBeGreaterThan(1)
    expect(screen.getAllByText(/Add the issuing root as a trust anchor/).length).toBeGreaterThan(0)
    expect(screen.queryByLabelText('Report output')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'XML' }))
    expect(screen.getByLabelText('Report output').textContent).toContain('<ValidationReport')
  })

  it('falls back to plain text when the output is not an ETSI report', () => {
    renderResult('Error: signature file not found')
    expect(screen.getByLabelText('Report output')).toHaveTextContent('signature file not found')
    expect(screen.queryByRole('button', { name: 'XML' })).not.toBeInTheDocument()
  })
})
