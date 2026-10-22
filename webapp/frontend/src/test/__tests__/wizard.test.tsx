import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { Wizard } from '../../components/wizard'
import indeterminateXml from '../fixtures/report-indeterminate.xml?raw'

const next = () => fireEvent.click(screen.getByRole('button', { name: 'Next' }))
const stepStatuses = () => screen.getAllByTestId('IxWorkflowStep').map(s => s.getAttribute('data-status'))

function chooseSignAndUpload() {
  render(<Wizard />)
  fireEvent.click(screen.getByRole('radio', { name: /Sign a document/ }))
  next()
  const file = new File(['hello'], 'hello.txt', { type: 'text/plain' })
  fireEvent.change(screen.getByTestId('upload-inputDocument'), { target: { files: [file] } })
}

describe('Wizard', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('starts on the action step with nothing selected and Next disabled', () => {
    render(<Wizard />)
    expect(screen.getByRole('heading', { name: 'Choose Action' })).toBeInTheDocument()
    screen.getAllByRole('radio').forEach(r => expect(r).toHaveAttribute('aria-checked', 'false'))
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  })

  it('selecting an action does not navigate until Next is pressed', () => {
    render(<Wizard />)
    fireEvent.click(screen.getByRole('radio', { name: /Verify a signature/ }))
    expect(screen.getByRole('heading', { name: 'Choose Action' })).toBeInTheDocument()
    next()
    expect(screen.getByRole('heading', { name: 'Select Files' })).toBeInTheDocument()
    expect(screen.getByText('Signature file (.p7s)')).toBeInTheDocument()
    expect(screen.getByText('Original document (optional)')).toBeInTheDocument()
  })

  it('double-clicking an action selects it and continues', () => {
    render(<Wizard />)
    fireEvent.doubleClick(screen.getByRole('radio', { name: /Sign a document/ }))
    expect(screen.getByRole('heading', { name: 'Select Files' })).toBeInTheDocument()
    expect(screen.getByText('Document to sign')).toBeInTheDocument()
  })

  it('Enter selects an action, and Enter on the selected one continues', () => {
    render(<Wizard />)
    const verify = screen.getByRole('radio', { name: /Verify a signature/ })
    fireEvent.keyDown(verify, { key: 'Enter' })
    expect(verify).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('heading', { name: 'Choose Action' })).toBeInTheDocument()

    fireEvent.keyDown(screen.getByRole('radio', { name: /Verify a signature/ }), { key: 'Enter' })
    expect(screen.getByRole('heading', { name: 'Select Files' })).toBeInTheDocument()
    expect(screen.getByText('Signature file (.p7s)')).toBeInTheDocument()
  })

  it('requires the document before continuing and shows it once uploaded', () => {
    render(<Wizard />)
    fireEvent.click(screen.getByRole('radio', { name: /Sign a document/ }))
    next()
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
    const file = new File(['hello'], 'hello.txt', { type: 'text/plain' })
    fireEvent.change(screen.getByTestId('upload-inputDocument'), { target: { files: [file] } })
    expect(screen.getByText('hello.txt')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled()

    fireEvent.click(screen.getByRole('button', { name: 'Remove hello.txt' }))
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  })

  it('Back returns to the previous step and keeps state', () => {
    chooseSignAndUpload()
    next()
    expect(screen.getByRole('heading', { name: 'Configure Options' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Back' }))
    expect(screen.getByText('hello.txt')).toBeInTheDocument()
  })

  it('marks completed workflow steps as done', () => {
    chooseSignAndUpload()
    next()
    expect(stepStatuses()).toEqual(['done', 'done', 'open', 'open', 'open'])
  })

  it('signing requires a keystore before Review is enabled', () => {
    chooseSignAndUpload()
    next()
    expect(screen.getByRole('button', { name: 'Review' })).toBeDisabled()
    fireEvent.change(screen.getByTestId('keystoreFile'), { target: { files: [new File(['k'], 'mine.p12')] } })
    expect(screen.getByRole('button', { name: 'Review' })).toBeEnabled()
  })

  it('separate key files need a TSA file above level B', () => {
    chooseSignAndUpload()
    next()
    fireEvent.change(screen.getByRole('combobox', { name: 'Key source' }), { target: { value: 'separate' } })
    fireEvent.change(screen.getByTestId('signerFile'), { target: { files: [new File(['s'], 'signer.pem')] } })
    expect(screen.getByRole('button', { name: 'Review' })).toBeDisabled()
    fireEvent.change(screen.getByTestId('tsaFile'), { target: { files: [new File(['t'], 'tsa.pem')] } })
    expect(screen.getByRole('button', { name: 'Review' })).toBeEnabled()
  })

  it('generating a keystore sends the request flag and offers the keystore for download', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('sig', {
      status: 200,
      headers: { 'X-Cades-Keystore': btoa('p12'), 'X-Cades-Summary': encodeURIComponent('Level reached : CAdES-BASELINE-LT') },
    }))
    window.URL.createObjectURL = vi.fn(() => 'blob:x')
    window.URL.revokeObjectURL = vi.fn()
    chooseSignAndUpload()
    next()
    fireEvent.change(screen.getByRole('combobox', { name: 'Key source' }), { target: { value: 'generate' } })
    fireEvent.click(screen.getByRole('button', { name: 'Review' }))
    expect(screen.getByText(/A new keystore will be generated/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Sign document' }))

    await waitFor(() => expect(screen.getByRole('button', { name: 'Download keystore' })).toBeInTheDocument())
    const body = fetchMock.mock.calls[0][1]?.body as FormData
    expect(body.get('generateKeystore')).toBe('true')
    expect(body.get('keystoreFile')).toBeNull()
  })

  const signWithSummary = async (level: string, summary: string) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('sig', {
      status: 200, headers: { 'X-Cades-Summary': encodeURIComponent(summary) },
    }))
    window.URL.createObjectURL = vi.fn(() => 'blob:x')
    window.URL.revokeObjectURL = vi.fn()
    chooseSignAndUpload()
    next()
    fireEvent.change(screen.getByRole('combobox', { name: 'Signature level' }), { target: { value: level } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Key source' }), { target: { value: 'generate' } })
    fireEvent.click(screen.getByRole('button', { name: 'Review' }))
    fireEvent.click(screen.getByRole('button', { name: 'Sign document' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Signature created' })).toBeInTheDocument())
  }

  it('signing at B shows the self-check for B, not for B-LT', async () => {
    await signWithSummary('B', [
      'Self-check:',
      '  - Level requested    : CAdES-BASELINE-B',
      '  - Level reached      : CAdES-BASELINE-B',
      '  - Signature intact?  : true',
      '  - Trusted chain?     : true',
      '  - Passed?            : true (validation INDETERMINATE, expected without embedded revocation data)',
    ].join('\n'))
    expect(screen.getByText('Self-check for B')).toBeInTheDocument()
    const check = screen.getByLabelText('Self-check')
    expect(check).toHaveTextContent('Signature intact')
    expect(check).toHaveTextContent('expected without embedded revocation data')
    expect(check).not.toHaveTextContent('Long-term')
    expect(check).not.toHaveTextContent('Timestamped')
    expect(screen.getByRole('status')).not.toHaveTextContent('did not pass')
  })

  it('a failed self-check turns the result into a warning', async () => {
    await signWithSummary('LT', [
      'Self-check:',
      '  - Level requested    : CAdES-BASELINE-LT',
      '  - Level reached      : CAdES-BASELINE-T',
      '  - Signature intact?  : true',
      '  - Trusted chain?     : true',
      '  - Timestamped?       : true',
      '  - Long-term?         : false',
      '  - Passed?            : false (INDETERMINATE)',
    ].join('\n'))
    expect(screen.getByText('Self-check for B-LT')).toBeInTheDocument()
    expect(screen.getByLabelText('Self-check')).toHaveTextContent('Long-term')
    expect(screen.getByRole('status')).toHaveTextContent('self-check did not pass for B-LT')
  })

  it('double-clicking a word in a card selects it instead of continuing', () => {
    render(<Wizard />)
    const card = screen.getByRole('radio', { name: /Sign a document/ })
    // jsdom has no layout; pretend every text line covers the top-left 500×50 px.
    const original = Range.prototype.getClientRects
    Range.prototype.getClientRects = () => [{ left: 0, right: 500, top: 0, bottom: 50 }] as unknown as DOMRectList
    try {
      fireEvent.doubleClick(card, { clientX: 10, clientY: 10 })
      expect(screen.getByRole('heading', { name: 'Choose Action' })).toBeInTheDocument()

      fireEvent.doubleClick(card, { clientX: 900, clientY: 300 })
      expect(screen.getByRole('heading', { name: 'Select Files' })).toBeInTheDocument()
    } finally {
      Range.prototype.getClientRects = original
    }
  })

  it('review shows the configuration and detached warning', () => {
    chooseSignAndUpload()
    next()
    fireEvent.change(screen.getByTestId('keystoreFile'), { target: { files: [new File(['k'], 'mine.p12')] } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Hash digest' }), { target: { value: 'SHA512' } })
    fireEvent.click(screen.getByRole('button', { name: 'Review' }))
    expect(screen.getByText('Hash digest: SHA512')).toBeInTheDocument()
    expect(screen.getByText(/Keep the original file/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign document' })).toBeEnabled()
  })

  it('verifying classifies an indeterminate result as a warning', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ output: 'Indication: INDETERMINATE', success: true }), { status: 200 }))
    render(<Wizard />)
    fireEvent.click(screen.getByRole('radio', { name: /Verify a signature/ }))
    next()
    fireEvent.change(screen.getByTestId('upload-signedDocument'), { target: { files: [new File(['x'], 'doc.p7s')] } })
    next()
    fireEvent.click(screen.getByRole('button', { name: 'Review' }))
    fireEvent.click(screen.getByRole('button', { name: 'Verify signature' }))

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Validation indeterminate' })).toBeInTheDocument())
    expect(screen.getByTestId('IxMessageBar')).toHaveAttribute('data-type', 'warning')
    expect(screen.getByText('Indication: INDETERMINATE')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'View full report' })).toBeInTheDocument()
    expect(stepStatuses()[4]).toBe('warning')

    fireEvent.click(screen.getByRole('button', { name: 'Start over' }))
    expect(screen.getByRole('heading', { name: 'Choose Action' })).toBeInTheDocument()
  })

  it('classifies a full ETSI report by its main indication', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ output: indeterminateXml, success: true }), { status: 200 }))
    render(<Wizard />)
    fireEvent.click(screen.getByRole('radio', { name: /Verify a signature/ }))
    next()
    fireEvent.change(screen.getByTestId('upload-signedDocument'), { target: { files: [new File(['x'], 'doc.p7s')] } })
    next()
    fireEvent.change(screen.getByRole('combobox', { name: 'Report format' }), { target: { value: 'full' } })
    fireEvent.click(screen.getByRole('button', { name: 'Review' }))
    fireEvent.click(screen.getByRole('button', { name: 'Verify signature' }))

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Validation indeterminate' })).toBeInTheDocument())
    expect(screen.getByText('Signature by CAdES Demo Signer')).toBeInTheDocument()
  })

  const reviewKeystoreSign = () => {
    chooseSignAndUpload()
    next()
    fireEvent.change(screen.getByTestId('keystoreFile'), { target: { files: [new File(['k'], 'keys.p12')] } })
    fireEvent.click(screen.getByRole('button', { name: 'Review' }))
  }

  it('a known server error shows an explanation with the raw text as technical details', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: 'Error: Unable to load the test PKI from /srv/uploads/abc (wrong password, or the keystore lacks the root/signer/tsa entries)',
    }), { status: 500 }))
    reviewKeystoreSign()
    fireEvent.click(screen.getByRole('button', { name: 'Sign document' }))

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Signing failed' })).toBeInTheDocument())
    expect(screen.getByText(/Check the password/)).toBeInTheDocument()
    expect(screen.getByText('Technical details')).toBeInTheDocument()
    expect(screen.getByLabelText('Technical details')).toHaveTextContent('/srv/uploads/abc')
  })

  it('a non-JSON error page is reported as a server error, not a connection problem', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<html>Bad Gateway</html>', { status: 502, statusText: 'Bad Gateway' }))
    reviewKeystoreSign()
    fireEvent.click(screen.getByRole('button', { name: 'Sign document' }))

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Signing failed' })).toBeInTheDocument())
    expect(screen.getByText(/HTTP 502/)).toBeInTheDocument()
  })

  it('Cancel aborts the running request and stays on Review', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((_url, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
    }))
    reviewKeystoreSign()
    fireEvent.click(screen.getByRole('button', { name: 'Sign document' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))

    await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument())
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true)
    expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign document' })).toBeEnabled()
  })
})
