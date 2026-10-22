import { describe, it, expect } from 'vitest'
import { describeError, readJson } from '../../components/wizard/errorMessages'

describe('describeError', () => {
  it.each([
    ['Error: Unable to load the test PKI from /tmp/x (wrong password, or the keystore lacks the root/signer/tsa entries)', /password/],
    ['Error: keystore password was incorrect', /password/],
    ['Error: PEM private key is encrypted but no password was provided', /encrypted/],
    ['Error: Unable to read private keys from a.pem: the PEM data is damaged, truncated or encrypted with another password', /could not be read/],
    ['Error: Revocation data is missing for one or more certificate(s).', /OCSP or CRL/],
    ['No revocation data found after the best signature time', /OCSP or CRL/],
    ['File too large', /50 MB/],
    ['Unexpected field', /rejected/],
    ['A keystore is required: upload a keystore, upload signer and TSA files, or generate a new keystore', /needs keys/],
  ])('explains %s', (raw, expected) => {
    expect(describeError(raw)?.message).toMatch(expected)
  })

  it('titles timeouts', () => {
    expect(describeError('Signing timed out')?.title).toBe('Request timed out')
    expect(describeError('Verification timed out')?.title).toBe('Request timed out')
  })

  it('returns null for unknown or empty text', () => {
    expect(describeError('Something unexpected happened')).toBeNull()
    expect(describeError('')).toBeNull()
    expect(describeError(undefined)).toBeNull()
  })
})

describe('readJson', () => {
  it('parses JSON bodies', async () => {
    expect(await readJson(new Response('{"output":"ok"}'))).toEqual({ output: 'ok' })
  })

  it('turns non-JSON bodies into an error with the status', async () => {
    const data = await readJson(new Response('<html>Bad Gateway</html>', { status: 502, statusText: 'Bad Gateway' }))
    expect(data.error).toMatch(/HTTP 502 Bad Gateway/)
  })
})
