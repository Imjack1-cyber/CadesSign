/**
 * Turns the raw error text the backend returns (CLI stderr, multer or validation messages) into a
 * plain-language explanation. The raw text stays available as technical details.
 */

export interface FriendlyError {
  title?: string
  message: string
}

const RULES: Array<{ pattern: RegExp; error: FriendlyError }> = [
  {
    pattern: /no password was provided/i,
    error: { message: 'The private key file is encrypted. Enter its password in the options step and try again.' },
  },
  {
    pattern: /wrong password|password was incorrect|mac check failed|given final block not properly padded/i,
    error: { message: 'The keystore could not be opened. Check the password, and that the file is the keystore you meant to use.' },
  },
  {
    pattern: /PEM data is damaged|unable to read (certificates|private keys)/i,
    error: { message: 'A key or certificate file could not be read. It may be damaged, truncated or protected by another password; re-export it rather than copying it by hand.' },
  },
  {
    pattern: /revocation data is missing|no revocation data found after the best signature time/i,
    error: { message: 'Level B-LT needs revocation data (OCSP or CRL) for every certificate in the chain. Add OCSP or CRL endpoints, or choose level B-T.' },
  },
  {
    pattern: /(signing|verification) timed out/i,
    error: { title: 'Request timed out', message: 'The operation took too long. A slow or unreachable TSA, OCSP or CRL endpoint is the usual cause.' },
  },
  {
    pattern: /file too large/i,
    error: { message: 'A file exceeds the 50 MB upload limit.' },
  },
  {
    pattern: /unexpected field|too many files/i,
    error: { message: 'The upload was rejected by the server. Reload the page and try again.' },
  },
  {
    pattern: /a keystore is required/i,
    error: { message: 'Signing needs keys: upload a keystore, upload signer and TSA files, or let the app generate a new keystore.' },
  },
]

/** The explanation for a known error, or null when the raw text is all there is. */
export function describeError(raw: string | undefined): FriendlyError | null {
  if (!raw) return null
  return RULES.find(rule => rule.pattern.test(raw))?.error ?? null
}

/**
 * Reads a JSON response body, tolerating non-JSON error pages (e.g. an HTML 502 from a proxy),
 * which come back as `{ error: <status text> }`.
 */
export async function readJson(res: Response): Promise<Record<string, any>> {
  const text = await res.text()
  try {
    return JSON.parse(text)
  } catch {
    return { error: `The server returned an unexpected response (HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ''}).` }
  }
}
