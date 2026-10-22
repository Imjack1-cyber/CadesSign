/*
 * Turns the ETSI TS 119 102-2 validation report that DSS emits (`verify --report full`) into a
 * small view model. The XML identifies everything by URN and by validation-object ID; this module
 * resolves those into labels, names and plain results so the UI does not have to.
 */

export type Outcome = 'passed' | 'failed' | 'indeterminate' | 'skipped' | 'unknown'

export interface Indication {
  outcome: Outcome
  /** Main indication as written in the report, e.g. "total-passed". */
  main: string
  /** Sub-indication code, e.g. "NO_CERTIFICATE_CHAIN_FOUND". */
  sub?: string
  /** Plain-language explanation of the sub-indication, when known. */
  explanation?: string
}

export interface Message {
  level: 'error' | 'warning' | 'info'
  text: string
}

export interface Check {
  label: string
  /** The check was switched off by the validation policy. */
  disabled: boolean
  result?: Indication
}

export interface ChainEntry {
  role: 'Signing certificate' | 'Intermediate' | 'Trust anchor'
  id: string
  name?: string
}

export interface Crypto {
  algorithm: string
  secure: boolean
  /** Date after which the policy no longer considers the algorithm secure. */
  notAfter?: string
}

export interface Evaluation {
  result?: Indication
  signer?: string
  chain: ChainEntry[]
  crypto?: Crypto
  messages: Message[]
  checks: Check[]
}

export interface SignatureReport extends Evaluation {
  id: string
  process?: string
  signingTime?: string
  timestampTimes: string[]
  validationTime?: string
  bestSignatureTime?: string
  mimeType?: string
}

export type ObjectKind = 'timestamp' | 'certificate' | 'revocation' | 'signedData' | 'other'

export interface ValidationObject extends Evaluation {
  id: string
  kind: ObjectKind
  /** Human-readable type, e.g. "OCSP response". */
  type: string
  name: string
  /** Earliest time the object is proven to have existed. */
  poeTime?: string
  /** For timestamps: the time the timestamp asserts. */
  timestampTime?: string
}

export interface ValidationReport {
  signatures: SignatureReport[]
  objects: ValidationObject[]
}

const CHECK_LABELS: Record<string, string> = {
  formatChecking: 'Format checking',
  identificationOfTheSigningCertificate: 'Signing certificate identification',
  validationContextInitialization: 'Validation context initialisation',
  x509CertificateValidation: 'X.509 certificate validation',
  cryptographicVerification: 'Cryptographic verification',
  signatureAcceptanceValidation: 'Signature acceptance validation',
  pastSignatureValidation: 'Past signature validation',
  pastCertificateValidation: 'Past certificate validation',
  validationTimeSliding: 'Validation time sliding',
}

const SUB_INDICATIONS: Record<string, string> = {
  NO_CERTIFICATE_CHAIN_FOUND: 'No chain to a trusted root was found. Add the issuing root as a trust anchor.',
  NO_SIGNING_CERTIFICATE_FOUND: 'The signing certificate could not be identified.',
  HASH_FAILURE: 'The signed content does not match the signature. The document was modified or the wrong original was supplied.',
  SIG_CRYPTO_FAILURE: 'The signature value could not be verified with the signer\'s public key.',
  SIGNED_DATA_NOT_FOUND: 'The signed content is missing. A detached signature needs the original document.',
  FORMAT_FAILURE: 'The signature is not a well-formed CAdES signature.',
  REVOKED: 'The signing certificate is revoked.',
  REVOKED_NO_POE: 'The certificate was revoked and there is no proof that the signature existed before.',
  REVOKED_CA_NO_POE: 'A CA certificate in the chain was revoked and there is no proof that the signature existed before.',
  EXPIRED: 'The signing certificate expired before the signature was proven to exist.',
  OUT_OF_BOUNDS_NO_POE: 'The certificate was not valid at validation time and there is no proof of existence while it was.',
  OUT_OF_BOUNDS_NOT_REVOKED: 'The certificate was not valid at validation time, though it is not revoked.',
  NOT_YET_VALID: 'The signing time lies before the certificate became valid.',
  TRY_LATER: 'Revocation data is not fresh enough yet. Try again later.',
  REVOCATION_OUT_OF_BOUNDS_NO_POE: 'The revocation data is outside the certificate\'s validity and there is no proof of existence.',
  CRYPTO_CONSTRAINTS_FAILURE: 'An algorithm or key size is no longer considered secure.',
  CRYPTO_CONSTRAINTS_FAILURE_NO_POE: 'An algorithm became insecure and there is no proof the signature existed before that.',
  CHAIN_CONSTRAINTS_FAILURE: 'The certificate chain does not satisfy the validation policy.',
  CERTIFICATE_CHAIN_GENERAL_FAILURE: 'The certificate chain could not be validated.',
  SIG_CONSTRAINTS_FAILURE: 'The signature does not satisfy the validation policy.',
  TIMESTAMP_ORDER_FAILURE: 'The timestamps are not in the expected order.',
  POLICY_PROCESSING_ERROR: 'The validation policy could not be processed.',
  SIGNATURE_POLICY_NOT_AVAILABLE: 'The signature policy referenced by the signature is not available.',
  NO_POE: 'There is no proof that the object existed at the relevant time.',
}

const PROCESSES: Record<string, string> = {
  Basic: 'Basic validation',
  LTVM: 'Validation with time-stamps and long-term material',
  LTA: 'Validation with long-term and archival data',
}

const OBJECT_TYPES: Record<string, { kind: ObjectKind; type: string }> = {
  timestamp: { kind: 'timestamp', type: 'Timestamp' },
  certificate: { kind: 'certificate', type: 'Certificate' },
  CRL: { kind: 'revocation', type: 'CRL' },
  OCSPResponse: { kind: 'revocation', type: 'OCSP response' },
  signedData: { kind: 'signedData', type: 'Signed data' },
}

/** The part of a URN after its last colon, e.g. "urn:etsi:019102:mainindication:passed" -> "passed". */
const lastSegment = (urn: string) => urn.slice(urn.lastIndexOf(':') + 1)

/** "someCamelCase" -> "Some camel case", the fallback for unknown check identifiers. */
const humanize = (name: string) => {
  const words = name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/_/g, ' ').toLowerCase()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

/** "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" -> "RSA with SHA-256". */
export function algorithmLabel(uri: string): string {
  const name = uri.slice(uri.lastIndexOf('#') + 1)
  const part = (p: string) => {
    const sha = /^sha(\d+)$/i.exec(p)
    if (sha) return `SHA-${sha[1]}`
    return p.toUpperCase()
  }
  const parts = name.split('-')
  return parts.length === 2 ? `${part(parts[0])} with ${part(parts[1])}` : parts.map(part).join('-')
}

function outcomeOf(main: string): Outcome {
  if (main.endsWith('passed')) return 'passed'
  if (main.endsWith('failed')) return 'failed'
  if (main === 'indeterminate') return 'indeterminate'
  return 'unknown'
}

// The report uses several XML namespaces; elements are matched by local name only.
const kids = (el: Element | undefined, name: string): Element[] =>
  el ? Array.from(el.children).filter(c => c.localName === name) : []
const kid = (el: Element | undefined, name: string): Element | undefined => kids(el, name)[0]
const text = (el: Element | undefined, ...path: string[]): string | undefined => {
  let current = el
  for (const name of path) current = kid(current, name)
  return current?.textContent?.trim() || undefined
}
const ref = (el: Element | undefined) => el?.getAttribute('VOReference') ?? undefined

function parseIndication(status: Element | undefined): Indication | undefined {
  const mainUrn = text(status, 'MainIndication')
  if (!mainUrn) return undefined
  const main = lastSegment(mainUrn)
  const subUrn = text(status, 'SubIndication')
  const sub = subUrn ? lastSegment(subUrn) : undefined
  return { outcome: outcomeOf(main), main, sub, explanation: sub ? SUB_INDICATIONS[sub] : undefined }
}

function parseMessages(data: Element | undefined): Message[] {
  return kids(kid(data, 'AdditionalValidationReportData'), 'ReportData').flatMap(report => {
    const message = text(report, 'Value')
    if (!message) return []
    const type = lastSegment(text(report, 'Type') ?? '')
    const level: Message['level'] = type === 'error' ? 'error' : type === 'warning' ? 'warning' : 'info'
    return [{ level, text: message }]
  })
}

function parseChain(data: Element | undefined): ChainEntry[] {
  const chain = kid(data, 'CertificateChain')
  const roles: Array<[string, ChainEntry['role']]> = [
    ['SigningCertificate', 'Signing certificate'],
    ['IntermediateCertificate', 'Intermediate'],
    ['TrustAnchor', 'Trust anchor'],
  ]
  return roles.flatMap(([tag, role]) =>
    kids(chain, tag).flatMap(entry => {
      const id = ref(entry)
      return id ? [{ role, id }] : []
    }))
}

/** The evaluation block shared by a signature and by each object it depends on. */
function parseEvaluation(report: Element | undefined): Evaluation {
  const status = kid(report, 'SignatureValidationStatus')
  const data = kid(status, 'AssociatedValidationReportData')
  const crypto = kid(data, 'CryptoInformation')
  const algorithm = text(crypto, 'Algorithm')
  return {
    result: parseIndication(status),
    signer: text(report, 'SignerInformation', 'Signer'),
    chain: parseChain(data),
    crypto: algorithm
      ? { algorithm: algorithmLabel(algorithm), secure: text(crypto, 'SecureAlgorithm') === 'true', notAfter: text(crypto, 'NotAfter') }
      : undefined,
    messages: parseMessages(data),
    checks: kids(kid(report, 'ValidationConstraintsEvaluationReport'), 'ValidationConstraint').map(constraint => {
      const id = lastSegment(text(constraint, 'ValidationConstraintIdentifier') ?? '')
      return {
        label: CHECK_LABELS[id] ?? humanize(id),
        disabled: lastSegment(text(constraint, 'ConstraintStatus', 'Status') ?? '') === 'disabled',
        result: parseIndication(kid(constraint, 'ValidationStatus')),
      }
    }),
  }
}

/** Short form of a validation-object ID for display, e.g. "C-6A8AC856…". */
export const shortId = (id: string) => (id.length > 12 ? `${id.slice(0, 10)}…` : id)

/**
 * Parses the XML report. Returns null when the text is not an ETSI validation report, so the
 * caller can fall back to showing it verbatim.
 */
export function parseValidationReport(xml: string): ValidationReport | null {
  if (!xml.trimStart().startsWith('<')) return null
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  const root = doc.documentElement
  if (!root || root.localName !== 'ValidationReport' || doc.getElementsByTagName('parsererror').length > 0) {
    return null
  }

  // Certificates are only named where they sign something; collect those names first.
  const names = new Map<string, string>()
  for (const info of Array.from(root.getElementsByTagNameNS('*', 'SignerInformation'))) {
    const id = ref(kid(info, 'SignerCertificate'))
    const name = text(info, 'Signer')
    if (id && name) names.set(id, name)
  }
  const named = (evaluation: Evaluation): Evaluation => ({
    ...evaluation,
    chain: evaluation.chain.map(entry => ({ ...entry, name: names.get(entry.id) })),
  })

  const signatures = kids(root, 'SignatureValidationReport').map((report): SignatureReport => {
    const attributes = kid(report, 'SignatureAttributes')
    const timeInfo = kid(report, 'ValidationTimeInfo')
    const process = text(report, 'SignatureValidationProcess', 'SignatureValidationProcessID')
    return {
      ...named(parseEvaluation(report)),
      id: kid(report, 'SignatureIdentifier')?.getAttribute('id') ?? '',
      process: process ? PROCESSES[lastSegment(process)] ?? lastSegment(process) : undefined,
      signingTime: text(attributes, 'SigningTime', 'Time'),
      timestampTimes: kids(attributes, 'SignatureTimeStamp').flatMap(ts => text(ts, 'TimeStampValue') ?? []),
      validationTime: text(timeInfo, 'ValidationTime'),
      bestSignatureTime: text(timeInfo, 'BestSignatureTime', 'POETime'),
      mimeType: text(attributes, 'DataObjectFormat', 'MimeType'),
    }
  })

  const objects = kids(kid(root, 'SignatureValidationObjects'), 'ValidationObject').map((object): ValidationObject => {
    const id = object.getAttribute('id') ?? ''
    const rawType = lastSegment(text(object, 'ObjectType') ?? '')
    const { kind, type } = OBJECT_TYPES[rawType] ?? { kind: 'other' as const, type: humanize(rawType) }
    const evaluation = named(parseEvaluation(kid(object, 'ValidationReport')))
    const subject = names.get(id) ?? evaluation.signer
    return {
      ...evaluation,
      id,
      kind,
      type,
      name: kind === 'certificate'
        ? subject ?? `Certificate ${shortId(id)}`
        : subject ? `${type} by ${subject}` : `${type} ${shortId(id)}`,
      poeTime: text(object, 'POE', 'POETime'),
      timestampTime: kind === 'timestamp' ? text(object, 'POEProvisioning', 'POETime') : undefined,
    }
  })

  return { signatures, objects }
}
