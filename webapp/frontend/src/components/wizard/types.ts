export type Action = '' | 'sign' | 'verify'

/** Where signing keys come from: one combined keystore, separate signer/TSA files, or a new keystore. */
export type CredentialSource = 'keystore' | 'separate' | 'generate'

export interface FilesState {
  inputDocument: File | null
  signedDocument: File | null
  originalFile: File | null
  keystoreFile: File | null
  signerFile: File | null
  tsaFile: File | null
}

export interface OptionsState {
  signatureLevel: string
  packaging: string
  digest: string
  tsaUrl: string
  ocspUrl: string
  crlUrl: string
  keystorePassword: string
  credentialSource: CredentialSource
  signerPassword: string
  tsaPassword: string
  reportFormat: string
  noKeystoreTrust: string
}

export type ResultKind = 'success' | 'warning' | 'error' | 'info'

export interface WizardResult {
  kind: ResultKind
  title: string
  message?: string
  output?: string
  /** Raw error text behind a friendly message, shown collapsed as technical details. */
  details?: string
}

export const EMPTY_FILES: FilesState = {
  inputDocument: null, signedDocument: null, originalFile: null, keystoreFile: null, signerFile: null, tsaFile: null,
}

export const DEFAULT_OPTIONS: OptionsState = {
  signatureLevel: 'LT', packaging: 'DETACHED', digest: 'SHA256',
  tsaUrl: '', ocspUrl: '', crlUrl: '', keystorePassword: '',
  credentialSource: 'keystore', signerPassword: '', tsaPassword: '',
  reportFormat: 'simple', noKeystoreTrust: 'false',
}

/** Whether the chosen signing keys are complete enough to sign with. */
export const hasSigningKeys = (files: FilesState, options: OptionsState): boolean => {
  switch (options.credentialSource) {
    case 'keystore':
      return files.keystoreFile !== null
    case 'separate':
      // A signer alone suffices for level B or with an online TSA; otherwise the TSA key is needed.
      return files.signerFile !== null && (files.tsaFile !== null || options.tsaUrl !== '' || options.signatureLevel === 'B')
    case 'generate':
      return true
  }
}

export const formatSize = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round((bytes / 1024) * 10) / 10} KB`
  return `${Math.round((bytes / 1024 / 1024) * 10) / 10} MB`
}
