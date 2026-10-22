import { IxCard, IxCardContent, IxCheckbox, IxInput, IxSelect, IxSelectItem, IxTypography } from '@siemens/ix-react'
import type { Action, CredentialSource, FilesState, OptionsState } from './types'
import { FileField } from './FileField'

interface Step3ConfigProps {
  options: OptionsState
  setOptions: (o: OptionsState) => void
  files: FilesState
  setFiles: (f: FilesState) => void
  action: Action
}

interface Choice { value: string; label: string }

const LEVELS: Choice[] = [
  { value: 'B', label: 'B – Basic' },
  { value: 'T', label: 'B-T – Time-stamped' },
  { value: 'LT', label: 'B-LT – Long-term' },
  { value: 'LTA', label: 'B-LTA – Long-term with archive' },
]
const PACKAGINGS: Choice[] = [
  { value: 'DETACHED', label: 'Detached' },
  { value: 'ENVELOPING', label: 'Enveloping' },
]
const DIGESTS: Choice[] = [
  { value: 'SHA256', label: 'SHA-256' },
  { value: 'SHA384', label: 'SHA-384' },
  { value: 'SHA512', label: 'SHA-512' },
]
const REPORT_FORMATS: Choice[] = [
  { value: 'simple', label: 'Simple – compact summary' },
  { value: 'full', label: 'Full – ETSI XML validation report' },
]

const CREDENTIAL_SOURCES: Choice[] = [
  { value: 'keystore', label: 'Combined keystore (.p12)' },
  { value: 'separate', label: 'Separate signer and TSA files' },
  { value: 'generate', label: 'Generate a new keystore' },
]
const CREDENTIAL_HELP: Record<CredentialSource, string> = {
  keystore: 'A PKCS#12 keystore with root, signer and tsa entries, e.g. from a previous generation.',
  separate: 'Each file holds a key and its certificate chain (PKCS#12/PFX or PEM). Include the issuing CA key for offline LT.',
  generate: 'A fresh demo PKI (root, signer, TSA) is created, used to sign, and downloaded so you can reuse it.',
}
const KEY_FILE_ACCEPT = '.p12,.pfx,.pem,.crt,.cer,.key'

const LEVEL_HELP: Record<string, string> = {
  B: 'Integrity and signer identity only.',
  T: 'Adds a trusted timestamp proving when the signature existed.',
  LT: 'Embeds certificates and revocation data for long-term validation.',
  LTA: 'Adds an archive timestamp so the evidence can be renewed.',
}
const PACKAGING_HELP: Record<string, string> = {
  DETACHED: 'The original file stays unchanged; the signature is a separate .p7s.',
  ENVELOPING: 'The original content is embedded inside the signature file.',
}

export function Step3Config({ options, setOptions, files, setFiles, action }: Step3ConfigProps) {
  const set = (key: keyof OptionsState) => (value: string) => setOptions({ ...options, [key]: value })

  const select = (key: keyof OptionsState, label: string, choices: Choice[], helperText?: string) => (
    <IxSelect
      label={label}
      name={key}
      value={options[key]}
      helperText={helperText}
      onValueChange={(e: CustomEvent<string | string[]>) => set(key)(String(e.detail))}
    >
      {choices.map(c => <IxSelectItem key={c.value} value={c.value} label={c.label} />)}
    </IxSelect>
  )

  const urlInput = (key: keyof OptionsState, label: string, placeholder: string, helperText: string) => (
    <IxInput
      type="url"
      label={label}
      name={key}
      value={options[key]}
      placeholder={placeholder}
      helperText={helperText}
      onValueChange={(e: CustomEvent<string>) => set(key)(e.detail)}
    />
  )

  return (
    <div className="stack">
      {action === 'sign' && (
        <IxCard variant="outline" passive>
          <IxCardContent>
            <div className="stack">
              <IxTypography format="h4">Signature</IxTypography>
              <div className="grid">
                {select('signatureLevel', 'Signature level', LEVELS, LEVEL_HELP[options.signatureLevel])}
                {select('packaging', 'Packaging', PACKAGINGS, PACKAGING_HELP[options.packaging])}
                {select('digest', 'Hash digest', DIGESTS, 'Algorithm used to hash the document.')}
              </div>
            </div>
          </IxCardContent>
        </IxCard>
      )}

      {action === 'sign' && (
        <IxCard variant="outline" passive>
          <IxCardContent>
            <div className="stack">
              <IxTypography format="h4">Signing keys</IxTypography>
              <div className="grid">
                {select('credentialSource', 'Key source', CREDENTIAL_SOURCES, CREDENTIAL_HELP[options.credentialSource])}
              </div>
              {options.credentialSource === 'keystore' && (
                <div className="grid">
                  <FileField
                    id="keystoreFile"
                    label="Keystore (.p12 / .pfx)"
                    accept=".p12,.pfx"
                    required
                    file={files.keystoreFile}
                    selectText="Drop a keystore here or"
                    helperText="Required: holds the signing and TSA keys."
                    onChange={file => setFiles({ ...files, keystoreFile: file })}
                  />
                  <IxInput
                    type="password"
                    label="Keystore password"
                    name="keystorePassword"
                    value={options.keystorePassword}
                    disabled={!files.keystoreFile}
                    helperText={files.keystoreFile ? 'Password protecting the keystore.' : 'Select a keystore first.'}
                    onValueChange={(e: CustomEvent<string>) => set('keystorePassword')(e.detail)}
                  />
                </div>
              )}
              {options.credentialSource === 'separate' && (
                <>
                  <div className="grid">
                    <FileField
                      id="signerFile"
                      label="Signer key and certificate"
                      accept={KEY_FILE_ACCEPT}
                      required
                      file={files.signerFile}
                      selectText="Drop a signer file here or"
                      helperText="PKCS#12/PFX or PEM with the signing key and its certificate chain."
                      onChange={file => setFiles({ ...files, signerFile: file })}
                    />
                    <IxInput
                      type="password"
                      label="Signer password"
                      name="signerPassword"
                      value={options.signerPassword}
                      disabled={!files.signerFile}
                      helperText={files.signerFile ? 'Keystore password, or the password of an encrypted PEM key.' : 'Select a signer file first.'}
                      onValueChange={(e: CustomEvent<string>) => set('signerPassword')(e.detail)}
                    />
                  </div>
                  <div className="grid">
                    <FileField
                      id="tsaFile"
                      label="TSA key and certificate"
                      accept={KEY_FILE_ACCEPT}
                      file={files.tsaFile}
                      selectText="Drop a TSA file here or"
                      helperText="Key and chain for the built-in TSA. With a TSA URL, just that TSA's certificates (no key)."
                      onChange={file => setFiles({ ...files, tsaFile: file })}
                    />
                    <IxInput
                      type="password"
                      label="TSA password"
                      name="tsaPassword"
                      value={options.tsaPassword}
                      disabled={!files.tsaFile}
                      helperText={files.tsaFile ? 'Keystore password, or the password of an encrypted PEM key.' : 'Select a TSA file first.'}
                      onValueChange={(e: CustomEvent<string>) => set('tsaPassword')(e.detail)}
                    />
                  </div>
                </>
              )}
              {options.credentialSource === 'generate' && (
                <div className="grid">
                  <IxInput
                    type="password"
                    label="New keystore password"
                    name="keystorePassword"
                    value={options.keystorePassword}
                    helperText="Protects the generated keystore. Leave empty for the demo default 'passwort'."
                    onValueChange={(e: CustomEvent<string>) => set('keystorePassword')(e.detail)}
                  />
                </div>
              )}
            </div>
          </IxCardContent>
        </IxCard>
      )}

      {action === 'verify' && (
        <IxCard variant="outline" passive>
          <IxCardContent>
            <div className="stack">
              <IxTypography format="h4">Validation report</IxTypography>
              <div className="grid">
                {select('reportFormat', 'Report format', REPORT_FORMATS, 'The full report includes validation steps, certificate chain and revocation data.')}
                <div className="stack-sm">
                  <IxCheckbox
                    label="Ignore keystore trust anchors"
                    checked={options.noKeystoreTrust === 'true'}
                    onCheckedChange={(e: CustomEvent<boolean>) => set('noKeystoreTrust')(e.detail ? 'true' : 'false')}
                  />
                  <IxTypography format="label-sm" textColor="soft">
                    Only the system trust store and certificates embedded in the signature are trusted.
                  </IxTypography>
                </div>
              </div>
            </div>
          </IxCardContent>
        </IxCard>
      )}

      <IxCard variant="outline" passive>
        <IxCardContent>
          <div className="stack">
            <IxTypography format="h4">Trust &amp; revocation (optional)</IxTypography>
            {action === 'sign' && (
              <div className="grid">
                {urlInput('tsaUrl', 'TSA URL', 'http://tsa.example.com/tsa', 'Time Stamp Authority used for B-T and above.')}
                {urlInput('ocspUrl', 'OCSP URL', 'http://ocsp.example.com/ocsp', 'Online revocation status responder.')}
                {urlInput('crlUrl', 'CRL URL', 'http://crl.example.com/crl', 'Certificate Revocation List location.')}
              </div>
            )}
            {action === 'verify' && (
              <div className="grid">
                <FileField
                  id="keystoreFile"
                  label="Keystore (.p12 / .pfx)"
                  accept=".p12,.pfx"
                  file={files.keystoreFile}
                  selectText="Drop a keystore here or"
                  helperText="Trust anchors for chains not rooted in the default trust store."
                  onChange={file => setFiles({ ...files, keystoreFile: file })}
                />
                <IxInput
                  type="password"
                  label="Keystore password"
                  name="keystorePassword"
                  value={options.keystorePassword}
                  disabled={!files.keystoreFile}
                  helperText={files.keystoreFile ? 'Password protecting the keystore.' : 'Select a keystore first.'}
                  onValueChange={(e: CustomEvent<string>) => set('keystorePassword')(e.detail)}
                />
              </div>
            )}
          </div>
        </IxCardContent>
      </IxCard>
    </div>
  )
}
