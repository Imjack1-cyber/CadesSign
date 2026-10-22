import { IxCard, IxCardContent, IxKeyValue, IxKeyValueList, IxMessageBar, IxTypography } from '@siemens/ix-react'
import { type Action, type FilesState, type OptionsState, formatSize } from './types'

interface Step4ReviewProps {
  action: Action
  files: FilesState
  options: OptionsState
  warnings: string[]
}

const fileLabel = (file: File | null, fallback: string) => (file ? `${file.name} (${formatSize(file.size)})` : fallback)

function SigningKeys({ files, options }: { files: FilesState; options: OptionsState }) {
  switch (options.credentialSource) {
    case 'keystore':
      return <IxKeyValue icon="key" label="Keystore" value={fileLabel(files.keystoreFile, 'None selected')} />
    case 'separate':
      return (
        <>
          <IxKeyValue icon="key" label="Signer" value={fileLabel(files.signerFile, 'None selected')} />
          <IxKeyValue icon="key" label="TSA" value={fileLabel(files.tsaFile, options.tsaUrl ? 'Online TSA' : 'None')} />
        </>
      )
    case 'generate':
      return <IxKeyValue icon="key" label="Keystore" value="Generate a new keystore" />
  }
}

export function Step4Review({ action, files, options, warnings }: Step4ReviewProps) {
  const sources = [
    options.tsaUrl && 'TSA',
    options.ocspUrl && 'OCSP',
    options.crlUrl && 'CRL',
  ].filter(Boolean).join(', ')

  return (
    <div className="stack">
      <div className="grid grid-wide">
        <IxCard variant="outline" passive>
          <IxCardContent>
            <div className="stack">
              <IxTypography format="h4">Files</IxTypography>
              <IxKeyValueList striped>
                <IxKeyValue icon={action === 'sign' ? 'ink-pen' : 'shield-check'} label="Action" value={action === 'sign' ? 'Sign document' : 'Verify signature'} />
                {action === 'sign' ? (
                  <IxKeyValue icon="document" label="Document" value={fileLabel(files.inputDocument, 'None selected')} />
                ) : (
                  <>
                    <IxKeyValue icon="document" label="Signature" value={fileLabel(files.signedDocument, 'None selected')} />
                    <IxKeyValue icon="document" label="Original" value={fileLabel(files.originalFile, 'Not provided (enveloping)')} />
                  </>
                )}
                {action === 'sign' ? (
                  <SigningKeys files={files} options={options} />
                ) : (
                  <IxKeyValue icon="key" label="Keystore" value={fileLabel(files.keystoreFile, 'Default trust store')} />
                )}
              </IxKeyValueList>
            </div>
          </IxCardContent>
        </IxCard>

        <IxCard variant="outline" passive>
          <IxCardContent>
            <div className="stack">
              <IxTypography format="h4">Options</IxTypography>
              <IxKeyValueList striped>
                {action === 'sign' ? (
                  <>
                    <IxKeyValue label="Signature level" value={options.signatureLevel} />
                    <IxKeyValue label="Packaging" value={options.packaging} />
                    <IxKeyValue label="Hash digest" value={options.digest} />
                    <IxKeyValue label="External sources" value={sources || 'None'} />
                  </>
                ) : (
                  <>
                    <IxKeyValue label="Report format" value={options.reportFormat === 'full' ? 'Full (XML)' : 'Simple'} />
                    <IxKeyValue label="Ignore keystore trust" value={options.noKeystoreTrust === 'true' ? 'Yes' : 'No'} />
                  </>
                )}
              </IxKeyValueList>
            </div>
          </IxCardContent>
        </IxCard>
      </div>

      {warnings.length > 0 && (
        <div className="stack-sm" aria-live="polite">
          <IxTypography format="h4">Pre-flight checks</IxTypography>
          {warnings.map(w => (
            <IxMessageBar key={w} type="warning" persistent>
              {w}
            </IxMessageBar>
          ))}
        </div>
      )}
    </div>
  )
}
