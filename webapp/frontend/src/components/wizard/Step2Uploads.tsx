import type { Action, FilesState } from './types'
import { FileField } from './FileField'

interface Step2UploadsProps {
  files: FilesState
  setFiles: (f: FilesState) => void
  action: Action
}

export function Step2Uploads({ files, setFiles, action }: Step2UploadsProps) {
  const set = (key: keyof FilesState) => (file: File | null) => setFiles({ ...files, [key]: file })

  if (action === 'sign') {
    return (
      <div className="grid grid-wide">
        <FileField
          id="upload-inputDocument"
          label="Document to sign"
          required
          file={files.inputDocument}
          selectText="Drop the document here or"
          helperText="Any file type, e.g. .txt, .xml, .pdf, .png. The file is hashed and signed; its content is not changed."
          onChange={set('inputDocument')}
        />
      </div>
    )
  }

  return (
    <div className="grid grid-wide">
      <FileField
        id="upload-signedDocument"
        label="Signature file (.p7s)"
        required
        accept=".p7s,.p7m,.pkcs7"
        file={files.signedDocument}
        selectText="Drop the signature here or"
        helperText="The CAdES signature to validate."
        onChange={set('signedDocument')}
      />
      <FileField
        id="upload-originalFile"
        label="Original document (optional)"
        file={files.originalFile}
        selectText="Drop the original file here or"
        helperText="Required for detached signatures. Leave empty for enveloping signatures."
        onChange={set('originalFile')}
      />
    </div>
  )
}
