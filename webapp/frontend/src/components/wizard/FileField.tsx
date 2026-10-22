import { IxFieldLabel, IxIconButton, IxIcon, IxTypography, IxUpload } from '@siemens/ix-react'
import { formatSize } from './types'
import { TOUCH_QUERY, useMediaQuery } from '../../design/useMediaQuery'

interface FileFieldProps {
  id: string
  label: string
  helperText?: string
  accept?: string
  required?: boolean
  file: File | null
  selectText: string
  onChange: (file: File | null) => void
}

/** A labelled IxUpload drop zone that switches to a file summary row once a file is chosen. */
export function FileField({ id, label, helperText, accept, required, file, selectText, onChange }: FileFieldProps) {
  // Touch screens have no drag and drop; there the zone only states that the upload button is the way in.
  const touch = useMediaQuery(TOUCH_QUERY)
  return (
    <div className="stack-sm">
      <IxFieldLabel htmlFor={id} required={required}>{label}</IxFieldLabel>
      {file ? (
        <div className="file-row" id={id}>
          <IxIcon name="document" size="24" />
          <div className="file-name">
            <IxTypography format="label" bold title={file.name}>{file.name}</IxTypography>
            <IxTypography format="label-sm" textColor="soft">{formatSize(file.size)}</IxTypography>
          </div>
          <IxIconButton
            icon="trashcan"
            variant="subtle-tertiary"
            aria-label={`Remove ${file.name}`}
            title="Remove file"
            onClick={() => onChange(null)}
          />
        </div>
      ) : (
        <IxUpload
          id={id}
          accept={accept}
          selectFileText={touch ? 'No file chosen yet' : selectText}
          onFilesChanged={(e: CustomEvent<File[]>) => onChange(e.detail[0] ?? null)}
        />
      )}
      {helperText && <IxTypography format="label-sm" textColor="soft">{helperText}</IxTypography>}
    </div>
  )
}
