import { BinIcon, DocumentsIcon } from './Win95Icons'
import type { FolderId } from './win95Files'

interface Win95DesktopProps {
  /** Files in My Documents, and items in the Recycle Bin (closed windows and deleted files). */
  documents: number
  binned: number
  onOpen: (folder: FolderId) => void
}

/**
 * The icons on the desktop: My Documents and the Recycle Bin. A click selects one, a double-click or
 * Enter opens it in Explorer. On a phone they only show while they hold something.
 */
export function Win95Desktop({ documents, binned, onOpen }: Win95DesktopProps) {
  const icon = (folder: FolderId, label: string, detail: string, art: React.ReactNode, filled: boolean, extra = {}) => (
    <button
      type="button"
      className="w95-desktop-icon"
      data-filled={filled}
      aria-label={`${label}: ${detail}. Double-click or press Enter to open.`}
      onDoubleClick={() => onOpen(folder)}
      onKeyDown={e => {
        if (e.key === 'Enter') onOpen(folder)
      }}
      {...extra}
    >
      {art}
      <span>{label}</span>
    </button>
  )
  return (
    <div className="w95-desktop">
      {icon('docs', 'My Documents', `${documents} ${documents === 1 ? 'file' : 'files'}`, <DocumentsIcon />, documents > 0)}
      {icon('bin', 'Recycle Bin', binned ? `${binned} ${binned === 1 ? 'item' : 'items'}` : 'empty', <BinIcon full={binned > 0} />, binned > 0, { 'data-w95-bin': '' })}
    </div>
  )
}
