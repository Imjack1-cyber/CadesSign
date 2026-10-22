/** 32px pixel-style icons for the Windows 95 desktop, drawn crisp so they scale like the originals. */

interface IconProps {
  size?: number
}

const svg = (size: number, children: React.ReactNode) => (
  <svg viewBox="0 0 32 32" width={size} height={size} shapeRendering="crispEdges" aria-hidden="true">{children}</svg>
)

export const FolderIcon = ({ size = 32 }: IconProps) => svg(size, <>
  <path d="M2 8h10l2 3h16v17H2z" fill="#e8c840" stroke="#000" />
  <path d="M2 13h28" stroke="#fff3a0" />
</>)

/** My Documents: a folder with a sheet sticking out. */
export const DocumentsIcon = ({ size = 32 }: IconProps) => svg(size, <>
  <path d="M2 8h10l2 3h16v17H2z" fill="#e8c840" stroke="#000" />
  <path d="M8 4h14l4 4v12H8z" fill="#fff" stroke="#000" />
  <path d="M11 9h9M11 12h11M11 15h11" stroke="#000080" />
  <path d="M2 15h28v13H2z" fill="#f0d860" stroke="#000" />
</>)

const sheet = <path d="M7 2h13l6 6v22H7z" fill="#fff" stroke="#000" />
const fold = <path d="M20 2v6h6" fill="#c0c0c0" stroke="#000" />

/** A signature: a sheet with a red seal and ribbons. */
export const SignatureIcon = ({ size = 32 }: IconProps) => svg(size, <>
  {sheet}{fold}
  <path d="M10 11h12M10 14h12M10 17h7" stroke="#808080" />
  <path d="M17 24l-2 6 3-2 2 2-1-6" fill="#c00000" stroke="#600" />
  <circle cx="19" cy="22" r="4" fill="#e02020" stroke="#600" />
</>)

/** A report: a sheet of lines, like Notepad's documents. */
export const ReportIcon = ({ size = 32 }: IconProps) => svg(size, <>
  {sheet}{fold}
  <path d="M10 11h12M10 14h12M10 17h12M10 20h12M10 23h8" stroke="#000080" />
</>)

export const KeystoreIcon = ({ size = 32 }: IconProps) => svg(size, <>
  <circle cx="11" cy="16" r="6" fill="#e8c840" stroke="#000" />
  <circle cx="11" cy="16" r="2" fill="#fff" stroke="#000" />
  <path d="M17 15h12v3h-2v3h-3v-3h-2v3h-3v-3h-2z" fill="#e8c840" stroke="#000" />
</>)

/** A closed window waiting in the Recycle Bin. */
export const WindowIcon = ({ size = 32 }: IconProps) => svg(size, <>
  <rect x="3" y="5" width="26" height="22" fill="#c0c0c0" stroke="#000" />
  <rect x="4" y="6" width="24" height="4" fill="#000080" />
  <rect x="5" y="12" width="22" height="13" fill="#fff" />
</>)

export const BinIcon = ({ size = 32, full = false }: IconProps & { full?: boolean }) => svg(size, <>
  <path d="M7 9h18l-2 20H9z" fill="#c0c0c0" stroke="#000" />
  <path d="M11 12l1 14M16 12v14M21 12l-1 14" stroke="#808080" />
  <path d="M5 7h22v3H5z" fill="#dfdfdf" stroke="#000" />
  {full && <path d="M9 7q2-5 6-3t7-1l2 4M12 6l3-4 3 3" fill="#fff" stroke="#000" />}
</>)

/** The icon for a stored file, by its folder. */
export function FileIcon({ folder, size = 32 }: IconProps & { folder: string }) {
  if (folder === 'signatures') return <SignatureIcon size={size} />
  if (folder === 'keystores') return <KeystoreIcon size={size} />
  return <ReportIcon size={size} />
}
