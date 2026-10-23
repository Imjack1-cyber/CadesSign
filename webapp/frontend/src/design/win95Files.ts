/** The Windows 95 desktop's folders onto the generated files (generatedFiles.ts). */
import { FOLDERS } from './generatedFiles'
import type { GeneratedFolder } from './signals'

/** My Documents, one of its folders, or the Recycle Bin. */
export type FolderId = 'docs' | GeneratedFolder | 'bin'

export const folderTitle = (folder: FolderId) =>
  folder === 'docs' ? 'My Documents' : folder === 'bin' ? 'Recycle Bin' : FOLDERS.find(f => f.id === folder)!.label
