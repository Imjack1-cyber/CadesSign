import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'
import { emitChrome, type GeneratedFolder } from './signals'
import { BinIcon, DocumentsIcon, FileIcon, FolderIcon, WindowIcon } from './Win95Icons'
import { Win95Frame } from './Win95Frame'
import { download, FOLDERS, formatSize, type GeneratedFiles, readText, type StoredFile } from './generatedFiles'
import { type FolderId, folderTitle } from './win95Files'
import type { Win95Window } from './win95Windows'

interface Item {
  key: string
  kind: 'folder' | 'file' | 'window'
  label: string
  /** Shown in the status bar when selected. */
  detail: string
  icon: ReactNode
  folder?: GeneratedFolder
  file?: StoredFile
  window?: Win95Window
}

interface Win95ExplorerProps {
  folder: FolderId
  onNavigate: (folder: FolderId) => void
  files: GeneratedFiles
  closedWindows: Win95Window[]
  onRestoreWindow: (id: string) => void
  /** Opens a stored file: reports in Notepad, anything else is downloaded. */
  onOpenFile: (file: StoredFile) => void
  minimized: boolean
  onMinimize: () => void
  onClose: () => void
  active: boolean
  onActivate: () => void
}

const when = (ms: number) => new Date(ms).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })

/**
 * An Explorer window onto My Documents and the Recycle Bin, in large-icons view. Items select on a
 * click and open on a double-click or Enter (folders navigate, reports open in Notepad, signatures
 * and keystores download); Delete sends a file to the Recycle Bin, Backspace goes up a level. In the
 * Recycle Bin, opening an item restores it, and Empty Recycle Bin deletes for good after asking.
 */
export function Win95Explorer(props: Win95ExplorerProps) {
  const { folder, onNavigate, files, closedWindows, onRestoreWindow, onOpenFile, minimized, onMinimize, onClose, active, onActivate } = props
  // Both belong to the folder they were made in, so they reset when Explorer navigates.
  const [selection, setSelection] = useState({ folder, index: 0 })
  const [confirmIn, setConfirmIn] = useState<FolderId | null>(null)
  const selected = selection.folder === folder ? selection.index : 0
  const confirmEmpty = confirmIn === folder
  const setSelected = (index: number) => setSelection({ folder, index })
  const setConfirmEmpty = (on: boolean) => setConfirmIn(on ? folder : null)
  const listRef = useRef<HTMLDivElement>(null)
  const title = folderTitle(folder)

  const items = useMemo<Item[]>(() => {
    if (folder === 'docs') {
      return FOLDERS.map(f => {
        const n = files.files.filter(x => x.folder === f.id && !x.deleted).length
        return { key: f.id, kind: 'folder', label: f.label, detail: `${n} object(s)`, icon: <FolderIcon />, folder: f.id }
      })
    }
    if (folder === 'bin') {
      return [
        ...closedWindows.map(w => ({
          key: w.id, kind: 'window' as const, label: w.title, detail: 'Closed window', icon: <WindowIcon />, window: w,
        })),
        ...files.files.filter(f => f.deleted).map(f => ({
          key: f.id, kind: 'file' as const, label: f.name, icon: <FileIcon folder={f.folder} />, file: f,
          detail: `From ${folderTitle(f.folder)}, ${formatSize(f.size)}`,
        })),
      ]
    }
    return files.files.filter(f => f.folder === folder && !f.deleted).map(f => ({
      key: f.id, kind: 'file' as const, label: f.name, icon: <FileIcon folder={f.folder} />, file: f,
      detail: `${formatSize(f.size)}, created ${when(f.created)}`,
    }))
  }, [folder, files.files, closedWindows])

  const current = items[Math.min(selected, items.length - 1)]

  const focusItem = (i: number) => {
    const next = Math.max(0, Math.min(items.length - 1, i))
    setSelected(next)
    listRef.current?.querySelectorAll<HTMLElement>('[role=option]')[next]?.focus()
  }

  const open = (item: Item | undefined) => {
    if (!item) return
    if (item.kind === 'folder') {
      emitChrome('open')
      onNavigate(item.folder!)
    } else if (item.kind === 'window') onRestoreWindow(item.window!.id)
    else if (folder === 'bin') files.setDeleted(item.file!.id, false)
    else onOpenFile(item.file!)
  }

  const remove = (item: Item | undefined) => {
    if (!item?.file || folder === 'bin') return
    files.setDeleted(item.file.id, true)
    emitChrome('close')
  }

  const up = () => {
    if (folder !== 'docs' && folder !== 'bin') onNavigate('docs')
  }

  const onKey = (e: ReactKeyboardEvent) => {
    const perRow = Math.max(1, Math.floor((listRef.current?.clientWidth ?? 300) / 88))
    switch (e.key) {
      case 'ArrowRight': focusItem(selected + 1); break
      case 'ArrowLeft': focusItem(selected - 1); break
      case 'ArrowDown': focusItem(selected + perRow); break
      case 'ArrowUp': focusItem(selected - perRow); break
      case 'Home': focusItem(0); break
      case 'End': focusItem(items.length - 1); break
      case 'Enter': open(current); break
      case 'Delete': remove(current); break
      case 'Backspace': up(); break
      default: return
    }
    e.preventDefault()
  }

  const total = items.reduce((sum, i) => sum + (i.file?.size ?? 0), 0)
  const binned = items.length

  return (
    <Win95Frame
      title={title}
      icon={folder === 'bin' ? <BinIcon size={14} full={binned > 0} /> : <DocumentsIcon size={14} />}
      initial={{ x: Math.max(8, window.innerWidth / 2 - 220), y: Math.max(56, window.innerHeight / 2 - 200) }}
      minimized={minimized}
      onMinimize={onMinimize}
      onClose={onClose}
      className="w95-explorer"
      active={active}
      onActivate={onActivate}
    >
      <div className="w95-toolbar" role="toolbar" aria-label={`${title} toolbar`}>
        <button type="button" className="w95-tool" disabled={folder === 'docs' || folder === 'bin'} onClick={up}>Up</button>
        {folder === 'bin' ? (
          <>
            <button type="button" className="w95-tool" disabled={!current} onClick={() => open(current)}>Restore</button>
            <button type="button" className="w95-tool" disabled={!files.files.some(f => f.deleted)} onClick={() => setConfirmEmpty(true)}>
              Empty Recycle Bin
            </button>
          </>
        ) : (
          <>
            <button type="button" className="w95-tool" disabled={!current} onClick={() => open(current)}>Open</button>
            <button type="button" className="w95-tool" disabled={current?.kind !== 'file'} onClick={() => remove(current)}>Delete</button>
          </>
        )}
      </div>

      {confirmEmpty && (
        <div className="w95-confirm" role="alertdialog" aria-label="Confirm File Delete">
          <span>Are you sure you want to delete these files for good?</span>
          <button
            type="button"
            className="w95-button"
            autoFocus
            onClick={() => {
              files.emptyBin()
              emitChrome('close')
              setConfirmEmpty(false)
            }}
          >
            Yes
          </button>
          <button type="button" className="w95-button" onClick={() => setConfirmEmpty(false)}>No</button>
        </div>
      )}

      <div ref={listRef} className="w95-icons" role="listbox" aria-label={title} aria-orientation="horizontal" onKeyDown={onKey}>
        {items.length === 0 && <p className="w95-empty">This folder is empty.</p>}
        {items.map((item, i) => (
          <button
            key={item.key}
            type="button"
            role="option"
            aria-selected={i === selected}
            tabIndex={i === selected ? 0 : -1}
            title={item.detail}
            className="w95-icon"
            onClick={() => setSelected(i)}
            onDoubleClick={() => open(item)}
          >
            {item.icon}
            <span>{item.label}</span>
          </button>
        ))}
      </div>

      <div className="w95-statusbar">
        <span>{current ? current.detail : `${items.length} object(s)`}</span>
        <span>{total ? formatSize(total) : ''}</span>
      </div>
    </Win95Frame>
  )
}

interface Win95NotepadProps {
  file: StoredFile
  minimized: boolean
  onMinimize: () => void
  onClose: () => void
  active: boolean
  onActivate: () => void
}

/** Notepad, read-only, for opening a report from My Documents; Save downloads it. */
export function Win95Notepad({ file, minimized, onMinimize, onClose, active, onActivate }: Win95NotepadProps) {
  const [text, setText] = useState('')

  useEffect(() => {
    let live = true
    void readText(file.blob).then((t: string) => { if (live) setText(t) })
    return () => { live = false }
  }, [file])

  return (
    <Win95Frame
      title={`${file.name} - Notepad`}
      initial={{ x: Math.max(8, window.innerWidth / 2 - 160), y: Math.max(64, window.innerHeight / 2 - 160) }}
      minimized={minimized}
      onMinimize={onMinimize}
      onClose={onClose}
      className="w95-notepad"
      active={active}
      onActivate={onActivate}
    >
      <div className="w95-toolbar" role="toolbar" aria-label="Notepad toolbar">
        <button type="button" className="w95-tool" onClick={() => download(file)}>Save</button>
      </div>
      <pre className="w95-notepad-text" tabIndex={0} aria-label={file.name}>{text}</pre>
    </Win95Frame>
  )
}
