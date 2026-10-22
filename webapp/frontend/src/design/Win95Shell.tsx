import { useCallback, useEffect, useRef, useState } from 'react'
import type { View } from '../components/layout/AppShell'
import { emitChrome } from './signals'
import { useDesign } from './useDesign'
import { Win95Assistant } from './Win95Assistant'
import { Win95Desktop } from './Win95Desktop'
import { Win95Explorer, Win95Notepad } from './Win95Explorer'
import { download, type FolderId, folderTitle, type StoredFile, useWin95Files } from './win95Files'
import { Win95Shutdown } from './Win95Shutdown'
import { type Task, Win95Taskbar } from './Win95Taskbar'
import { type Win95Window, WindowManager } from './win95Windows'

interface Win95ShellProps {
  view: View
  onViewChange: (view: View) => void
  onOpenAppearance: () => void
  onOpenAbout: () => void
}

const ASSISTANT_KEY = 'cades-w95-assistant'

const readHidden = () => {
  try {
    return window.localStorage.getItem(ASSISTANT_KEY) === 'hidden'
  } catch {
    return false
  }
}

/**
 * Everything the Windows 95 theme adds on top of the app: the taskbar and Start menu, the desktop
 * icons, Explorer and Notepad onto the generated files, Paperclip, the shutdown sequence, and the
 * window manager that turns the app's cards into windows. Rendered only while the theme is active,
 * so the files are recorded and the cards managed only then.
 */
export function Win95Shell({ view, onViewChange, onOpenAppearance, onOpenAbout }: Win95ShellProps) {
  const { setTheme } = useDesign()
  const [windows, setWindows] = useState<Win95Window[]>([])
  const manager = useRef<WindowManager | null>(null)
  const files = useWin95Files()
  const [explorer, setExplorer] = useState<{ folder: FolderId; minimized: boolean } | null>(null)
  const [notepad, setNotepad] = useState<{ file: StoredFile; minimized: boolean } | null>(null)
  const [assistantHidden, setAssistantHidden] = useState(readHidden)
  const [shuttingDown, setShuttingDown] = useState(false)
  /** Which of the desktop's own windows is in front. */
  const [front, setFront] = useState<'explorer' | 'notepad'>('explorer')

  useEffect(() => {
    const m = new WindowManager(setWindows)
    m.start()
    manager.current = m
    return () => {
      m.stop()
      manager.current = null
    }
  }, [])

  const openFolder = useCallback((folder: FolderId) => {
    emitChrome('open')
    setExplorer({ folder, minimized: false })
    setFront('explorer')
  }, [])

  const openFile = useCallback((file: StoredFile) => {
    if (file.folder === 'reports') {
      emitChrome('open')
      setNotepad({ file, minimized: false })
      setFront('notepad')
    } else download(file)
  }, [])

  const setHidden = useCallback((hidden: boolean) => {
    setAssistantHidden(hidden)
    try {
      window.localStorage.setItem(ASSISTANT_KEY, hidden ? 'hidden' : 'shown')
    } catch {
      // Storage blocked: the choice lasts for this visit only.
    }
  }, [])

  const closeShutdown = useCallback(() => {
    setShuttingDown(false)
    document.querySelector<HTMLElement>('.w95-start')?.focus()
  }, [])
  const leaveTheme = useCallback(() => setTheme('none'), [setTheme])

  const closed = windows.filter(w => w.state === 'closed')
  const tasks: Task[] = [
    ...windows.filter(w => w.state === 'minimized').map(w => ({
      id: w.id, label: w.title, open: false, onClick: () => manager.current?.restore(w.id),
    })),
    ...(explorer ? [{
      id: 'explorer', label: folderTitle(explorer.folder), open: !explorer.minimized,
      onClick: () => setExplorer({ ...explorer, minimized: !explorer.minimized }),
    }] : []),
    ...(notepad ? [{
      id: 'notepad', label: `${notepad.file.name} - Notepad`, open: !notepad.minimized,
      onClick: () => setNotepad({ ...notepad, minimized: !notepad.minimized }),
    }] : []),
  ]

  return (
    <>
      <Win95Desktop
        documents={files.files.filter(f => !f.deleted).length}
        binned={closed.length + files.files.filter(f => f.deleted).length}
        onOpen={openFolder}
      />
      {explorer && (
        <Win95Explorer
          folder={explorer.folder}
          onNavigate={folder => setExplorer({ folder, minimized: false })}
          files={files}
          closedWindows={closed}
          onRestoreWindow={id => manager.current?.restore(id)}
          onOpenFile={openFile}
          minimized={explorer.minimized}
          onMinimize={() => {
            emitChrome('minimize')
            setExplorer({ ...explorer, minimized: true })
          }}
          onClose={() => setExplorer(null)}
          active={front === 'explorer'}
          onActivate={() => setFront('explorer')}
        />
      )}
      {notepad && (
        <Win95Notepad
          file={notepad.file}
          minimized={notepad.minimized}
          onMinimize={() => {
            emitChrome('minimize')
            setNotepad({ ...notepad, minimized: true })
          }}
          onClose={() => setNotepad(null)}
          active={front === 'notepad'}
          onActivate={() => setFront('notepad')}
        />
      )}
      {/* The computer is off during the shutdown sequence, Paperclip included. */}
      {!assistantHidden && !shuttingDown && <Win95Assistant onHide={() => setHidden(true)} onOpenDocuments={() => openFolder('docs')} />}
      <Win95Taskbar
        view={view}
        onViewChange={onViewChange}
        onOpenAppearance={onOpenAppearance}
        onOpenAbout={onOpenAbout}
        onOpenDocuments={() => openFolder('docs')}
        tasks={tasks}
        assistantHidden={assistantHidden}
        onToggleAssistant={() => setHidden(!assistantHidden)}
        onShutdown={() => setShuttingDown(true)}
      />
      {shuttingDown && <Win95Shutdown onClose={closeShutdown} onLeave={leaveTheme} />}
    </>
  )
}
