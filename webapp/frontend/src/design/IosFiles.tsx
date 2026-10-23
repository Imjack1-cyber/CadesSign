import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react'
import { download, FOLDERS, type GeneratedFiles, readText, type StoredFile } from './generatedFiles'
import type { AlertSpec, MenuItem } from './IosAlert'
import { FileThumb, FolderIcon, Glyph, type GlyphName } from './IosIcons'
import { useClock } from './iosDevice'
import { DEFAULT_SORT, fileDate, fileKind, fileSize, groupByDate, nextSort, type SortKey, type SortOrder, sortFiles, stem } from './iosFiles'
import { type Point, useLongPress } from './iosGestures'
import { IosSheet } from './IosSheet'
import type { GeneratedFolder } from './signals'

/** Recents, the device with its folders, one of the folders, or Recently Deleted. */
export type FilesPlace = 'recents' | 'device' | GeneratedFolder | 'deleted'

const FOLDER_GLYPH: Record<GeneratedFolder, GlyphName> = { signatures: 'seal', reports: 'doc-text', keystores: 'key' }
const SORT_LABEL: Record<SortKey, string> = { name: 'Name', date: 'Date', size: 'Size', kind: 'Kind' }
/** A row swiped left further than this (px) is deleted without waiting for the button. */
const FULL_SWIPE = 160
const REVEAL = 80

const folderLabel = (id: string) => FOLDERS.find(f => f.id === id)?.label ?? 'Files'

interface EntryProps {
  file: StoredFile
  grid: boolean
  /** iPad lists show Date, Size and Kind in columns of their own. */
  columns: boolean
  now: number
  selecting: boolean
  selected: boolean
  renaming: boolean
  onOpen: (f: StoredFile) => void
  onToggle: (f: StoredFile) => void
  onMenu: (f: StoredFile, at: Point) => void
  onDelete: (f: StoredFile) => void
  onRename: (f: StoredFile, name: string | null) => void
}

/** The name being edited: the name without its extension is selected; Enter keeps it, Escape does not. */
function RenameField({ file, onDone }: { file: StoredFile; onDone: (name: string | null) => void }) {
  const ref = useRef<HTMLInputElement>(null)
  const done = useRef(false)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    el.focus()
    el.setSelectionRange(0, stem(file.name).length)
  }, [file.name])
  const finish = (name: string | null) => {
    if (done.current) return
    done.current = true
    onDone(name)
  }
  return (
    <input
      ref={ref}
      className="ios-rename"
      data-escape
      aria-label={`New name for ${file.name}`}
      defaultValue={file.name}
      spellCheck={false}
      onKeyDown={e => {
        if (e.key === 'Enter') finish(e.currentTarget.value)
        else if (e.key === 'Escape') finish(null)
      }}
      onBlur={e => finish(e.currentTarget.value)}
      onClick={e => e.stopPropagation()}
    />
  )
}

/** A file as an icon tile or a list row. A row swipes left to delete; both open their menu on a long press. */
function FileEntry(props: EntryProps) {
  const { file, grid, columns, now, selecting, selected, renaming, onOpen, onToggle, onMenu, onDelete, onRename } = props
  const { handlers, fired } = useLongPress(at => !selecting && onMenu(file, at))
  const [dx, setDx] = useState(0)
  const swipe = useRef<{ x: number; moved: boolean } | null>(null)
  const kind = fileKind(file.name)

  const onDown = (e: ReactPointerEvent) => {
    handlers.onPointerDown(e)
    if (!grid && !selecting && e.pointerType !== 'mouse') swipe.current = { x: e.clientX - dx, moved: false }
  }
  const onMove = (e: ReactPointerEvent) => {
    handlers.onPointerMove(e)
    const s = swipe.current
    if (!s) return
    const d = Math.min(0, e.clientX - s.x)
    if (Math.abs(d) > 6) s.moved = true
    setDx(d)
  }
  const onUp = () => {
    handlers.onPointerUp()
    const s = swipe.current
    swipe.current = null
    if (!s) return
    if (dx < -FULL_SWIPE) {
      setDx(0)
      onDelete(file)
    } else setDx(dx < -REVEAL / 2 ? -REVEAL : 0)
  }

  const date = fileDate(file.created, now, !grid)
  // What the entry shows, around its name; while renaming, the name is a field (which cannot sit in a button).
  const content = (name: React.ReactNode) => (
    <>
      {selecting && <span className="ios-file-check" aria-hidden="true">{selected && <Glyph name="check-circle" size={22} />}</span>}
      <span className="ios-file-thumb"><FileThumb name={file.name} size={grid ? 64 : 34} /></span>
      <span className="ios-file-text">
        {name}
        {grid ? (
          <>
            <span>{date}</span>
            <span>{fileSize(file.size)}</span>
          </>
        ) : !columns && <span>{`${date} · ${fileSize(file.size)}`}</span>}
      </span>
      {columns && !grid && (
        <>
          <span className="ios-file-col ios-file-col--date">{date}</span>
          <span className="ios-file-col ios-file-col--size">{fileSize(file.size)}</span>
          <span className="ios-file-col ios-file-col--kind">{kind.label}</span>
        </>
      )}
    </>
  )
  return (
    <li
      className={grid ? 'ios-file-tile' : 'ios-file-row'}
      data-selected={selected || undefined}
      style={{ '--swipe': `${dx}px` } as React.CSSProperties}
    >
      {!grid && (
        <button type="button" className="ios-file-delete" tabIndex={dx ? 0 : -1} aria-hidden={!dx} onClick={() => onDelete(file)}>
          <Glyph name="trash" size={18} />
          <span>Delete</span>
        </button>
      )}
      <div className="ios-file-body">
        {renaming ? (
          <div className="ios-file-open">{content(<RenameField file={file} onDone={n => onRename(file, n)} />)}</div>
        ) : (
        <button
          type="button"
          className="ios-file-open"
          {...handlers}
          onPointerDown={onDown}
          onPointerMove={onMove}
          onPointerUp={onUp}
          onPointerCancel={onUp}
          onClick={() => {
            if (fired() || swipe.current?.moved) return
            if (dx) setDx(0)
            else if (selecting) onToggle(file)
            else onOpen(file)
          }}
          aria-pressed={selecting ? selected : undefined}
          aria-label={`${file.name}, ${kind.label}, ${fileSize(file.size)}, ${fileDate(file.created, now)}`}
        >
          {content(<b>{file.name}</b>)}
        </button>
        )}
        {!grid && !selecting && !renaming && (
          <button
            type="button"
            className="ios-file-more"
            aria-label={`Actions for ${file.name}`}
            onClick={e => {
              const r = e.currentTarget.getBoundingClientRect()
              onMenu(file, { x: r.right, y: r.bottom })
            }}
          >
            <Glyph name="ellipsis" size={18} />
          </button>
        )}
      </div>
    </li>
  )
}

interface IosFilesProps {
  files: GeneratedFiles
  phone: boolean
  presentation: 'sheet' | 'page'
  onClose: () => void
  /** Opens a file in Quick Look, with the files around it to page through. */
  onQuickLook: (f: StoredFile, list: StoredFile[]) => void
  onMenu: (at: Point, title: string, items: MenuItem[]) => void
  onAlert: (alert: AlertSpec) => void
}

/**
 * The Files app onto what the app generated. Browse Recents (grouped by day), the device with its
 * Signatures, Reports and Keystores folders, or Recently Deleted; search; show icons or a list (on
 * iPad with Name, Date, Size and Kind columns that sort, and sort the other way when chosen again).
 * Tapping a file opens Quick Look. Holding it, right-clicking it or its "…" button offers Quick
 * Look, Rename, Share, Select and Delete; a list row also swipes left to delete. Select picks several
 * files at once to share, delete or recover. On iPad it is a sheet with a sidebar; on a phone a tab
 * with the places as a row of chips.
 */
export function IosFiles({ files, phone, presentation, onClose, onQuickLook, onMenu, onAlert }: IosFilesProps) {
  const now = useClock().getTime()
  const [place, setPlace] = useState<FilesPlace>('recents')
  /** Where Back goes: the device, when a folder was opened from it. */
  const [parent, setParent] = useState<FilesPlace | null>(null)
  const [query, setQuery] = useState('')
  const [grid, setGrid] = useState(!phone)
  const [sort, setSort] = useState<SortOrder>(DEFAULT_SORT)
  const [groups, setGroups] = useState(true)
  const [selecting, setSelecting] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(() => new Set())
  const [renaming, setRenaming] = useState<string | null>(null)
  const device = phone ? 'On My iPhone' : 'On My iPad'

  const go = (p: FilesPlace, from: FilesPlace | null = null) => {
    setPlace(p)
    setParent(from)
    setSelected(new Set())
    setSelecting(false)
    setRenaming(null)
  }

  const live = files.files.filter(f => !f.deleted)
  const count = (p: FilesPlace) =>
    p === 'deleted' ? files.files.length - live.length : p === 'recents' || p === 'device' ? live.length : live.filter(f => f.folder === p).length

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    const inPlace = (f: StoredFile) =>
      place === 'deleted' ? f.deleted : !f.deleted && (place === 'recents' || (place === 'device' ? !!q : f.folder === place))
    return sortFiles(files.files.filter(f => inPlace(f) && (!q || f.name.toLowerCase().includes(q))), sort)
  }, [files.files, place, query, sort])

  const title = place === 'recents' ? 'Recents' : place === 'device' ? device : place === 'deleted' ? 'Recently Deleted' : folderLabel(place)
  const showFolders = place === 'device' && !query.trim()
  const sections = groups && sort.key === 'date' && place !== 'deleted' ? groupByDate(shown, now) : [{ title: '', files: shown }]
  const columns = !phone && !grid

  const toggle = (f: StoredFile) => {
    const next = new Set(selected)
    if (next.has(f.id)) next.delete(f.id)
    else next.add(f.id)
    setSelected(next)
  }

  const confirmPurge = (list: StoredFile[], done?: () => void) => onAlert({
    title: list.length === 1 ? `Delete “${list[0].name}”?` : `Delete ${list.length} Files?`,
    message: `${list.length === 1 ? 'This file' : 'These files'} will be deleted immediately. You can’t undo this action.`,
    actions: [{ label: 'Cancel', style: 'cancel' }, {
      label: 'Delete', style: 'destructive', run: () => {
        files.purge(list.map(f => f.id))
        done?.()
      },
    }],
  })

  const remove = (f: StoredFile) => {
    if (f.deleted) confirmPurge([f])
    else files.setDeleted(f.id, true)
  }

  const menuFor = (f: StoredFile, at: Point) => onMenu(at, f.name, f.deleted
    ? [
        { label: 'Recover', glyph: 'recover', run: () => files.setDeleted(f.id, false) },
        { label: 'Delete Now', glyph: 'trash', destructive: true, run: () => remove(f) },
      ]
    : [
        { label: 'Quick Look', glyph: 'eye', run: () => onQuickLook(f, shown) },
        { label: 'Rename', glyph: 'pen', run: () => setRenaming(f.id) },
        { label: 'Share', glyph: 'share', run: () => download(f) },
        { label: 'Select', glyph: 'check-circle', run: () => { setSelecting(true); setSelected(new Set([f.id])) } },
        { label: 'Delete', glyph: 'trash', destructive: true, run: () => remove(f) },
      ])

  const moreMenu = (e: React.MouseEvent<HTMLButtonElement>) => {
    const r = e.currentTarget.getBoundingClientRect()
    const arrow = (k: SortKey) => (sort.key === k ? (sort.ascending ? ' ↑' : ' ↓') : '')
    onMenu({ x: r.right, y: r.bottom + 6 }, 'View Options', [
      { label: 'Icons', checked: grid, run: () => setGrid(true) },
      { label: 'List', checked: !grid, run: () => setGrid(false) },
      ...(['name', 'date', 'size', 'kind'] as SortKey[]).map((k): MenuItem => ({
        label: `${SORT_LABEL[k]}${arrow(k)}`, checked: sort.key === k, run: () => setSort(nextSort(sort, k)),
      })),
      { label: 'Use Groups', checked: groups, run: () => setGroups(!groups) },
    ])
  }

  const chosen = shown.filter(f => selected.has(f.id))
  const allChosen = shown.length > 0 && chosen.length === shown.length
  const totalSize = shown.reduce((sum, f) => sum + f.size, 0)

  // Escape leaves a selection before it closes Files.
  const escape = () => {
    if (selecting) {
      setSelecting(false)
      setSelected(new Set())
    } else onClose()
  }

  const places: ReadonlyArray<{ id: FilesPlace; label: string; glyph: GlyphName }> = [
    { id: 'recents', label: 'Recents', glyph: 'clock' },
    { id: 'device', label: device, glyph: phone ? 'iphone' : 'folder' },
    ...FOLDERS.map(f => ({ id: f.id as FilesPlace, label: f.label, glyph: FOLDER_GLYPH[f.id] })),
    { id: 'deleted', label: 'Recently Deleted', glyph: 'trash' },
  ]
  const sideItem = (p: (typeof places)[number]) => (
    <button key={p.id} type="button" className="ios-side-item" aria-current={p.id === place ? 'true' : undefined} onClick={() => go(p.id)}>
      <Glyph name={p.glyph} size={18} />
      <span>{p.label}</span>
      <span className="ios-side-count">{count(p.id) || ''}</span>
    </button>
  )

  return (
    <IosSheet label="Files" onClose={escape} presentation={presentation} className="ios-files">
      {!phone && (
        <nav className="ios-files-side" aria-label="Browse">
          <h2>Browse</h2>
          {sideItem(places[0])}
          <h3>Locations</h3>
          {sideItem(places[1])}
          {sideItem(places[5])}
          <h3>Favorites</h3>
          {places.slice(2, 5).map(sideItem)}
        </nav>
      )}
      <div className="ios-files-main">
        <header className="ios-navbar">
          {selecting ? (
            <>
              <button type="button" className="ios-text-button" onClick={() => setSelected(allChosen ? new Set() : new Set(shown.map(f => f.id)))}>
                {allChosen ? 'Deselect All' : 'Select All'}
              </button>
              <h2 className="ios-navbar-title" aria-live="polite">{chosen.length ? `${chosen.length} Selected` : 'Select Items'}</h2>
              <button type="button" className="ios-text-button ios-navbar-done" data-autofocus onClick={escape}>Done</button>
            </>
          ) : (
            <>
              {parent && (
                <button type="button" className="ios-back" onClick={() => go(parent)}>
                  <Glyph name="chevron-left" size={18} />
                  {parent === 'device' ? device : 'Back'}
                </button>
              )}
              <div className="ios-navbar-actions">
                {!showFolders && shown.length > 0 && <button type="button" className="ios-pill-button ios-pill-button--small" onClick={() => setSelecting(true)}>Select</button>}
                <div className="ios-segmented" role="group" aria-label="View">
                  <button type="button" aria-pressed={grid} aria-label="Icons" onClick={() => setGrid(true)}><Glyph name="grid" size={15} /></button>
                  <button type="button" aria-pressed={!grid} aria-label="List" onClick={() => setGrid(false)}><Glyph name="list" size={15} /></button>
                </div>
                <button type="button" className="ios-round-button" aria-label="View options" onClick={moreMenu}><Glyph name="ellipsis" size={16} /></button>
                {presentation === 'sheet' && <button type="button" className="ios-text-button ios-navbar-done" data-autofocus onClick={onClose}>Done</button>}
              </div>
              <h2 className="ios-large-title">{phone && place === 'recents' ? 'Files' : title}</h2>
            </>
          )}
        </header>
        <label className="ios-search">
          <Glyph name="search" size={16} />
          <input type="search" placeholder={place === 'device' || place === 'recents' ? 'Search' : `Search in ${title}`} aria-label="Search files" value={query} onChange={e => setQuery(e.target.value)} />
        </label>
        {phone && (
          <div className="ios-chips" role="group" aria-label="Browse">
            {places.map(p => (
              <button key={p.id} type="button" className="ios-chip" aria-pressed={p.id === place} onClick={() => go(p.id)}>{p.label}</button>
            ))}
          </div>
        )}
        {place === 'deleted' && shown.length > 0 && !selecting && (
          <div className="ios-files-bar">
            <span>Files stay here until you delete them.</span>
            <button type="button" className="ios-text-button" onClick={() => shown.forEach(f => files.setDeleted(f.id, false))}>Recover All</button>
            <button type="button" className="ios-text-button" data-destructive onClick={() => confirmPurge(shown)}>Delete All</button>
          </div>
        )}

        {showFolders ? (
          <ul className="ios-folder-grid" aria-label={device}>
            {FOLDERS.map(f => (
              <li key={f.id}>
                <button type="button" className="ios-folder" onClick={() => go(f.id, 'device')}>
                  <FolderIcon size={76} />
                  <b>{f.label}</b>
                  <span>{count(f.id)} item{count(f.id) === 1 ? '' : 's'}</span>
                </button>
              </li>
            ))}
          </ul>
        ) : shown.length ? (
          <div className="ios-file-sections">
            {columns && (
              <div className="ios-file-columns" role="group" aria-label="Sort by">
                {(['name', 'date', 'size', 'kind'] as SortKey[]).map(k => (
                  <button
                    key={k}
                    type="button"
                    data-col={k}
                    aria-pressed={sort.key === k}
                    aria-label={`Sort by ${SORT_LABEL[k]}${sort.key === k ? (sort.ascending ? ', ascending' : ', descending') : ''}`}
                    onClick={() => setSort(nextSort(sort, k))}
                  >
                    {SORT_LABEL[k]}
                    {sort.key === k && <span className="ios-sort-arrow" data-ascending={sort.ascending || undefined}><Glyph name="chevron-left" size={11} /></span>}
                  </button>
                ))}
              </div>
            )}
            {sections.map(section => (
              <section key={section.title || 'all'} className="ios-file-section" aria-label={section.title || title}>
                {section.title && <h3>{section.title}</h3>}
                <ul className={grid ? 'ios-file-grid' : 'ios-file-list ios-inset-group'}>
                  {section.files.map(f => (
                    <FileEntry
                      key={f.id} file={f} grid={grid} columns={columns} now={now} selecting={selecting} selected={selected.has(f.id)}
                      renaming={renaming === f.id} onOpen={file => onQuickLook(file, shown)} onToggle={toggle} onMenu={menuFor} onDelete={remove}
                      onRename={(file, name) => {
                        setRenaming(null)
                        if (name !== null) files.rename(file.id, name)
                      }}
                    />
                  ))}
                </ul>
              </section>
            ))}
          </div>
        ) : (
          <div className="ios-empty">
            <Glyph name={query ? 'search' : place === 'deleted' ? 'trash' : 'folder'} size={44} />
            <b>{query ? 'No Results' : place === 'deleted' ? 'No Recently Deleted Files' : 'No Files'}</b>
            <span>{query ? `Nothing matches “${query}”.` : 'Signatures you make, reports and keystores appear here.'}</span>
          </div>
        )}

        {selecting ? (
          <div className="ios-files-toolbar" role="toolbar" aria-label="Selection">
            {place === 'deleted' ? (
              <button type="button" className="ios-text-button" disabled={!chosen.length} onClick={() => { chosen.forEach(f => files.setDeleted(f.id, false)); escape() }}>Recover</button>
            ) : (
              <button type="button" className="ios-text-button" disabled={!chosen.length} onClick={() => chosen.forEach(download)}>
                <Glyph name="share" size={18} /> Share
              </button>
            )}
            <span>{chosen.length ? `${chosen.length} of ${shown.length}` : ''}</span>
            <button
              type="button" className="ios-text-button" data-destructive disabled={!chosen.length}
              onClick={() => {
                if (place === 'deleted') confirmPurge(chosen, escape)
                else {
                  chosen.forEach(f => files.setDeleted(f.id, true))
                  escape()
                }
              }}
            >
              <Glyph name="trash" size={18} /> Delete
            </button>
          </div>
        ) : (
          <p className="ios-files-foot">
            {showFolders ? `${FOLDERS.length} folders · ${live.length} items` : `${shown.length} item${shown.length === 1 ? '' : 's'}${shown.length ? ` · ${fileSize(totalSize)}` : ''}`}
          </p>
        )}
      </div>
    </IosSheet>
  )
}

interface QuickLookProps {
  /** The files to page through, and the one shown. */
  files: StoredFile[]
  id: string
  onShow: (id: string) => void
  onDelete: (f: StoredFile) => void
  onClose: () => void
}

/** A drag sideways further than this (px) moves to the next or previous file. */
const PAGE_PX = 70

/**
 * Quick Look: a report's text, or for anything without a preview its thumbnail and what Files knows
 * about it (kind, size, when, where). Share saves it to downloads; the arrows, the arrow keys or a
 * swipe sideways go through the files around it; Delete moves it to Recently Deleted.
 */
export function IosQuickLook({ files, id, onShow, onDelete, onClose }: QuickLookProps) {
  const now = useClock().getTime()
  const index = Math.max(0, files.findIndex(f => f.id === id))
  const file = files[index]
  const [text, setText] = useState<{ id: string; text: string } | null>(null)
  const drag = useRef<number | null>(null)
  const textual = file.folder === 'reports' || /\.(txt|xml)$/i.test(file.name)

  useEffect(() => {
    if (!textual) return
    let live = true
    readText(file.blob).then(t => live && setText({ id: file.id, text: t })).catch(() => {})
    return () => {
      live = false
    }
  }, [file, textual])

  const show = (i: number) => {
    if (i >= 0 && i < files.length) onShow(files[i].id)
  }
  const onKey = (e: ReactKeyboardEvent) => {
    if (e.key === 'ArrowRight') show(index + 1)
    else if (e.key === 'ArrowLeft') show(index - 1)
    else return
    e.preventDefault()
  }

  const kind = fileKind(file.name)
  const shownText = text?.id === file.id ? text.text : null
  return (
    <IosSheet label={`Quick Look: ${file.name}`} onClose={onClose} presentation="sheet" className="ios-quicklook">
      <div className="ios-quicklook-inner" onKeyDown={onKey}>
        <header className="ios-navbar ios-navbar--inline">
          <button type="button" className="ios-text-button" onClick={() => download(file)}><Glyph name="share" size={18} /> Share</button>
          <div className="ios-quicklook-title">
            <h2>{file.name}</h2>
            {files.length > 1 && <span>{index + 1} of {files.length}</span>}
          </div>
          <button type="button" className="ios-text-button" data-autofocus onClick={onClose}>Done</button>
        </header>
        <div
          className="ios-quicklook-body"
          key={file.id}
          onPointerDown={e => { drag.current = e.clientX }}
          onPointerUp={e => {
            const start = drag.current
            drag.current = null
            if (start === null) return
            if (e.clientX - start < -PAGE_PX) show(index + 1)
            else if (e.clientX - start > PAGE_PX) show(index - 1)
          }}
        >
          {textual && shownText !== null ? (
            <pre className="ios-quicklook-text" tabIndex={0} aria-label="Contents">{shownText}</pre>
          ) : (
            <div className="ios-quicklook-info">
              <FileThumb name={file.name} size={150} />
              <b>{file.name}</b>
              <span>{kind.label} · {fileSize(file.size)}</span>
              <dl>
                <div><dt>Kind</dt><dd>{kind.label}</dd></div>
                <div><dt>Size</dt><dd>{fileSize(file.size)} ({file.size.toLocaleString()} bytes)</dd></div>
                <div><dt>Created</dt><dd>{fileDate(file.created, now)}</dd></div>
                <div><dt>Where</dt><dd>{folderLabel(file.folder)}</dd></div>
              </dl>
              <button type="button" className="ios-pill-button" onClick={() => download(file)}>Save to Downloads</button>
            </div>
          )}
        </div>
        <footer className="ios-quicklook-bar">
          <button type="button" className="ios-round-button" aria-label="Previous file" disabled={index === 0} onClick={() => show(index - 1)}>
            <Glyph name="chevron-left" size={16} />
          </button>
          <button type="button" className="ios-text-button" data-destructive aria-label={`Delete ${file.name}`} onClick={() => onDelete(file)}>
            <Glyph name="trash" size={20} />
          </button>
          <button type="button" className="ios-round-button" aria-label="Next file" disabled={index === files.length - 1} onClick={() => show(index + 1)}>
            <Glyph name="chevron-right" size={16} />
          </button>
        </footer>
      </div>
    </IosSheet>
  )
}
