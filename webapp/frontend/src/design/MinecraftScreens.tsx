import { type DragEvent, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, useEffect, useRef, useState } from 'react'
import { type GeneratedFiles, type StoredFile, download, formatSize } from './generatedFiles'
import { ADVANCEMENTS, readAdvancements } from './minecraftState'
import type { Outcome } from './signals'
import { trapFocus } from './trapFocus'

/** The chest's slots, as a single chest has. */
export const CHEST_SLOTS = 27

interface ScreenProps {
  title: string
  onClose: () => void
  children: ReactNode
  className?: string
  /** An alert dialog (the death screen): it needs a choice, and Escape still closes it. */
  alert?: boolean
}

/**
 * A screen over the app in the game's GUI style: a modal dialog that takes focus, keeps Tab inside
 * and closes on Escape, giving focus back to whatever had it.
 */
export function McScreen({ title, onClose, children, className, alert }: ScreenProps) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null
    const first = ref.current?.querySelector<HTMLElement>('[data-autofocus]') ?? ref.current
    first?.focus()
    return () => before?.focus?.()
  }, [])
  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      e.stopPropagation()
      onClose()
    } else if (e.key === 'Tab') trapFocus(e.nativeEvent, ref.current)
  }
  return (
    <div className="mc-screen-backdrop">
      <div
        ref={ref}
        className={`mc-screen ${className ?? ''}`}
        role={alert ? 'alertdialog' : 'dialog'}
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        <h2>{title}</h2>
        {children}
        {!alert && <button type="button" className="mc-button" onClick={onClose}>Done</button>}
      </div>
    </div>
  )
}

const FOLDER_ITEM: Record<StoredFile['folder'], string> = { signatures: 'Signature', reports: 'Report', keystores: 'Keystore' }

/**
 * The chest: every signature, report and keystore the app made (the store the Windows 95 and iPadOS
 * themes share), newest first, one per slot. A slot downloads its file; dragged into the lava, or
 * with Delete pressed on it, the file goes to the bin. Hovering shows the game's item tooltip.
 */
export function MinecraftChest({ store, onClose }: { store: GeneratedFiles; onClose: () => void }) {
  const files = store.files.filter(f => !f.deleted).sort((a, b) => b.created - a.created)
  const shown = files.slice(0, CHEST_SLOTS)
  const [tip, setTip] = useState<StoredFile | null>(null)
  const [said, setSaid] = useState('')
  const [hot, setHot] = useState(false)

  const burn = (f: StoredFile) => {
    store.setDeleted(f.id, true)
    setSaid(`${f.name} burned in the lava (it is in the bin)`)
    setTip(null)
  }

  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setHot(false)
    const f = files.find(x => x.id === e.dataTransfer.getData('text/x-mc-file'))
    if (f) burn(f)
  }

  return (
    <McScreen title="Chest" onClose={onClose} className="mc-chest">
      <p className="mc-chest-note">
        {files.length ? `${files.length} item${files.length === 1 ? '' : 's'}. Click to take one (download), drag it into the lava or press Delete to burn it.` : 'Empty. Signatures, reports and keystores you make land here.'}
      </p>
      <ul className="mc-chest-slots" aria-label="Chest slots">
        {Array.from({ length: CHEST_SLOTS }, (_, i) => {
          const f = shown[i]
          return (
            <li key={f?.id ?? `empty-${i}`}>
              {f ? (
                <button
                  type="button"
                  className="mc-slot"
                  data-item={f.folder}
                  data-autofocus={i === 0 || undefined}
                  draggable
                  aria-label={`${f.name}, ${FOLDER_ITEM[f.folder]}, ${formatSize(f.size)}`}
                  onClick={() => download(f)}
                  onKeyDown={(e: ReactKeyboardEvent) => {
                    if (e.key === 'Delete' || e.key === 'Backspace') {
                      e.preventDefault()
                      burn(f)
                    }
                  }}
                  onDragStart={(e: DragEvent) => e.dataTransfer.setData('text/x-mc-file', f.id)}
                  onMouseEnter={() => setTip(f)}
                  onMouseLeave={() => setTip(null)}
                  onFocus={() => setTip(f)}
                  onBlur={() => setTip(null)}
                />
              ) : (
                <span className="mc-slot" aria-hidden="true" />
              )}
            </li>
          )
        })}
      </ul>
      <div className="mc-tooltip-area">
        {tip && (
          <div className="mc-tooltip" role="tooltip">
            <b data-item={tip.folder}>{tip.name}</b>
            <span>{FOLDER_ITEM[tip.folder]}</span>
            <span className="mc-tooltip-dim">{formatSize(tip.size)} · {new Date(tip.created).toLocaleString()}</span>
          </div>
        )}
      </div>
      {files.length > CHEST_SLOTS && <p className="mc-chest-note">{files.length - CHEST_SLOTS} more in the Windows 95 and iPadOS file browsers.</p>}
      <div
        className="mc-lava"
        data-hot={hot || undefined}
        onDragOver={(e: DragEvent) => {
          e.preventDefault()
          setHot(true)
        }}
        onDragLeave={() => setHot(false)}
        onDrop={onDrop}
        aria-hidden="true"
      >
        Lava
      </div>

      <p className="mc-sr" aria-live="polite">{said}</p>
    </McScreen>
  )
}

/** The advancements: every one, done or not, with when it was made. */
export function MinecraftAdvancements({ onClose }: { onClose: () => void }) {
  const done = readAdvancements()
  const count = ADVANCEMENTS.filter(a => done[a.id]).length
  return (
    <McScreen title="Advancements" onClose={onClose} className="mc-advancements">
      <p>{count} of {ADVANCEMENTS.length} made</p>
      <ul>
        {ADVANCEMENTS.map(a => (
          <li key={a.id} data-done={done[a.id] ? true : undefined}>
            <span className="mc-adv-icon" aria-hidden="true" />
            <span>
              <b>{a.title}</b>
              <span>{a.description}</span>
            </span>
            <span className="mc-sr">{done[a.id] ? `, made ${new Date(done[a.id]!).toLocaleDateString()}` : ', not yet made'}</span>
          </li>
        ))}
      </ul>
    </McScreen>
  )
}

/** The death screen after a failed operation: what went wrong, the score, and Respawn (retry) or Title Screen (start over). */
export function DeathScreen({ title, message, score, onRespawn, onTitle, onClose }: {
  title?: string
  message?: string
  score: number
  onRespawn: () => void
  onTitle: () => void
  onClose: () => void
}) {
  return (
    <McScreen title="You died!" onClose={onClose} className="mc-death" alert>
      <p>{title ? `Steve was slain by ${title}` : 'Steve was slain'}</p>
      {message && <p className="mc-death-detail">{message}</p>}
      <p>Score: <b>{score}</b></p>
      <button type="button" className="mc-button" data-autofocus onClick={onRespawn}>Respawn</button>
      <button type="button" className="mc-button" onClick={onTitle}>Title Screen</button>
    </McScreen>
  )
}

export interface Operation {
  kind: Outcome
  title: string
  action?: string
  at: number
}

const PING: Record<Outcome, number> = { success: 5, info: 4, warning: 2, error: 0 }

/** Held Tab: this session's operations as the server's player list, each with its "ping". */
export function PlayerList({ operations }: { operations: Operation[] }) {
  return (
    <div className="mc-players" aria-hidden="true">
      <b>Operations this session: {operations.length}</b>
      <ul>
        {operations.length ? operations.slice(-12).map((o, i) => (
          <li key={i} data-kind={o.kind}>
            <span>{o.title}</span>
            <span className="mc-ping" data-bars={PING[o.kind]}><i /><i /><i /><i /><i /></span>
          </li>
        )) : <li>Nobody here yet. Sign or verify something.</li>}
      </ul>
    </div>
  )
}
