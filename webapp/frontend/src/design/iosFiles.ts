/**
 * How the iPadOS Files app names, dates, sorts and groups the generated files. Plain functions over
 * plain data, so they can be tested without rendering anything.
 */
import type { StoredFile } from './generatedFiles'

export interface FileKind {
  /** What Files calls it, e.g. "CAdES Signature". */
  label: string
  /** The short type shown on the thumbnail, e.g. "P7S". */
  badge: string
  color: string
}

const KINDS: Record<string, FileKind> = {
  p7s: { label: 'CAdES Signature', badge: 'P7S', color: '#0a6cf0' },
  p7m: { label: 'CAdES Signature', badge: 'P7M', color: '#0a6cf0' },
  txt: { label: 'Plain Text', badge: 'TXT', color: '#8e8e93' },
  xml: { label: 'XML Document', badge: 'XML', color: '#f08a00' },
  p12: { label: 'PKCS #12 Keystore', badge: 'P12', color: '#a050dc' },
  pfx: { label: 'PKCS #12 Keystore', badge: 'PFX', color: '#a050dc' },
  pdf: { label: 'PDF Document', badge: 'PDF', color: '#e0352b' },
}

const extension = (name: string) => {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : ''
}

export function fileKind(name: string): FileKind {
  const ext = extension(name)
  return KINDS[ext] ?? { label: 'Document', badge: ext ? ext.slice(0, 4).toUpperCase() : 'FILE', color: '#8e8e93' }
}

const DAY = 86_400_000
const startOfDay = (ms: number) => {
  const d = new Date(ms)
  d.setHours(0, 0, 0, 0)
  return d.getTime()
}

/** Days between the calendar days of `ms` and `now`: 0 today, 1 yesterday. */
export const daysAgo = (ms: number, now: number) => Math.round((startOfDay(now) - startOfDay(ms)) / DAY)

/** A file's date as Files shows it: "Today at 9:41", "Yesterday at 17:02", "Monday", then the date. */
export function fileDate(ms: number, now: number, withTime = true) {
  const days = daysAgo(ms, now)
  const time = new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
  if (days <= 0) return withTime ? `Today at ${time}` : 'Today'
  if (days === 1) return withTime ? `Yesterday at ${time}` : 'Yesterday'
  if (days < 7) return new Date(ms).toLocaleDateString([], { weekday: 'long' })
  return new Date(ms).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' })
}

/** "332 bytes", "4 KB", "1.2 MB", as Finder and Files round them. */
export function fileSize(bytes: number) {
  if (bytes < 1000) return `${bytes} byte${bytes === 1 ? '' : 's'}`
  if (bytes < 1_000_000) return `${Math.round(bytes / 1000)} KB`
  return `${(bytes / 1_000_000).toFixed(1)} MB`
}

export type SortKey = 'name' | 'date' | 'size' | 'kind'

export interface SortOrder {
  key: SortKey
  /** Ascending: A to Z, oldest first, smallest first. */
  ascending: boolean
}

/** Newest first, as Files starts. */
export const DEFAULT_SORT: SortOrder = { key: 'date', ascending: false }

/** The order a new sort key starts in: names and kinds A to Z, dates and sizes biggest first. */
export const naturalOrder = (key: SortKey) => key === 'name' || key === 'kind'

/** Choosing the column already sorted by turns it round; another column starts in its natural order. */
export const nextSort = (current: SortOrder, key: SortKey): SortOrder =>
  current.key === key ? { key, ascending: !current.ascending } : { key, ascending: naturalOrder(key) }

const COMPARE: Record<SortKey, (a: StoredFile, b: StoredFile) => number> = {
  name: (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }),
  date: (a, b) => a.created - b.created,
  size: (a, b) => a.size - b.size,
  kind: (a, b) => fileKind(a.name).label.localeCompare(fileKind(b.name).label) || a.name.localeCompare(b.name),
}

export function sortFiles(files: readonly StoredFile[], order: SortOrder) {
  const sign = order.ascending ? 1 : -1
  return [...files].sort((a, b) => sign * COMPARE[order.key](a, b) || COMPARE.name(a, b))
}

/** Files by when they were made: Today, Yesterday, Previous 7 Days, Earlier. Empty groups are left out. */
export function groupByDate(files: readonly StoredFile[], now: number) {
  const groups: Array<{ title: string; files: StoredFile[] }> = [
    { title: 'Today', files: [] }, { title: 'Yesterday', files: [] }, { title: 'Previous 7 Days', files: [] }, { title: 'Earlier', files: [] },
  ]
  for (const f of files) {
    const days = daysAgo(f.created, now)
    groups[days <= 0 ? 0 : days === 1 ? 1 : days < 7 ? 2 : 3].files.push(f)
  }
  return groups.filter(g => g.files.length)
}

/** The name without its extension, which a rename starts by selecting. */
export const stem = (name: string) => {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? name.slice(0, dot) : name
}
