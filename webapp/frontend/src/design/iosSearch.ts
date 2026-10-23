/**
 * Spotlight for the iPadOS theme: everything the theme can find, and how well an entry matches what
 * was typed (title start, then a word start, then a keyword, then anywhere, then letters in order).
 * Plain data in, plain data out; IosSpotlight.tsx runs what is chosen.
 */
import type { GeneratedFolder, WizardCommand } from './signals'
import type { AppId } from './iosPrefs'
import type { GlyphName } from './IosIcons'

export type Surface = 'control' | 'notifications' | 'spotlight' | 'files' | 'settings' | 'home' | 'switcher'

export type SearchAction =
  | { type: 'view'; view: 'wizard' | 'dashboard' | 'about' }
  | { type: 'wizard'; command: WizardCommand }
  | { type: 'surface'; surface: Surface }
  | { type: 'lock' }
  | { type: 'appearance' }
  | { type: 'shortcuts' }
  | { type: 'toggle'; setting: 'dark' | 'sound' | 'focus' | 'transparency' | 'pointer' }
  | { type: 'leave' }
  | { type: 'file'; id: string }

export type Section = 'Actions' | 'Apps' | 'Files' | 'Settings' | 'Help'

export interface SearchItem {
  id: string
  section: Section
  title: string
  subtitle?: string
  /** Extra words it answers to. */
  keywords?: string
  app?: AppId
  glyph?: GlyphName
  action: SearchAction
}

export interface SearchFile {
  id: string
  name: string
  folder: GeneratedFolder
  created: number
}

const ITEMS: readonly SearchItem[] = [
  { id: 'sign', section: 'Actions', title: 'Sign a Document', subtitle: 'Sign / Verify', keywords: 'signature cades create new', app: 'sign', action: { type: 'wizard', command: { type: 'start', action: 'sign' } } },
  { id: 'verify', section: 'Actions', title: 'Verify a Signature', subtitle: 'Sign / Verify', keywords: 'check validate validation p7s', app: 'verify', action: { type: 'wizard', command: { type: 'start', action: 'verify' } } },
  { id: 'next', section: 'Actions', title: 'Next Step', subtitle: 'Sign / Verify', keywords: 'continue forward', glyph: 'chevron-right', action: { type: 'wizard', command: { type: 'next' } } },
  { id: 'back', section: 'Actions', title: 'Previous Step', subtitle: 'Sign / Verify', keywords: 'back return', glyph: 'chevron-left', action: { type: 'wizard', command: { type: 'back' } } },
  { id: 'run', section: 'Actions', title: 'Run', subtitle: 'Sign or verify now', keywords: 'go execute start', glyph: 'sparkles', action: { type: 'wizard', command: { type: 'run' } } },
  { id: 'reset', section: 'Actions', title: 'Start Over', subtitle: 'Sign / Verify', keywords: 'reset clear new', glyph: 'recover', action: { type: 'wizard', command: { type: 'reset' } } },
  { id: 'lock', section: 'Actions', title: 'Lock Screen', keywords: 'sleep away', glyph: 'lock', action: { type: 'lock' } },
  { id: 'app-sign', section: 'Apps', title: 'Sign / Verify', keywords: 'wizard', app: 'sign', action: { type: 'view', view: 'wizard' } },
  { id: 'app-analytics', section: 'Apps', title: 'Analytics', keywords: 'dashboard statistics history chart', app: 'analytics', action: { type: 'view', view: 'dashboard' } },
  { id: 'app-files', section: 'Apps', title: 'Files', keywords: 'documents signatures reports keystores downloads', app: 'files', action: { type: 'surface', surface: 'files' } },
  { id: 'app-settings', section: 'Apps', title: 'Settings', keywords: 'preferences options', app: 'settings', action: { type: 'surface', surface: 'settings' } },
  { id: 'app-about', section: 'Apps', title: 'About', keywords: 'help info version', app: 'about', action: { type: 'view', view: 'about' } },
  { id: 'home', section: 'Apps', title: 'Home Screen', keywords: 'springboard widgets', glyph: 'home', action: { type: 'surface', surface: 'home' } },
  { id: 'switcher', section: 'Apps', title: 'App Switcher', keywords: 'multitasking recent', glyph: 'grid', action: { type: 'surface', surface: 'switcher' } },
  { id: 'cc', section: 'Settings', title: 'Control Center', keywords: 'brightness volume', glyph: 'sparkles', action: { type: 'surface', surface: 'control' } },
  { id: 'nc', section: 'Settings', title: 'Notification Center', keywords: 'notifications banners', glyph: 'bell', action: { type: 'surface', surface: 'notifications' } },
  { id: 'dark', section: 'Settings', title: 'Dark Mode', keywords: 'light appearance night', glyph: 'contrast', action: { type: 'toggle', setting: 'dark' } },
  { id: 'sound', section: 'Settings', title: 'Silent Mode', keywords: 'sound mute volume audio', glyph: 'bell-slash', action: { type: 'toggle', setting: 'sound' } },
  { id: 'focus', section: 'Settings', title: 'Do Not Disturb', keywords: 'focus quiet', glyph: 'moon', action: { type: 'toggle', setting: 'focus' } },
  { id: 'transparency', section: 'Settings', title: 'Reduce Transparency', keywords: 'accessibility glass solid', glyph: 'eye', action: { type: 'toggle', setting: 'transparency' } },
  { id: 'pointer', section: 'Settings', title: 'Pointer Control', keywords: 'cursor mouse accessibility', glyph: 'cursor', action: { type: 'toggle', setting: 'pointer' } },
  { id: 'appearance', section: 'Settings', title: 'Theme & Appearance', keywords: 'layout colors animation design', glyph: 'photo', action: { type: 'appearance' } },
  { id: 'shortcuts', section: 'Settings', title: 'Keyboard Shortcuts', keywords: 'keys hotkeys', glyph: 'keyboard', action: { type: 'shortcuts' } },
  { id: 'leave', section: 'Settings', title: 'Leave iPadOS Theme', keywords: 'exit quit none windows', glyph: 'xmark', action: { type: 'leave' } },
  { id: 'help-levels', section: 'Help', title: 'Signature Levels', subtitle: 'B-B, B-T, B-LT and B-LTA', keywords: 'baseline level lta', glyph: 'info', action: { type: 'view', view: 'about' } },
  { id: 'help-tsa', section: 'Help', title: 'Timestamps', subtitle: 'What a time stamp authority proves', keywords: 'tsa timestamp time', glyph: 'clock', action: { type: 'view', view: 'about' } },
  { id: 'help-revocation', section: 'Help', title: 'Revocation Checks', subtitle: 'OCSP and CRLs', keywords: 'ocsp crl revoked certificate', glyph: 'seal', action: { type: 'view', view: 'about' } },
  { id: 'help-keystore', section: 'Help', title: 'Keystores', subtitle: 'Your private key and its password', keywords: 'pkcs12 p12 pfx key password', glyph: 'key', action: { type: 'view', view: 'about' } },
]

const FOLDER_NAMES: Record<GeneratedFolder, string> = { signatures: 'Signatures', reports: 'Reports', keystores: 'Keystores' }

const words = (s: string) => s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)

/** Whether the letters of `q` appear in `s` in order. */
function inOrder(q: string, s: string) {
  let i = 0
  for (const ch of s) if (ch === q[i]) i++
  return i === q.length
}

/** How well one typed word matches an entry; 0 is no match. */
function wordScore(q: string, item: SearchItem) {
  const title = item.title.toLowerCase()
  if (title.startsWith(q)) return 100
  if (words(item.title).some(w => w.startsWith(q))) return 80
  if (words(`${item.subtitle ?? ''} ${item.keywords ?? ''}`).some(w => w.startsWith(q))) return 60
  if (title.includes(q)) return 50
  if (q.length > 2 && inOrder(q, title.replace(/\s+/g, ''))) return 20
  return 0
}

/** How well a query matches an entry: every word must match; 0 is no match. */
export function score(query: string, item: SearchItem) {
  const qs = words(query)
  if (!qs.length) return 0
  let total = 0
  for (const q of qs) {
    const s = wordScore(q, item)
    if (!s) return 0
    total += s
  }
  return total / qs.length
}

const fileItem = (f: SearchFile): SearchItem => ({
  id: `file-${f.id}`, section: 'Files', title: f.name, subtitle: FOLDER_NAMES[f.folder], keywords: f.folder,
  glyph: f.folder === 'keystores' ? 'key' : f.folder === 'reports' ? 'doc-text' : 'doc', action: { type: 'file', id: f.id },
})

export interface SearchResult {
  top: SearchItem | null
  groups: Array<{ section: Section | 'Siri Suggestions'; items: SearchItem[] }>
}

const SECTIONS: readonly Section[] = ['Actions', 'Apps', 'Files', 'Settings', 'Help']

/**
 * What Spotlight shows for `query`: the best match as the Top Hit and the rest grouped by section,
 * best first. With nothing typed: suggestions, and the latest files.
 */
export function search(query: string, files: readonly SearchFile[], perSection = 4): SearchResult {
  if (!query.trim()) {
    const recent = [...files].sort((a, b) => b.created - a.created).slice(0, 3).map(fileItem)
    const suggested = ITEMS.filter(i => ['sign', 'verify', 'app-analytics', 'app-files'].includes(i.id))
    return { top: null, groups: [{ section: 'Siri Suggestions', items: suggested }, ...(recent.length ? [{ section: 'Files' as const, items: recent }] : [])] }
  }
  const scored = [...ITEMS, ...files.map(fileItem)]
    .map(item => ({ item, s: score(query, item) }))
    .filter(r => r.s > 0)
    .sort((a, b) => b.s - a.s)
  if (!scored.length) return { top: null, groups: [] }
  const top = scored[0].item
  const groups = SECTIONS
    .map(section => ({ section, items: scored.filter(r => r.item.section === section && r.item !== top).slice(0, perSection).map(r => r.item) }))
    .filter(g => g.items.length)
  return { top, groups }
}
