/**
 * The documents of the themes that keep files (the Windows 95 desktop's My Documents, the iPadOS
 * Files app): every signature, report and keystore the app generated while such a theme was on, kept
 * in this browser (IndexedDB) so they are still there after a reload, and shared between the themes.
 * Deleting moves a file to the bin (Recycle Bin, Recently Deleted); only emptying it removes the file
 * for good. Without IndexedDB (a private window, blocked storage, tests) the files live in memory for
 * the session.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { GENERATED_EVENT, type GeneratedFile, type GeneratedFolder } from './signals'

export interface StoredFile {
  id: string
  folder: GeneratedFolder
  name: string
  type: string
  size: number
  /** Epoch ms. */
  created: number
  /** In the Recycle Bin. */
  deleted: boolean
  blob: Blob
}

export const FOLDERS: ReadonlyArray<{ id: GeneratedFolder; label: string }> = [
  { id: 'signatures', label: 'Signatures' },
  { id: 'reports', label: 'Reports' },
  { id: 'keystores', label: 'Keystores' },
]

export interface FileStore {
  list(): Promise<StoredFile[]>
  put(file: StoredFile): Promise<void>
  remove(id: string): Promise<void>
}

/** Named after the first theme that kept files; renaming it would lose everyone's stored files. */
const DB_NAME = 'cades-win95'
const STORE = 'files'

const request = <T>(r: IDBRequest<T>) => new Promise<T>((resolve, reject) => {
  r.onsuccess = () => resolve(r.result)
  r.onerror = () => reject(r.error)
})

function memoryStore(): FileStore {
  const files = new Map<string, StoredFile>()
  return {
    list: async () => [...files.values()],
    put: async f => { files.set(f.id, f) },
    remove: async id => { files.delete(id) },
  }
}

/** IndexedDB when it opens, otherwise a store that forgets on reload. */
export async function openFileStore(): Promise<FileStore> {
  if (typeof indexedDB === 'undefined') return memoryStore()
  try {
    const open = indexedDB.open(DB_NAME, 1)
    open.onupgradeneeded = () => open.result.createObjectStore(STORE, { keyPath: 'id' })
    const db = await request(open)
    const tx = (mode: IDBTransactionMode) => db.transaction(STORE, mode).objectStore(STORE)
    return {
      list: () => request(tx('readonly').getAll() as IDBRequest<StoredFile[]>),
      put: async f => { await request(tx('readwrite').put(f)) },
      remove: async id => { await request(tx('readwrite').delete(id)) },
    }
  } catch {
    return memoryStore()
  }
}

/** "report.txt" becomes "report (2).txt" when the folder already has one, as Explorer named copies. */
export function uniqueName(name: string, taken: ReadonlySet<string>) {
  if (!taken.has(name)) return name
  const dot = name.lastIndexOf('.')
  const [base, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, '']
  for (let n = 2; ; n++) {
    const candidate = `${base} (${n})${ext}`
    if (!taken.has(candidate)) return candidate
  }
}

export function formatSize(bytes: number) {
  return bytes < 1024 ? `${bytes} bytes` : `${Math.max(1, Math.round(bytes / 1024))}KB`
}

export interface GeneratedFiles {
  files: StoredFile[]
  /** Moves a file to the bin, or back out of it. */
  setDeleted(id: string, deleted: boolean): void
  /** Removes every file in the bin for good. */
  emptyBin(): void
  /** Removes these files for good. */
  purge(ids: readonly string[]): void
  /** Gives a file a new name, made unique in its folder the way copies are; an empty name is ignored. */
  rename(id: string, name: string): void
}

/**
 * The stored files, kept in step with the store. While mounted it also files away everything the
 * app generates (GENERATED_EVENT), so a theme's files are recorded only while the theme is on.
 */
export function useGeneratedFiles(open: () => Promise<FileStore> = openFileStore): GeneratedFiles {
  const [files, setFiles] = useState<StoredFile[]>([])
  const [store] = useState(open)
  // The latest files, for the event handlers below.
  const current = useRef(files)
  useEffect(() => {
    current.current = files
  })

  useEffect(() => {
    let live = true
    void store.then((s: FileStore) => s.list()).then((list: StoredFile[]) => {
      // Keep anything generated while the store was still loading.
      if (live) setFiles((fs: StoredFile[]) => [...list, ...fs.filter(f => !list.some(l => l.id === f.id))].sort((a, b) => a.created - b.created))
    })
    const onGenerated = (e: Event) => {
      const { folder, name, blob } = (e as CustomEvent<GeneratedFile>).detail
      const taken = new Set<string>(current.current.filter((f: StoredFile) => f.folder === folder && !f.deleted).map((f: StoredFile) => f.name))
      const file: StoredFile = {
        id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
        folder, name: uniqueName(name, taken), type: blob.type, size: blob.size, created: Date.now(), deleted: false, blob,
      }
      // Counted at once, so files generated in the same instant get distinct names.
      current.current = [...current.current, file]
      setFiles((fs: StoredFile[]) => [...fs, file])
      void store.then((s: FileStore) => s.put(file))
    }
    window.addEventListener(GENERATED_EVENT, onGenerated)
    return () => {
      live = false
      window.removeEventListener(GENERATED_EVENT, onGenerated)
    }
  }, [store])

  const setDeleted = useCallback((id: string, deleted: boolean) => {
    const file = current.current.find((f: StoredFile) => f.id === id)
    if (!file) return
    const next = { ...file, deleted }
    setFiles((fs: StoredFile[]) => fs.map(f => (f.id === id ? next : f)))
    void store.then((s: FileStore) => s.put(next))
  }, [store])

  const purge = useCallback((ids: readonly string[]) => {
    const gone = new Set(ids)
    current.current = current.current.filter((f: StoredFile) => !gone.has(f.id))
    setFiles((fs: StoredFile[]) => fs.filter(f => !gone.has(f.id)))
    void store.then((s: FileStore) => Promise.all(ids.map(id => s.remove(id))))
  }, [store])

  const emptyBin = useCallback(() => {
    purge(current.current.filter((f: StoredFile) => f.deleted).map((f: StoredFile) => f.id))
  }, [purge])

  const rename = useCallback((id: string, name: string) => {
    const file = current.current.find((f: StoredFile) => f.id === id)
    const wanted = name.trim()
    if (!file || !wanted || wanted === file.name) return
    const taken = new Set<string>(current.current.filter((f: StoredFile) => f.folder === file.folder && f.id !== id && !f.deleted).map((f: StoredFile) => f.name))
    const next = { ...file, name: uniqueName(wanted, taken) }
    current.current = current.current.map((f: StoredFile) => (f.id === id ? next : f))
    setFiles((fs: StoredFile[]) => fs.map(f => (f.id === id ? next : f)))
    void store.then((s: FileStore) => s.put(next))
  }, [store])

  return { files, setDeleted, emptyBin, purge, rename }
}

/** A file's text; FileReader works where Blob.text() is missing. */
export function readText(blob: Blob) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(blob)
  })
}

/** Saves a stored file to the user's downloads. */
export function download(file: Pick<StoredFile, 'blob' | 'name'>) {
  const url = URL.createObjectURL(file.blob)
  const a = document.createElement('a')
  a.href = url
  a.download = file.name
  document.body.append(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
