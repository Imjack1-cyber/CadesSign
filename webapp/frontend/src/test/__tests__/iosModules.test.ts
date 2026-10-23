import { beforeEach, describe, it, expect } from 'vitest'
import type { StoredFile } from '../../design/generatedFiles'
import { DEFAULT_SORT, fileDate, fileKind, fileSize, groupByDate, nextSort, sortFiles, stem } from '../../design/iosFiles'
import { edgeSwipe, rubberBand, shouldDismiss } from '../../design/iosGestures'
import { APPS, DEFAULT_PREFS, getIosPrefs, parsePrefs, reloadIosPrefs, setIosPrefs } from '../../design/iosPrefs'
import { score, search } from '../../design/iosSearch'

describe('Spotlight search', () => {
  const files = [
    { id: 'a', name: 'contract.pdf.p7s', folder: 'signatures' as const, created: 2 },
    { id: 'b', name: 'contract-self-check.txt', folder: 'reports' as const, created: 3 },
    { id: 'c', name: 'keystore.p12', folder: 'keystores' as const, created: 1 },
  ]

  it('ranks a title start over a word start over a keyword over letters in order', () => {
    const item = { id: 'x', section: 'Apps' as const, title: 'Analytics Board', keywords: 'dashboard chart', action: { type: 'lock' as const } }
    expect(score('ana', item)).toBeGreaterThan(score('boa', item))
    expect(score('boa', item)).toBeGreaterThan(score('chart', item))
    expect(score('chart', item)).toBeGreaterThan(score('alyt', item))
    expect(score('alyt', item)).toBeGreaterThan(score('aly bd', item))
    expect(score('zzz', item)).toBe(0)
    // Every word must match.
    expect(score('analytics zzz', item)).toBe(0)
  })

  it('puts the best match first as the Top Hit and groups the rest', () => {
    const r = search('anal', files)
    expect(r.top?.title).toBe('Analytics')
    expect(r.top?.action).toEqual({ type: 'view', view: 'dashboard' })
    const verify = search('verify', files)
    expect(verify.top?.action).toEqual({ type: 'wizard', command: { type: 'start', action: 'verify' } })
    expect(search('ocsp', files).top?.section).toBe('Help')
    expect(search('qwxz', files)).toEqual({ top: null, groups: [] })
  })

  it('finds files by name, and suggests actions and the latest files when nothing is typed', () => {
    const r = search('contract', files)
    expect([r.top, ...r.groups.flatMap(g => g.items)].filter(i => i?.section === 'Files').map(i => i!.title))
      .toEqual(expect.arrayContaining(['contract.pdf.p7s', 'contract-self-check.txt']))
    const empty = search('', files)
    expect(empty.top).toBeNull()
    expect(empty.groups[0].section).toBe('Siri Suggestions')
    expect(empty.groups[1].items.map(i => i.title)).toEqual(['contract-self-check.txt', 'contract.pdf.p7s', 'keystore.p12'])
  })
})

describe('iOS gestures', () => {
  it('rubber-bands: follows less and less, never past the limit', () => {
    expect(rubberBand(0, 100)).toBe(0)
    expect(rubberBand(50, 100)).toBeLessThan(50)
    expect(rubberBand(10_000, 100)).toBeLessThan(100)
    expect(rubberBand(-50, 100)).toBe(-rubberBand(50, 100))
  })

  it('tells the system swipes apart', () => {
    const w = 400
    const h = 800
    expect(edgeSwipe({ x: 50, y: 20 }, { x: 60, y: 300 }, w, h, 200)).toBe('notifications')
    expect(edgeSwipe({ x: 350, y: 20 }, { x: 340, y: 300 }, w, h, 200)).toBe('control')
    expect(edgeSwipe({ x: 200, y: 795 }, { x: 205, y: 400 }, w, h, 150)).toBe('home')
    expect(edgeSwipe({ x: 200, y: 795 }, { x: 205, y: 600 }, w, h, 600)).toBe('switcher')
    expect(edgeSwipe({ x: 5, y: 400 }, { x: 200, y: 410 }, w, h, 200)).toBe('back')
    // Not from an edge, or too short: nothing.
    expect(edgeSwipe({ x: 200, y: 400 }, { x: 200, y: 700 }, w, h, 200)).toBeNull()
    expect(edgeSwipe({ x: 50, y: 20 }, { x: 50, y: 40 }, w, h, 200)).toBeNull()
  })

  it('a sheet closes when pulled a third of the way down, or flicked', () => {
    expect(shouldDismiss(100, 0.1, 600)).toBe(false)
    expect(shouldDismiss(250, 0.1, 600)).toBe(true)
    expect(shouldDismiss(60, 0.9, 600)).toBe(true)
  })
})

describe('iOS settings', () => {
  beforeEach(() => {
    window.localStorage.clear()
    reloadIosPrefs()
  })

  it('start with the iPad pointer, Auto-Lock at two minutes and banners and alerts on; the dock stays and tilt is off', () => {
    expect(getIosPrefs()).toMatchObject({ pointer: true, autoLock: 120, banners: true, alerts: true, dockHide: false, tilt: false })
  })

  it('keep what is valid of what was stored, and fall back for the rest', () => {
    expect(parsePrefs('not json')).toEqual(DEFAULT_PREFS)
    expect(parsePrefs('[1, 2]')).toEqual(DEFAULT_PREFS)
    const p = parsePrefs(JSON.stringify({
      pointer: false, autoLock: 45, volume: 3, brightness: 0, wallpaper: 'tide', home: ['sign'], focus: 'yes', extra: 1,
    }))
    expect(p).toMatchObject({ pointer: false, autoLock: 120, volume: 1, brightness: 0.4, wallpaper: 'tide', home: [...APPS], focus: false })
    expect(p).not.toHaveProperty('extra')
    const order = [...APPS].reverse()
    expect(parsePrefs(JSON.stringify({ home: order })).home).toEqual(order)
  })

  it('are kept, and survive reading them again', () => {
    setIosPrefs({ focus: true, wallpaper: 'graphite' })
    expect(getIosPrefs()).toMatchObject({ focus: true, wallpaper: 'graphite' })
    reloadIosPrefs()
    expect(getIosPrefs()).toMatchObject({ focus: true, wallpaper: 'graphite' })
    expect(JSON.parse(window.localStorage.getItem('cades-ios-prefs')!)).toMatchObject({ focus: true })
  })
})

describe('Files', () => {
  const now = new Date(2026, 9, 22, 15, 0).getTime()
  const at = (days: number, hour = 9) => new Date(2026, 9, 22 - days, hour, 41).getTime()
  const file = (name: string, size: number, created: number): StoredFile => ({
    id: name, folder: 'signatures', name, type: '', size, created, deleted: false, blob: new Blob([]),
  })

  it('names each kind of file and puts its type on the thumbnail', () => {
    expect(fileKind('contract.pdf.p7s')).toMatchObject({ label: 'CAdES Signature', badge: 'P7S' })
    expect(fileKind('report.XML')).toMatchObject({ label: 'XML Document', badge: 'XML' })
    expect(fileKind('keys.pfx')).toMatchObject({ label: 'PKCS #12 Keystore', badge: 'PFX' })
    expect(fileKind('notes.markdown')).toMatchObject({ label: 'Document', badge: 'MARK' })
    expect(fileKind('README')).toMatchObject({ badge: 'FILE' })
    expect(stem('contract.pdf.p7s')).toBe('contract.pdf')
    expect(stem('.hidden')).toBe('.hidden')
  })

  it('dates files as Files does, and rounds sizes', () => {
    expect(fileDate(at(0), now)).toMatch(/^Today at /)
    expect(fileDate(at(0), now, false)).toBe('Today')
    expect(fileDate(at(1, 23), now)).toMatch(/^Yesterday at /)
    expect(fileDate(at(3), now)).toBe(new Date(at(3)).toLocaleDateString([], { weekday: 'long' }))
    expect(fileDate(at(30), now)).toBe(new Date(at(30)).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }))
    expect([1, 332, 4_800, 1_250_000].map(fileSize)).toEqual(['1 byte', '332 bytes', '5 KB', '1.3 MB'])
  })

  it('sorts by any column, the chosen one turning round when chosen again', () => {
    const files = [file('b.p7s', 10, at(2)), file('a10.txt', 30, at(0)), file('a9.xml', 20, at(1))]
    const names = (order: typeof DEFAULT_SORT) => sortFiles(files, order).map(f => f.name)
    expect(names(DEFAULT_SORT)).toEqual(['a10.txt', 'a9.xml', 'b.p7s'])
    const byName = nextSort(DEFAULT_SORT, 'name')
    expect(byName).toEqual({ key: 'name', ascending: true })
    expect(names(byName)).toEqual(['a9.xml', 'a10.txt', 'b.p7s'])
    expect(names(nextSort(byName, 'name'))).toEqual(['b.p7s', 'a10.txt', 'a9.xml'])
    expect(names(nextSort(byName, 'size'))).toEqual(['a10.txt', 'a9.xml', 'b.p7s'])
    expect(names({ key: 'kind', ascending: true })).toEqual(['b.p7s', 'a10.txt', 'a9.xml'])
  })

  it('groups files by day, leaving out empty groups', () => {
    const groups = groupByDate([file('a', 1, at(0)), file('b', 1, at(3)), file('c', 1, at(40))], now)
    expect(groups.map(g => [g.title, g.files.map(f => f.name)])).toEqual([['Today', ['a']], ['Previous 7 Days', ['b']], ['Earlier', ['c']]])
  })
})

