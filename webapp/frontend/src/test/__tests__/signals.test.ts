import { describe, it, expect, afterEach } from 'vitest'
import { describeInput, describeKey, locateKey } from '../../design/effects/engine'
import { APP_SIGNAL_EVENT, emitBusy, emitOutcome, type AppSignal } from '../../design/signals'

const key = (k: string, mods: Partial<Pick<KeyboardEvent, 'ctrlKey' | 'metaKey' | 'altKey'>> = {}) =>
  describeKey({ key: k, ctrlKey: false, metaKey: false, altKey: false, ...mods })

afterEach(() => {
  document.body.innerHTML = ''
})

describe('theme signals', () => {
  it('busy and outcome reach a listener', () => {
    const got: AppSignal[] = []
    const listen = (e: Event) => got.push((e as CustomEvent<AppSignal>).detail)
    window.addEventListener(APP_SIGNAL_EVENT, listen)
    emitBusy(true)
    emitOutcome('error')
    window.removeEventListener(APP_SIGNAL_EVENT, listen)
    expect(got).toEqual([{ type: 'busy', on: true }, { type: 'outcome', kind: 'error' }])
  })
})

describe('keys', () => {
  it('sorts keys into typing, deleting, enter and tab; shortcuts are ignored', () => {
    expect(key('a')).toBe('char')
    expect(key(' ')).toBe('space')
    expect(key('Backspace')).toBe('delete')
    expect(key('Delete')).toBe('delete')
    expect(key('Enter')).toBe('enter')
    expect(key('Tab')).toBe('tab')
    expect(key('Shift')).toBeNull()
    expect(key('c', { ctrlKey: true })).toBeNull()
    expect(key('v', { metaKey: true })).toBeNull()
    // AltGr arrives as Ctrl+Alt and still types.
    expect(key('@', { ctrlKey: true, altKey: true })).toBe('char')
    expect(key('Unidentified')).toBe('unknown')
  })

  it('virtual keyboards are read from the input event', () => {
    expect(describeInput('insertText', 'x')).toBe('char')
    expect(describeInput('insertText', ' ')).toBe('space')
    expect(describeInput('deleteContentBackward', null)).toBe('delete')
    expect(describeInput('insertLineBreak', null)).toBe('enter')
    expect(describeInput('historyUndo', null)).toBeNull()
  })

  it('passes the typed glyph for text fields but never for passwords', () => {
    const text = document.createElement('input')
    const password = document.createElement('input')
    password.type = 'password'
    document.body.append(text, password)
    expect(locateKey('char', text, 'k')).toMatchObject({ field: true, glyph: 'k' })
    expect(locateKey('char', password, 'k').glyph).toBeUndefined()
    expect(locateKey('char', password, 'k').field).toBe(true)
    expect(locateKey('enter', document.body)).toMatchObject({ field: false })
  })

  it('tells whether the field was empty', () => {
    const field = document.createElement('input')
    document.body.append(field)
    expect(locateKey('delete', field).empty).toBe(true)
    field.value = 'x'
    expect(locateKey('delete', field).empty).toBe(false)
  })
})
