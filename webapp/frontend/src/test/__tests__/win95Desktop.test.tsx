import { describe, it, expect, beforeEach, vi } from 'vitest'
import { act, fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react'
import App from '../../App'
import { emitChrome, emitGenerated, emitOutcome, emitStep } from '../../design/signals'
import { uniqueName, useGeneratedFiles } from '../../design/generatedFiles'

const signature = () => emitGenerated({ folder: 'signatures', name: 'contract.pdf.p7s', blob: new Blob(['sig'], { type: 'application/pkcs7-signature' }) })
const report = () => emitGenerated({ folder: 'reports', name: 'contract-validation.txt', blob: new Blob(['Signature is VALID'], { type: 'text/plain' }) })

beforeEach(() => {
  window.localStorage.clear()
  window.history.replaceState(null, '', '#wizard')
  window.localStorage.setItem('cades-theme', 'win95')
})

describe('generated files', () => {
  it('names a copy like Explorer did', () => {
    expect(uniqueName('a.txt', new Set())).toBe('a.txt')
    expect(uniqueName('a.txt', new Set(['a.txt', 'a (2).txt']))).toBe('a (3).txt')
    expect(uniqueName('README', new Set(['README']))).toBe('README (2)')
  })

  it('files what the app generates; deleting goes to the Recycle Bin, emptying it removes for good', async () => {
    const { result } = renderHook(() => useGeneratedFiles())
    await act(async () => {
      signature()
      signature()
    })
    expect(result.current.files.map(f => f.name)).toEqual(['contract.pdf.p7s', 'contract.pdf (2).p7s'])
    act(() => result.current.setDeleted(result.current.files[0].id, true))
    expect(result.current.files.filter(f => f.deleted)).toHaveLength(1)
    act(() => result.current.emptyBin())
    expect(result.current.files.map(f => f.name)).toEqual(['contract.pdf (2).p7s'])
  })

  it('renames a file, keeping names unique in its folder; an empty name changes nothing', async () => {
    const { result } = renderHook(() => useGeneratedFiles())
    await act(async () => {
      signature()
      signature()
    })
    const [first, second] = result.current.files
    act(() => result.current.rename(second.id, 'contract.pdf.p7s'))
    expect(result.current.files[1].name).toBe('contract.pdf (2).p7s')
    act(() => result.current.rename(first.id, '  offer.p7s '))
    act(() => result.current.rename(second.id, '   '))
    expect(result.current.files.map(f => f.name)).toEqual(['offer.p7s', 'contract.pdf (2).p7s'])
  })
})

describe('Windows 95 desktop', () => {
  const desktopIcon = (name: RegExp) => screen.getByRole('button', { name })
  const explorer = (name: string) => screen.getByRole('region', { name })

  it('My Documents opens in Explorer: folders, files, Delete to the bin and back', async () => {
    render(<App />)
    act(() => {
      signature()
      report()
    })
    fireEvent.doubleClick(desktopIcon(/^My Documents: 2 files/))
    const docs = within(explorer('My Documents')).getByRole('listbox', { name: 'My Documents' })
    expect(within(docs).getAllByRole('option').map(o => o.textContent)).toEqual(['Signatures', 'Reports', 'Keystores'])
    fireEvent.keyDown(docs, { key: 'Enter' })

    const sigs = within(explorer('Signatures')).getByRole('listbox')
    expect(within(sigs).getByRole('option', { name: 'contract.pdf.p7s' })).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(sigs, { key: 'Delete' })
    expect(within(sigs).queryAllByRole('option')).toHaveLength(0)
    expect(desktopIcon(/^Recycle Bin: 1 item/)).toBeInTheDocument()

    fireEvent.keyDown(sigs, { key: 'Backspace' })
    expect(explorer('My Documents')).toBeInTheDocument()
    fireEvent.doubleClick(desktopIcon(/^Recycle Bin/))
    const bin = within(explorer('Recycle Bin')).getByRole('listbox')
    fireEvent.doubleClick(within(bin).getByRole('option', { name: 'contract.pdf.p7s' }))
    expect(within(bin).queryAllByRole('option')).toHaveLength(0)
  })

  it('a report opens in Notepad, and Explorer has a taskbar button that minimizes it', async () => {
    render(<App />)
    act(() => report())
    fireEvent.click(screen.getByRole('button', { name: 'Start' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Documents' }))
    fireEvent.doubleClick(within(explorer('My Documents')).getByRole('option', { name: 'Reports' }))
    fireEvent.doubleClick(within(explorer('Reports')).getByRole('option', { name: 'contract-validation.txt' }))
    await waitFor(() => expect(screen.getByLabelText('contract-validation.txt', { selector: 'pre' })).toHaveTextContent('Signature is VALID'))

    fireEvent.click(screen.getByRole('button', { name: 'Minimize Reports', pressed: true }))
    expect(screen.queryByRole('region', { name: 'Reports' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Restore Reports' }))
    expect(explorer('Reports')).toBeInTheDocument()
  })
})

describe('Paperclip', () => {
  const balloon = () => screen.getByRole('status')
  const clip = () => screen.getByRole('button', { name: 'Paperclip, your assistant' })

  it('greets on the first step and follows the wizard', () => {
    render(<App />)
    expect(balloon()).toHaveTextContent("I'm Paperclip")
    act(() => emitStep(2, 'verify'))
    expect(balloon()).toHaveTextContent("checking a signature")
  })

  it('offers the details after an error, and opens them', () => {
    render(<App />)
    const details = document.createElement('details')
    details.className = 'technical-details'
    details.scrollIntoView = vi.fn()
    document.body.append(details)
    act(() => emitOutcome('error'))
    fireEvent.click(within(balloon()).getByRole('button', { name: 'Show me the details' }))
    expect(details.open).toBe(true)
    details.remove()
  })

  it('its menu explains the levels and hides it; the Start menu brings it back', () => {
    render(<App />)
    fireEvent.keyDown(clip(), { key: 'Enter' })
    fireEvent.click(within(balloon()).getByRole('button', { name: 'Explain the signature levels' }))
    expect(balloon()).toHaveTextContent('B-LT also packs in the certificates')

    fireEvent.keyDown(clip(), { key: 'Enter' })
    fireEvent.click(within(balloon()).getByRole('button', { name: 'Hide Paperclip' }))
    expect(screen.queryByRole('button', { name: 'Paperclip, your assistant' })).not.toBeInTheDocument()
    expect(window.localStorage.getItem('cades-w95-assistant')).toBe('hidden')

    fireEvent.click(screen.getByRole('button', { name: 'Start' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Show Paperclip' }))
    expect(clip()).toBeInTheDocument()
  })

  it('points closed windows to the Recycle Bin, once', () => {
    render(<App />)
    act(() => emitChrome('close'))
    expect(balloon()).toHaveTextContent('Recycle Bin')
  })
})
