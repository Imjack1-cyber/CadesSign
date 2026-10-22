import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { Dashboard } from '../../components/dashboard/Dashboard'

const mockStats: any[] = [
  { id: 1, timestamp: '2026-01-01 10:00:00', action: 'SIGN', signature_level: 'LT', packaging: 'DETACHED', digest: 'SHA256', used_tsa: true, used_ocsp: false, used_crl: false, used_keystore: false },
  { id: 2, timestamp: '2026-01-02 11:00:00', action: 'VERIFY', signature_level: 'B-T', packaging: 'ENVELOPING', digest: 'SHA384', used_tsa: false, used_ocsp: true, used_crl: false, used_keystore: false },
]

const respond = (body: unknown, status = 200) =>
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

const rowCount = () => screen.getAllByRole('row').length - 1

describe('Dashboard', () => {
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => vi.restoreAllMocks())

  async function loadDashboard() {
    render(<Dashboard />)
    await waitFor(() => expect(screen.getByText('Operations', { exact: true })).toBeInTheDocument())
  }

  it('shows loading state initially', () => {
    respond(mockStats)
    render(<Dashboard />)
    expect(screen.getByText(/Loading statistics/)).toBeInTheDocument()
  })

  it('loads stats and renders operations table', async () => {
    const fetchMock = respond(mockStats)
    await loadDashboard()
    expect(fetchMock).toHaveBeenCalledWith('/api/stats')
    expect(rowCount()).toBe(2)
  })

  it('filters by action to VERIFY only', async () => {
    respond(mockStats)
    await loadDashboard()
    fireEvent.change(screen.getByRole('combobox', { name: 'Action' }), { target: { value: 'VERIFY' } })
    expect(rowCount()).toBe(1)
    expect(screen.getByText(/Showing 1 of 2/)).toBeInTheDocument()
  })

  it('external source toggles narrow results and reset restores them', async () => {
    respond(mockStats)
    await loadDashboard()
    fireEvent.click(screen.getByRole('button', { name: 'OCSP' }))
    expect(rowCount()).toBe(1)
    fireEvent.click(screen.getByRole('button', { name: 'TSA' }))
    expect(screen.getByText('No operations match the current filters')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }))
    expect(rowCount()).toBe(2)
  })

  it('does not render 0 for unused sources stored as SQLite integers', async () => {
    respond([{ id: 3, timestamp: '2026-01-03 09:00:00', action: 'SIGN', signature_level: 'LT', packaging: 'DETACHED', digest: 'SHA256', used_tsa: 0, used_ocsp: 0, used_crl: 0, used_keystore: 1 }])
    await loadDashboard()
    const sourcesCell = screen.getAllByRole('row')[1].querySelectorAll('td')[4]
    expect(sourcesCell.textContent).toBe('Keystore')
  })

  it('shows an empty state with a way to the wizard when nothing is recorded', async () => {
    respond([])
    const onNavigate = vi.fn()
    render(<Dashboard onNavigateToWizard={onNavigate} />)
    await waitFor(() => expect(screen.getByText('No operations recorded yet')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Go to Sign / Verify' }))
    expect(onNavigate).toHaveBeenCalled()
  })

  it('shows an error with retry', async () => {
    const fetchMock = respond({ error: 'boom' }, 500)
    render(<Dashboard />)
    await waitFor(() => expect(screen.getByText(/Error loading statistics/)).toBeInTheDocument())
    fetchMock.mockImplementation(async () => new Response(JSON.stringify(mockStats), { status: 200 }))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(rowCount()).toBe(2))
  })
})
