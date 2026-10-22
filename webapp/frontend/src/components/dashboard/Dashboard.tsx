import { useState, useEffect, type ReactNode } from 'react'
import {
  IxBlind, IxButton, IxCard, IxCardContent, IxDateInput, IxEmptyState,
  IxIcon, IxIconButton, IxInput, IxKpi, IxMessageBar, IxPagination, IxPill, IxSelect, IxSelectItem, IxSpinner,
  IxToggleButton, IxTypography,
} from '@siemens/ix-react'
import { PageHeader } from '../layout/PageHeader'
import { PHONE_QUERY, useMediaQuery } from '../../design/useMediaQuery'

const PAGE_SIZE = 25

interface DashboardProps {
  onNavigateToWizard?: () => void
}

export function Dashboard({ onNavigateToWizard }: DashboardProps = {}) {
  const phone = useMediaQuery(PHONE_QUERY)
  const [stats, setStats] = useState<any[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<any>(null)
  const [reloadKey, setReloadKey] = useState(0)

  const [actionFilter, setActionFilter] = useState<string>('ALL')
  const [levelFilter, setLevelFilter] = useState<string>('ALL')
  const [packagingFilter, setPackagingFilter] = useState<string>('ALL')
  const [digestFilter, setDigestFilter] = useState<string>('ALL')
  const [sourceFilter, setSourceFilter] = useState<string[]>([])
  const [dateFrom, setDateFrom] = useState<string>('')
  const [dateTo, setDateTo] = useState<string>('')
  const [search, setSearch] = useState<string>('')
  const [sortKey, setSortKey] = useState<string>('timestamp')
  const [sortDir, setSortDir] = useState<string>('desc')
  const [page, setPage] = useState(0)

  useEffect(() => {
    fetch('/api/stats')
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch stats')
        return r.json()
      })
      .then(data => { setStats(data); setError(null) })
      .catch(setError)
      .finally(() => setLoading(false))
  }, [reloadKey])

  const retry = () => {
    setLoading(true)
    setReloadKey(reloadKey + 1)
  }

  const SOURCE_META = [
    { key: 'tsa', label: 'TSA', field: 'used_tsa' },
    { key: 'ocsp', label: 'OCSP', field: 'used_ocsp' },
    { key: 'crl', label: 'CRL', field: 'used_crl' },
    { key: 'keystore', label: 'Keystore', field: 'used_keystore' },
  ]
  const SOURCE_FIELD = { tsa: 'used_tsa', ocsp: 'used_ocsp', crl: 'used_crl', keystore: 'used_keystore' }

  const parseTs = (ts: any) => {
    if (!ts) return 0
    const raw = String(ts)
    const d = new Date(raw.includes('T') ? raw : raw.replace(' ', 'T'))
    return isNaN(d.getTime()) ? 0 : d.getTime()
  }

  const header = (actions?: ReactNode) => (
    <PageHeader title="Analytics & Metrics" subtitle="Every recorded sign / verify operation and the settings it used.">
      {actions}
    </PageHeader>
  )

  if (loading) {
    return (
      <div className="page">
        {header()}
        <div className="centered" role="status" aria-live="polite">
          <div className="stack" style={{ alignItems: 'center' }}>
            <IxSpinner size="large" />
            <IxTypography format="body" textColor="soft">Loading statistics...</IxTypography>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="page">
        {header()}
        <IxMessageBar type="alarm" persistent>
          Error loading statistics: {error?.message || String(error)}
        </IxMessageBar>
        <div>
          <IxButton variant="secondary" icon="refresh" onClick={retry}>Retry</IxButton>
        </div>
      </div>
    )
  }

  const filtered = stats.filter((s: any) => {
    if (actionFilter !== 'ALL' && s.action !== actionFilter) return false
    if (levelFilter !== 'ALL' && (s.signature_level || '') !== levelFilter) return false
    if (packagingFilter !== 'ALL' && (s.packaging || '') !== packagingFilter) return false
    if (digestFilter !== 'ALL' && (s.digest || '') !== digestFilter) return false
    for (const k of sourceFilter) {
      if (!(s as any)[(SOURCE_FIELD as any)[k]]) return false
    }
    if (dateFrom || dateTo) {
      const t = parseTs(s.timestamp)
      if (dateFrom) {
        const from = new Date(dateFrom + 'T00:00:00').getTime()
        if (t < from) return false
      }
      if (dateTo) {
        const to = new Date(dateTo + 'T23:59:59.999').getTime()
        if (t > to) return false
      }
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      const hay = `${s.action} ${s.signature_level || ''} ${s.packaging || ''} ${s.digest || ''}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })

  const sorted = [...filtered].sort((a, b) => {
    const dir = sortDir === 'asc' ? 1 : -1
    let av, bv
    switch (sortKey) {
      case 'action': av = a.action; bv = b.action; break
      case 'level': av = a.signature_level || ''; bv = b.signature_level || ''; break
      case 'packaging': av = a.packaging || ''; bv = b.packaging || ''; break
      case 'digest': av = a.digest || ''; bv = b.digest || ''; break
      default: av = parseTs(a.timestamp); bv = parseTs(b.timestamp)
    }
    if (typeof av === 'string') av = av.toLowerCase()
    if (typeof bv === 'string') bv = bv.toLowerCase()
    if (av < bv) return -1 * dir
    if (av > bv) return 1 * dir
    return 0
  })

  const pageCount = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE))
  const currentPage = Math.min(page, pageCount - 1)
  const pageRows = sorted.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE)

  // Any filter change returns to the first page so results are never hidden on a later page.
  const withPageReset = <T,>(setter: (v: T) => void) => (v: T) => { setter(v); setPage(0) }

  const toggleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir(key === 'timestamp' ? 'desc' : 'asc')
    }
  }

  const distinct = (key: string) => [...new Set(stats.map((s: any) => s[key]).filter(Boolean))].sort()
  const levels = distinct('signature_level')
  const packagings = distinct('packaging')
  const digests = distinct('digest')

  const total = filtered.length || 1
  const distribution = (key: any) => {
    const counts: any = {}
    filtered.forEach((s: any) => {
      const v = String(s[key] || 'NOT SET')
      counts[v] = (counts[v] ?? 0) + 1
    })
    return Object.entries(counts)
      .sort((a: any, b: any) => b[1] - a[1])
      .map(([label, count]: [string, any]) => ({ label, count, pct: Math.round((count / total) * 100) }))
  }

  const levelDist = distribution('signature_level')
  const packagingDist = distribution('packaging')
  const digestDist = distribution('digest')
  const sourceUsage = SOURCE_META.map((src: { key: string; label: string; field: string }) => {
    const count = filtered.filter((s: any) => !!s[src.field]).length
    return { label: src.label, count, pct: Math.round((count / total) * 100) }
  })
  const withExternal = filtered.filter((s: any) => s.used_tsa || s.used_ocsp || s.used_crl || s.used_keystore).length

  const filtersActive = actionFilter !== 'ALL' || levelFilter !== 'ALL' || packagingFilter !== 'ALL' ||
    digestFilter !== 'ALL' || sourceFilter.length > 0 || dateFrom || dateTo || search.trim()

  const resetFilters = () => {
    setActionFilter('ALL')
    setLevelFilter('ALL')
    setPackagingFilter('ALL')
    setDigestFilter('ALL')
    setSourceFilter([])
    setDateFrom('')
    setDateTo('')
    setSearch('')
    setPage(0)
  }

  const exportCsv = () => {
    const headers = ['ID', 'Timestamp', 'Action', 'Signature Level', 'Packaging', 'Digest', 'TSA', 'OCSP', 'CRL', 'Keystore']
    const rows = sorted.map((s: any) => [
      s.id,
      new Date(parseTs(s.timestamp)).toISOString(),
      s.action,
      s.signature_level || '',
      s.packaging || '',
      s.digest || '',
      s.used_tsa ? 'yes' : 'no',
      s.used_ocsp ? 'yes' : 'no',
      s.used_crl ? 'yes' : 'no',
      s.used_keystore ? 'yes' : 'no',
    ])
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'cades-operations.csv'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)
  }

  const filterSelect = (label: string, value: string, onChange: (v: string) => void, allLabel: string, choices: Array<{ value: string; label: string }>) => (
    <IxSelect label={label} value={value} onValueChange={(e: CustomEvent<string | string[]>) => withPageReset(onChange)(String(e.detail))}>
      <IxSelectItem value="ALL" label={allLabel} />
      {choices.map(c => <IxSelectItem key={c.value} value={c.value} label={c.label} />)}
    </IxSelect>
  )
  const asChoices = (values: any[]) => values.map(v => ({ value: String(v), label: String(v) }))

  const sortHeader = (key: string, label: string) => {
    const active = sortKey === key
    return (
      <th aria-sort={active ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}>
        <button className="sort-btn" onClick={() => toggleSort(key)}>
          {label}
          <IxIcon name={active ? (sortDir === 'asc' ? 'sort-ascending' : 'sort-descending') : 'sort'} size="16" />
        </button>
      </th>
    )
  }

  if (stats.length === 0) {
    return (
      <div className="page">
        {header()}
        <IxEmptyState
          layout="large"
          icon="chart-diagrams"
          header="No operations recorded yet"
          subHeader="Sign or verify a document and its settings will appear here."
          action={onNavigateToWizard ? 'Go to Sign / Verify' : undefined}
          onActionClick={onNavigateToWizard}
        />
      </div>
    )
  }

  return (
    <div className="page">
      {header(
        // On phones the title needs the room, so the export is an icon button there.
        phone ? (
          <IxIconButton icon="download" variant="primary" aria-label="Export CSV" title="Export CSV" onClick={exportCsv} disabled={sorted.length === 0} />
        ) : (
          <IxButton variant="primary" icon="download" onClick={exportCsv} disabled={sorted.length === 0}>
            Export CSV
          </IxButton>
        )
      )}

      {/* Summary */}
      <div className="grid grid-kpi">
        <IxKpi label="Operations shown" value={filtered.length} unit={`of ${stats.length}`} orientation="vertical" />
        <IxKpi label="Signs" value={filtered.filter((s: any) => s.action === 'SIGN').length} orientation="vertical" />
        <IxKpi label="Verifies" value={filtered.filter((s: any) => s.action === 'VERIFY').length} orientation="vertical" />
        <IxKpi label="With external sources" value={withExternal} orientation="vertical" />
      </div>

      {/* Settings usage overview */}
      <div className="stack-sm">
        <IxTypography format="h4">Settings usage</IxTypography>
        <div className="grid grid-wide">
          <DistributionCard title="Signature level" items={levelDist} />
          <DistributionCard title="Packaging" items={packagingDist} />
          <DistributionCard title="Hash digest" items={digestDist} />
          <DistributionCard title="External sources" items={sourceUsage} />
        </div>
      </div>

      {/* Filters */}
      <IxBlind label="Filters" sublabel={filtersActive ? 'Active' : undefined} icon="filter">
        <div className="stack">
          <div className="grid">
            {filterSelect('Action', actionFilter, setActionFilter, 'All actions', [{ value: 'SIGN', label: 'Sign only' }, { value: 'VERIFY', label: 'Verify only' }])}
            {filterSelect('Signature level', levelFilter, setLevelFilter, 'All levels', asChoices(levels))}
            {filterSelect('Packaging', packagingFilter, setPackagingFilter, 'All packaging', asChoices(packagings))}
            {filterSelect('Hash digest', digestFilter, setDigestFilter, 'All digests', asChoices(digests))}
            <IxDateInput label="Date from" format="yyyy-LL-dd" value={dateFrom} maxDate={dateTo || undefined}
              onValueChange={(e: CustomEvent<string | undefined>) => withPageReset(setDateFrom)(e.detail ?? '')} />
            <IxDateInput label="Date to" format="yyyy-LL-dd" value={dateTo} minDate={dateFrom || undefined}
              onValueChange={(e: CustomEvent<string | undefined>) => withPageReset(setDateTo)(e.detail ?? '')} />
            <div className="span-all">
              <IxInput label="Search" placeholder="Action, level, packaging, digest..." value={search}
                onValueChange={(e: CustomEvent<string>) => withPageReset(setSearch)(e.detail)} />
            </div>
          </div>
          <div className="stack-sm">
            <IxTypography format="label">External sources (must include all selected)</IxTypography>
            <div className="row">
              {SOURCE_META.map(src => {
                const active = sourceFilter.includes(src.key)
                return (
                  <IxToggleButton
                    key={src.key}
                    pressed={active}
                    variant="subtle-primary"
                    onPressedChange={() => withPageReset(setSourceFilter)(active ? sourceFilter.filter(k => k !== src.key) : [...sourceFilter, src.key])}
                  >
                    {src.label}
                  </IxToggleButton>
                )
              })}
            </div>
          </div>
          {filtersActive && (
            <div>
              <IxButton variant="tertiary" icon="clear-filter" onClick={resetFilters}>Reset all filters</IxButton>
            </div>
          )}
        </div>
      </IxBlind>

      {/* Results table */}
      <div className="stack-sm">
        <div className="row-between">
          <IxTypography format="h4">Operations</IxTypography>
          <IxTypography format="label-sm" textColor="soft">
            Showing {sorted.length} of {stats.length} {stats.length === 1 ? 'operation' : 'operations'}
            {filtersActive ? ' (filtered)' : ''}
          </IxTypography>
        </div>

        {sorted.length === 0 ? (
          <IxEmptyState
            layout="compact"
            icon="search"
            header="No operations match the current filters"
            action="Reset filters"
            onActionClick={resetFilters}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="ix-table">
                <thead>
                  <tr>
                    {sortHeader('timestamp', 'Time')}
                    {sortHeader('action', 'Action')}
                    {sortHeader('level', 'Level / Packaging')}
                    {sortHeader('digest', 'Digest')}
                    <th>External sources</th>
                    <th>ID</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map((s, i) => (
                    <tr key={s.id ?? i}>
                      <td className="nowrap" title={new Date(parseTs(s.timestamp)).toISOString()}>
                        {new Date(parseTs(s.timestamp)).toLocaleString()}
                      </td>
                      <td>
                        <IxPill variant={s.action === 'SIGN' ? 'primary' : 'success'} icon={s.action === 'SIGN' ? 'ink-pen' : 'shield-check'}>
                          {s.action}
                        </IxPill>
                      </td>
                      <td>{s.signature_level || '-'} / {s.packaging || '-'}</td>
                      <td>{s.digest || '-'}</td>
                      <td>
                        <div className="row">
                          {!!s.used_tsa && <IxPill variant="neutral" outline>TSA</IxPill>}
                          {!!s.used_ocsp && <IxPill variant="neutral" outline>OCSP</IxPill>}
                          {!!s.used_crl && <IxPill variant="neutral" outline>CRL</IxPill>}
                          {!!s.used_keystore && <IxPill variant="neutral" outline>Keystore</IxPill>}
                          {!s.used_tsa && !s.used_ocsp && !s.used_crl && !s.used_keystore && (
                            <IxTypography format="label-sm" textColor="weak">None</IxTypography>
                          )}
                        </div>
                      </td>
                      <td className="mono">#{s.id ?? i + 1}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {pageCount > 1 && (
              <IxPagination count={pageCount} selectedPage={currentPage} onPageSelected={(e: CustomEvent<number>) => setPage(e.detail)} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

function DistributionCard({ title, items }: { title: string; items: Array<{ label: string; count: number; pct: number }> }) {
  return (
    <IxCard variant="outline" passive>
      <IxCardContent>
        <div className="stack">
          <IxTypography format="h5">{title}</IxTypography>
          {items.length === 0 ? (
            <IxTypography format="body-sm" textColor="weak">No data</IxTypography>
          ) : (
            items.map(item => (
              <div key={item.label} className="dist-bar">
                <div className="row-between">
                  <IxTypography format="label">{item.label}</IxTypography>
                  <IxTypography format="label-sm" textColor="soft">{item.count} ({item.pct}%)</IxTypography>
                </div>
                <div className="dist-track" role="progressbar" aria-label={item.label} aria-valuenow={item.pct} aria-valuemin={0} aria-valuemax={100}>
                  <div className="dist-fill" style={{ width: `${item.pct}%` }} />
                </div>
              </div>
            ))
          )}
        </div>
      </IxCardContent>
    </IxCard>
  )
}
