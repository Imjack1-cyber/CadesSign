import { useMemo, useState } from 'react'
import { IxButton, IxIcon, IxMessageBar, IxToggleButton, IxTypography } from '@siemens/ix-react'
import type { Action, ResultKind, WizardResult } from './types'
import { parseValidationReport } from './validationReport'
import { parseSelfCheck, type SelfCheck } from './selfCheck'
import { ValidationReportView } from './ValidationReportView'

interface Step5ResultProps {
  action: Action
  result: WizardResult | null
  fullReport: string | null
  reportIsFull: boolean
  loading: boolean
  onFetchFullReport: () => void
  onDownloadXml: () => void
  onDownloadSignature?: () => void
  onDownloadKeystore?: () => void
  onBackToSummary: () => void
  onChangeOptions: () => void
  onStartOver: () => void
}

const MESSAGE_TYPE: Record<ResultKind, 'success' | 'warning' | 'alarm' | 'info'> = {
  success: 'success',
  warning: 'warning',
  error: 'alarm',
  info: 'info',
}

/** The signing self-check as a checklist: only the rows the requested level calls for. */
function SelfCheckView({ check }: { check: SelfCheck }) {
  return (
    <dl className="self-check" aria-label="Self-check">
      {check.rows.map(row => (
        <div key={row.label} className={row.label === 'Passed' ? 'self-check-row self-check-row--verdict' : 'self-check-row'}>
          <dt>{row.label}</dt>
          <dd>
            {row.ok !== undefined && (
              <IxIcon
                name={row.ok ? 'success' : 'error'}
                size="16"
                color={row.ok ? 'color-success' : 'color-alarm'}
                aria-hidden="true"
              />
            )}
            <span>{row.value}</span>
            {row.note && <span className="self-check-note">{row.note}</span>}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function Step5Result({
  action, result, fullReport, reportIsFull, loading,
  onFetchFullReport, onDownloadXml, onDownloadSignature, onDownloadKeystore, onBackToSummary, onChangeOptions, onStartOver,
}: Step5ResultProps) {
  const [showXml, setShowXml] = useState(false)
  const report = fullReport ?? result?.output
  // Only the full verify report is ETSI XML; anything else stays plain text.
  const isXmlReport = action === 'verify' && (fullReport !== null || reportIsFull)
  const parsed = useMemo(() => (isXmlReport && report ? parseValidationReport(report) : null), [isXmlReport, report])
  const selfCheck = useMemo(() => (action === 'sign' ? parseSelfCheck(result?.output) : null), [action, result])

  if (!result) return null

  // The first verify run already returned the full report when the user picked that format.
  const canFetchFull = action === 'verify' && !fullReport && !reportIsFull && result.output !== undefined
  const hasXml = fullReport !== null || (action === 'verify' && reportIsFull && !!result.output)

  return (
    <div className="stack" data-result={result.kind} data-action={action}>
      <IxMessageBar type={MESSAGE_TYPE[result.kind]} persistent role="status">
        <strong>{result.title}.</strong> {result.message}
      </IxMessageBar>

      {report && (
        <div className="stack-sm">
          <div className="row-between">
            <IxTypography format="h4">
              {isXmlReport
                ? 'Full validation report'
                : selfCheck?.requested ? `Self-check for ${selfCheck.requested}` : action === 'sign' ? 'Details' : 'Validation summary'}
            </IxTypography>
            {parsed && (
              <div className="row" role="group" aria-label="Report view">
                <IxToggleButton variant="subtle-primary" icon="list" pressed={!showXml} onPressedChange={() => setShowXml(false)}>
                  Structured
                </IxToggleButton>
                <IxToggleButton variant="subtle-primary" icon="code" pressed={showXml} onPressedChange={() => setShowXml(true)}>
                  XML
                </IxToggleButton>
              </div>
            )}
          </div>
          {parsed && !showXml
            ? <ValidationReportView report={parsed} />
            : selfCheck
              ? <SelfCheckView check={selfCheck} />
              : <pre className="report-pre" tabIndex={0} aria-label="Report output">{report}</pre>}
        </div>
      )}

      {result.details && (
        <details className="technical-details">
          <summary>Technical details</summary>
          <pre className="report-pre" tabIndex={0} aria-label="Technical details">{result.details}</pre>
        </details>
      )}

      <div className="actions-bar">
        <IxButton variant="secondary" onClick={onChangeOptions}>Change options</IxButton>
        <div className="actions-end">
          {onDownloadSignature && (
            <IxButton variant="secondary" icon="download" onClick={onDownloadSignature}>Download again</IxButton>
          )}
          {onDownloadKeystore && (
            <IxButton variant="secondary" icon="download" onClick={onDownloadKeystore}>Download keystore</IxButton>
          )}
          {canFetchFull && (
            <IxButton variant="secondary" icon="audit-report" loading={loading} disabled={loading} onClick={onFetchFullReport}>
              View full report
            </IxButton>
          )}
          {fullReport && <IxButton variant="secondary" onClick={onBackToSummary}>Back to summary</IxButton>}
          {hasXml && <IxButton variant="secondary" icon="download" onClick={onDownloadXml}>Download XML</IxButton>}
          <IxButton variant="primary" icon="refresh" onClick={onStartOver}>Start over</IxButton>
        </div>
      </div>
    </div>
  )
}
