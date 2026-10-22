import {
  IxBlind, IxCard, IxCardContent, IxKeyValue, IxKeyValueList, IxMessageBar, IxPill, IxTypography,
} from '@siemens/ix-react'
import {
  type Check, type Evaluation, type Indication, type Message, type ObjectKind, type Outcome,
  type SignatureReport, type ValidationObject, type ValidationReport, shortId,
} from './validationReport'

const OUTCOME: Record<Outcome, { label: string; variant: 'success' | 'alarm' | 'warning' | 'neutral'; icon: string }> = {
  passed: { label: 'Passed', variant: 'success', icon: 'success' },
  failed: { label: 'Failed', variant: 'alarm', icon: 'error' },
  indeterminate: { label: 'Indeterminate', variant: 'warning', icon: 'warning' },
  skipped: { label: 'Skipped', variant: 'neutral', icon: 'minus' },
  unknown: { label: 'Unknown', variant: 'neutral', icon: 'question' },
}

const MESSAGE_TYPE: Record<Message['level'], 'alarm' | 'warning' | 'info'> = {
  error: 'alarm',
  warning: 'warning',
  info: 'info',
}

const GROUPS: Array<{ kind: ObjectKind; label: string; icon: string }> = [
  { kind: 'timestamp', label: 'Timestamps', icon: 'clock' },
  { kind: 'revocation', label: 'Revocation data', icon: 'shield-check' },
  { kind: 'certificate', label: 'Certificates', icon: 'certificate' },
  { kind: 'signedData', label: 'Signed data', icon: 'document' },
  { kind: 'other', label: 'Other objects', icon: 'info' },
]

const checkOutcome = (check: Check): Outcome => (check.disabled ? 'skipped' : check.result?.outcome ?? 'unknown')

function OutcomePill({ outcome }: { outcome: Outcome }) {
  const { label, variant, icon } = OUTCOME[outcome]
  return <IxPill variant={variant} icon={icon}>{label}</IxPill>
}

/** A localised date; IxKeyValue only renders string values. */
const formatTime = (iso?: string) => {
  if (!iso) return '-'
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

function ResultLine({ result }: { result?: Indication }) {
  if (!result) return null
  return (
    <div className="stack-sm">
      <div className="row">
        <OutcomePill outcome={result.outcome} />
        {result.sub && <IxTypography format="label" bold>{result.sub.replace(/_/g, ' ')}</IxTypography>}
      </div>
      {result.explanation && <IxTypography format="label-sm" textColor="soft">{result.explanation}</IxTypography>}
    </div>
  )
}

function Messages({ messages }: { messages: Message[] }) {
  if (messages.length === 0) return null
  return (
    <div className="stack-sm">
      {messages.map((m, i) => (
        <IxMessageBar key={`${m.level}-${i}`} type={MESSAGE_TYPE[m.level]} persistent>{m.text}</IxMessageBar>
      ))}
    </div>
  )
}

function Chain({ evaluation }: { evaluation: Evaluation }) {
  if (evaluation.chain.length === 0) {
    return <IxTypography format="label-sm" textColor="soft">No certificate chain could be built.</IxTypography>
  }
  return (
    <ol className="report-chain">
      {evaluation.chain.map(entry => (
        <li key={`${entry.role}-${entry.id}`}>
          <IxTypography format="label-sm" textColor="soft">{entry.role}</IxTypography>
          <IxTypography format="label" bold>{entry.name ?? 'Unnamed certificate'}</IxTypography>
          <span className="report-id" title={entry.id}>{shortId(entry.id)}</span>
        </li>
      ))}
    </ol>
  )
}

function ChecksTable({ checks }: { checks: Check[] }) {
  return (
    <div className="table-wrap">
      <table className="ix-table">
        <thead>
          <tr><th>Check</th><th>Result</th><th>Detail</th></tr>
        </thead>
        <tbody>
          {checks.map((check, i) => (
            <tr key={`${check.label}-${i}`}>
              <td>{check.label}</td>
              <td><OutcomePill outcome={checkOutcome(check)} /></td>
              <td>{check.disabled ? 'Disabled by the validation policy' : check.result?.sub?.replace(/_/g, ' ') ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const checksSummary = (checks: Check[]) => {
  const passed = checks.filter(c => checkOutcome(c) === 'passed').length
  const skipped = checks.filter(c => c.disabled).length
  return `${passed} of ${checks.length - skipped} passed` + (skipped ? `, ${skipped} skipped` : '')
}

function SignatureSection({ signature, index, count }: { signature: SignatureReport; index: number; count: number }) {
  const title = signature.signer ? `Signature by ${signature.signer}` : 'Signature'
  return (
    <div className="stack">
      <IxCard variant="outline" passive>
        <IxCardContent>
          <div className="stack">
            <IxTypography format="h4">{count > 1 ? `${title} (${index + 1} of ${count})` : title}</IxTypography>
            <ResultLine result={signature.result} />
          </div>
        </IxCardContent>
      </IxCard>

      <Messages messages={signature.messages} />

      <div className="grid grid-wide">
        <IxCard variant="outline" passive>
          <IxCardContent>
            <div className="stack">
              <IxTypography format="h4">Details</IxTypography>
              <IxKeyValueList striped>
                <IxKeyValue label="Signer" value={signature.signer ?? 'Unknown'} />
                <IxKeyValue label="Claimed signing time" value={formatTime(signature.signingTime)} />
                {signature.timestampTimes.map((t, i) => (
                  <IxKeyValue key={t + i} label="Signature timestamp" value={formatTime(t)} />
                ))}
                <IxKeyValue label="Proven to exist at" value={formatTime(signature.bestSignatureTime)} />
                <IxKeyValue label="Validated at" value={formatTime(signature.validationTime)} />
                {signature.process && <IxKeyValue label="Validation process" value={signature.process} />}
                {signature.crypto && (
                  <IxKeyValue
                    label="Algorithm"
                    value={`${signature.crypto.algorithm} (${signature.crypto.secure ? 'secure' : 'not secure'})`}
                  />
                )}
                {signature.crypto?.notAfter && (
                  <IxKeyValue label="Algorithm trusted until" value={formatTime(signature.crypto.notAfter)} />
                )}
                {signature.mimeType && <IxKeyValue label="Content type" value={signature.mimeType} />}
              </IxKeyValueList>
            </div>
          </IxCardContent>
        </IxCard>

        <IxCard variant="outline" passive>
          <IxCardContent>
            <div className="stack">
              <IxTypography format="h4">Certificate chain</IxTypography>
              <Chain evaluation={signature} />
            </div>
          </IxCardContent>
        </IxCard>
      </div>

      {signature.checks.length > 0 && (
        <IxBlind label="Validation checks" sublabel={checksSummary(signature.checks)} icon="checkboxes" collapsed>
          <ChecksTable checks={signature.checks} />
        </IxBlind>
      )}
    </div>
  )
}

/** One compact label/value pair; objects are many, so they skip the taller IxKeyValue. */
function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}

function ObjectEntry({ object }: { object: ValidationObject }) {
  const problems = object.checks.filter(c => !c.disabled && c.result && c.result.outcome !== 'passed')
  return (
    <li className="report-object">
      <div className="row-between">
        <div className="stack-sm">
          <IxTypography format="label" bold>{object.name}</IxTypography>
          <IxTypography format="label-sm" textColor="soft">
            {object.type} · <span className="report-id" title={object.id}>{shortId(object.id)}</span>
          </IxTypography>
        </div>
        {object.result && <OutcomePill outcome={object.result.outcome} />}
      </div>
      <dl className="report-facts">
        {object.timestampTime && <Fact label="Time asserted" value={formatTime(object.timestampTime)} />}
        <Fact label="Proven to exist at" value={formatTime(object.poeTime)} />
        {object.crypto && <Fact label="Algorithm" value={object.crypto.algorithm} />}
        {object.checks.length > 0 && <Fact label="Checks" value={checksSummary(object.checks)} />}
      </dl>
      {object.result?.sub && <ResultLine result={object.result} />}
      {problems.length > 0 && <ChecksTable checks={problems} />}
      {object.chain.length > 0 && object.kind === 'timestamp' && <Chain evaluation={object} />}
      <Messages messages={object.messages} />
    </li>
  )
}

/** Structured rendering of the ETSI validation report. */
export function ValidationReportView({ report }: { report: ValidationReport }) {
  return (
    <div className="stack">
      {report.signatures.map((signature, i) => (
        <SignatureSection key={signature.id || i} signature={signature} index={i} count={report.signatures.length} />
      ))}

      {GROUPS.map(group => {
        const objects = report.objects.filter(o => o.kind === group.kind)
        if (objects.length === 0) return null
        const issues = objects.filter(o => o.result && o.result.outcome !== 'passed').length
        return (
          <IxBlind
            key={group.kind}
            label={`${group.label} (${objects.length})`}
            sublabel={issues ? `${issues} not passed` : undefined}
            icon={group.icon}
            collapsed
          >
            <ul className="report-objects">
              {objects.map(o => <ObjectEntry key={o.id} object={o} />)}
            </ul>
          </IxBlind>
        )
      })}
    </div>
  )
}
