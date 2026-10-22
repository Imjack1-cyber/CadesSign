import { useState, useEffect, useRef } from 'react'
import { IxButton, IxWorkflowStep, IxWorkflowSteps, showToast } from '@siemens/ix-react'
import { PageHeader } from '../layout/PageHeader'

import { Step1Action } from './Step1Action'
import { Step2Uploads } from './Step2Uploads'
import { Step3Config } from './Step3Config'
import { Step4Review } from './Step4Review'
import { Step5Result } from './Step5Result'
import {
  type Action, type FilesState, type OptionsState, type WizardResult,
  EMPTY_FILES, DEFAULT_OPTIONS, formatSize, hasSigningKeys,
} from './types'
import { OPTION_CHOICES, findChoice } from './choices'
import { type Outcome, parseValidationReport } from './validationReport'
import { parseSelfCheck } from './selfCheck'
import { describeError, readJson } from './errorMessages'
import {
  APP_COMMAND_EVENT, type CommandEvent, type CommandReply, type WizardCommand,
  emitBusy, emitFile, emitGenerated, emitOutcome, emitStep,
} from '../../design/signals'
import { useDesign } from '../../design/useDesign'
import { useMediaQuery } from '../../design/useMediaQuery'

const STEPS = ['Action', 'Files', 'Options', 'Review', 'Result'] as const

const STEP_TITLES: Record<number, { title: string; subtitle: string }> = {
  1: { title: 'Choose Action', subtitle: 'Create a CAdES signature or validate an existing one.' },
  2: { title: 'Select Files', subtitle: 'Drop files onto the upload areas or browse your computer.' },
  3: { title: 'Configure Options', subtitle: 'Defaults produce a detached CAdES B-LT signature with SHA-256.' },
  4: { title: 'Review', subtitle: 'Check your selection before running the operation.' },
  5: { title: 'Result', subtitle: '' },
}

const OPTION_KEYS: Array<keyof OptionsState> = [
  'signatureLevel', 'packaging', 'digest', 'tsaUrl', 'ocspUrl', 'crlUrl',
  'keystorePassword', 'signerPassword', 'tsaPassword', 'reportFormat', 'noKeystoreTrust',
]
const GENERATED_KEYSTORE_NAME = 'cades-keystore.p12'
/** A little above the backend's own 120 s CLI timeout, so its timeout message normally wins. */
const REQUEST_TIMEOUT_MS = 130_000
/** Below this width a vertical step rail would push the step body off screen, so steps stay horizontal. */
const WIDE_QUERY = '(min-width: 48rem)'

/** The files to upload: only those belonging to the action and, when signing, to the chosen key source. */
function filesToSend(action: Action, options: OptionsState): Array<keyof FilesState> {
  if (action === 'verify') return ['signedDocument', 'originalFile', 'keystoreFile']
  switch (options.credentialSource) {
    case 'keystore': return ['inputDocument', 'keystoreFile']
    case 'separate': return ['inputDocument', 'signerFile', 'tsaFile']
    case 'generate': return ['inputDocument']
  }
}

function base64ToBlob(base64: string, type: string): Blob {
  const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0))
  return new Blob([bytes], { type })
}

/**
 * The overall DSS indication in verifier stdout. The simple summary prints "TOTAL_PASSED"; the full
 * ETSI report carries URNs such as "...:mainindication:total-passed", so it is read via the parser.
 */
function overallOutcome(output: string): Outcome {
  const outcomes = parseValidationReport(output)?.signatures.map(s => s.result?.outcome)
  if (outcomes && outcomes.length > 0) {
    if (outcomes.includes('failed')) return 'failed'
    if (outcomes.includes('indeterminate')) return 'indeterminate'
    return outcomes.every(o => o === 'passed') ? 'passed' : 'unknown'
  }
  if (output.includes('TOTAL_FAILED')) return 'failed'
  if (output.includes('INDETERMINATE')) return 'indeterminate'
  if (output.includes('TOTAL_PASSED')) return 'passed'
  return 'unknown'
}

/** Classifies verifier stdout by the DSS indication it reports. */
function classifyVerifyOutput(output: string, success: boolean): WizardResult {
  const outcome = overallOutcome(output)
  if (!success || outcome === 'failed') {
    return { kind: 'error', title: 'Signature is not valid', message: 'Validation failed. See the report below for details.' }
  }
  if (outcome === 'indeterminate') {
    return { kind: 'warning', title: 'Validation indeterminate', message: 'The signature could not be fully validated, typically because a trust anchor or revocation data is missing.' }
  }
  if (outcome === 'passed') {
    return { kind: 'success', title: 'Signature is valid', message: 'The signature passed validation.' }
  }
  return { kind: 'info', title: 'Verification finished' }
}

function downloadBlob(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  window.URL.revokeObjectURL(url)
}

function getWarnings(action: Action, files: FilesState, options: OptionsState): string[] {
  const warnings: string[] = []
  if (action === 'sign') {
    if (options.packaging === 'DETACHED') {
      warnings.push("Keep the original file: you are generating a detached signature. Verification needs both the original file and the .p7s signature.")
    }
    if (options.credentialSource === 'generate') {
      warnings.push(`A new keystore will be generated and downloaded as ${GENERATED_KEYSTORE_NAME}. Keep it: you need it to sign again with the same identity and to verify against its root.`)
    }
    if (options.signatureLevel === 'LT' && options.tsaUrl && !options.ocspUrl && !options.crlUrl) {
      warnings.push('LT constraint: an external TSA chains to a CA the offline PKI knows nothing about. Without OCSP/CRL endpoints, full LT validation may fall back to B-T.')
    }
  }
  if (action === 'verify') {
    if (!files.keystoreFile) {
      warnings.push('No trust anchor keystore: if the root certificate is not in the default Java keystore or the EU LOTL, validation will be indeterminate.')
    }
    if (!files.originalFile) {
      warnings.push('No original file: the signature is assumed to be enveloping. A detached signature will fail to verify.')
    }
  }
  return warnings
}

export function Wizard() {
  const { active } = useDesign()
  const isWide = useMediaQuery(WIDE_QUERY)
  const [step, setStep] = useState(1)
  const [action, setAction] = useState<Action>('')
  const [files, setFiles] = useState<FilesState>(EMPTY_FILES)
  const [options, setOptions] = useState<OptionsState>(DEFAULT_OPTIONS)
  const [result, setResult] = useState<WizardResult | null>(null)
  const [fullReport, setFullReport] = useState<string | null>(null)
  const [signature, setSignature] = useState<{ blob: Blob; name: string } | null>(null)
  const [generatedKeystore, setGeneratedKeystore] = useState<Blob | null>(null)
  const [loading, setLoading] = useState(false)
  const requestRef = useRef<AbortController | null>(null)

  const warnings = getWarnings(action, files, options)

  // Leaving the page abandons any request still in flight.
  useEffect(() => () => requestRef.current?.abort(), [])

  // Theme effects react to requests in flight and to how they ended.
  useEffect(() => {
    if (result) emitOutcome(result.kind, result.title, result.message)
  }, [result])
  useEffect(() => {
    emitBusy(loading)
  }, [loading])
  useEffect(() => {
    emitStep(step, action)
  }, [step, action])

  /** A signal for one request: aborted on cancel, on a newer request, or after REQUEST_TIMEOUT_MS. */
  const startRequest = () => {
    requestRef.current?.abort()
    const controller = new AbortController()
    requestRef.current = controller
    const timer = setTimeout(() => controller.abort('timeout'), REQUEST_TIMEOUT_MS)
    const finish = () => {
      clearTimeout(timer)
      if (requestRef.current === controller) requestRef.current = null
    }
    return { signal: controller.signal, finish }
  }

  const cancelRequest = () => requestRef.current?.abort('cancel')

  // Bring the new step into view, mainly for small screens where the actions bar sits below the fold.
  useEffect(() => {
    window.scrollTo?.({ top: 0, behavior: 'smooth' })
  }, [step])

  const hasRequiredFiles = action === 'sign' ? files.inputDocument !== null : action === 'verify' ? files.signedDocument !== null : false
  // Signing is never allowed without keys: a keystore, a signer file, or an explicit generation.
  const isReady = hasRequiredFiles && (action !== 'sign' || hasSigningKeys(files, options))

  const canAdvance = (): boolean => {
    if (step === 1) return action !== ''
    if (step === 2) return hasRequiredFiles
    if (step === 3) return isReady
    return true
  }

  const buildFormData = (overrides: Partial<OptionsState> = {}) => {
    const formData = new FormData()
    filesToSend(action, options).forEach(k => { const f = files[k]; if (f) formData.append(k, f) })
    const merged = { ...options, ...overrides }
    OPTION_KEYS.forEach(k => formData.append(k, merged[k]))
    if (action === 'sign' && options.credentialSource === 'generate') formData.append('generateKeystore', 'true')
    return formData
  }

  const executeAction = async () => {
    setLoading(true)
    setFullReport(null)
    const { signal, finish } = startRequest()
    try {
      const res = await fetch(`/api/${action}`, { method: 'POST', body: buildFormData(), signal })

      if (action === 'sign' && res.ok) {
        const blob = await res.blob()
        const name = `${files.inputDocument?.name ?? 'document'}.p7s`
        downloadBlob(blob, name)
        setSignature({ blob, name })
        emitGenerated({ folder: 'signatures', name, blob })
        const keystore = res.headers.get('X-Cades-Keystore')
        const keystoreBlob = keystore ? base64ToBlob(keystore, 'application/x-pkcs12') : null
        if (keystoreBlob) {
          downloadBlob(keystoreBlob, GENERATED_KEYSTORE_NAME)
          emitGenerated({ folder: 'keystores', name: GENERATED_KEYSTORE_NAME, blob: keystoreBlob })
        }
        setGeneratedKeystore(keystoreBlob)
        const summary = res.headers.get('X-Cades-Summary')
        const output = summary ? decodeURIComponent(summary) : undefined
        if (output) emitGenerated({ folder: 'reports', name: `${name}-self-check.txt`, blob: new Blob([output], { type: 'text/plain' }) })
        const check = parseSelfCheck(output)
        const created = keystoreBlob
          ? `${name} and the new keystore ${GENERATED_KEYSTORE_NAME} were generated and downloaded.`
          : `${name} was generated and downloaded.`
        // The self-check judges the signature against the level that was requested.
        setResult(check?.passed === false
          ? {
            kind: 'warning', title: 'Signature created',
            message: `${created} Its self-check did not pass for ${check.requested ?? 'the requested level'}; see the details below.`,
            output,
          }
          : { kind: 'success', title: 'Signature created', message: created, output })
        showToast({ type: 'success', title: 'Signature downloaded', message: name })
      } else {
        const data = await readJson(res)
        const failedTitle = action === 'sign' ? 'Signing failed' : 'Verification failed'
        // A recognised failure gets an explanation; its raw text moves to the technical details.
        const friendly = !res.ok ? describeError(data.error) : data.success === false ? describeError(data.errorOutput) : null
        if (friendly) {
          const details = [data.error, data.output, data.errorOutput].filter(Boolean).join('\n')
          setResult({ kind: 'error', title: friendly.title ?? failedTitle, message: friendly.message, details })
        } else if (!res.ok) {
          setResult({ kind: 'error', title: failedTitle, output: data.error || 'Request failed' })
        } else {
          const output = [data.output, data.success === false ? data.errorOutput : ''].filter(Boolean).join('\n')
          setResult({ ...classifyVerifyOutput(output, data.success !== false), output: output || 'No output' })
          if (output) {
            const xml = options.reportFormat === 'full'
            emitGenerated({
              folder: 'reports',
              name: `${files.signedDocument?.name ?? 'signature'}-validation.${xml ? 'xml' : 'txt'}`,
              blob: new Blob([output], { type: xml ? 'application/xml' : 'text/plain' }),
            })
          }
        }
      }
    } catch {
      if (signal.aborted && signal.reason !== 'timeout') {
        // Cancelled by the user or abandoned: stay on Review with the selection intact.
        finish()
        setLoading(false)
        if (signal.reason === 'cancel') showToast({ type: 'info', title: 'Operation cancelled', message: 'The result of the request is discarded.' })
        return
      }
      setResult(signal.aborted
        ? { kind: 'error', title: 'Request timed out', message: 'The server did not answer in time. A slow or unreachable TSA, OCSP or CRL endpoint is the usual cause; try again or check the endpoints.' }
        : { kind: 'error', title: 'Connection problem', message: 'A network or server error occurred. Check that the backend is running and try again.' })
    }
    finish()
    setLoading(false)
    setStep(5)
  }

  const fetchFullReport = async () => {
    setLoading(true)
    const { signal, finish } = startRequest()
    try {
      const body = buildFormData({ reportFormat: 'full' })
      // Same verification as the summary run; keep it out of the metrics
      body.append('track', 'false')
      const res = await fetch('/api/verify', { method: 'POST', body, signal })
      const data = await readJson(res)
      setFullReport(!res.ok ? (data.error || 'Failed to fetch full report')
        : data.success === false ? (data.errorOutput || 'Failed to fetch full report') : (data.output || 'No report data'))
      if (res.ok && data.success !== false && data.output) {
        emitGenerated({
          folder: 'reports',
          name: `${files.signedDocument?.name ?? 'signature'}-validation-report.xml`,
          blob: new Blob([data.output], { type: 'application/xml' }),
        })
      }
    } catch {
      if (!signal.aborted || signal.reason === 'timeout') {
        setFullReport(signal.aborted ? 'The server did not answer in time.' : 'A network or server error occurred.')
      }
    }
    finish()
    setLoading(false)
  }

  const onStartOver = () => {
    requestRef.current?.abort()
    setStep(1)
    setAction('')
    setResult(null)
    setFullReport(null)
    setSignature(null)
    setGeneratedKeystore(null)
    setFiles(EMPTY_FILES)
    setOptions(DEFAULT_OPTIONS)
  }

  /** Why the operation cannot run yet, in a few words, or null when it can. */
  const missing = (): string | null => {
    if (!action) return 'choose an action first: sign or verify'
    if (!hasRequiredFiles) return action === 'sign' ? 'no document loaded (load doc)' : 'no signature loaded (load sig)'
    if (!isReady) {
      return options.credentialSource === 'keystore'
        ? 'no keystore loaded (load keystore, or keys generate)'
        : 'the signer key, or a TSA key or URL for this level, is missing (load signer, load tsa)'
    }
    return null
  }

  /** Answers a command from the terminal theme's command line by working the wizard on screen. */
  const command = (cmd: WizardCommand): CommandReply => {
    const error = (text: string): CommandReply => ({ text, error: true })
    if (loading && cmd.type !== 'cancel' && cmd.type !== 'status') return error('busy: wait for the running operation, or cancel')
    switch (cmd.type) {
      case 'start':
        setAction(cmd.action)
        setResult(null)
        setFullReport(null)
        setStep(2)
        return { text: `${cmd.action}: now load the ${cmd.action === 'sign' ? 'document (load doc)' : 'signature (load sig)'}` }
      case 'file': {
        setFiles({ ...files, [cmd.slot]: cmd.file })
        emitFile(true)
        return { text: `loaded ${cmd.file.name} (${formatSize(cmd.file.size)})` }
      }
      case 'set': {
        const key = cmd.key as keyof OptionsState
        if (!(key in options)) return error(`unknown option: ${cmd.key}`)
        const choices = (OPTION_CHOICES as Partial<Record<keyof OptionsState, readonly { value: string; label: string }[]>>)[key]
        let value = cmd.value.trim()
        if (choices) {
          const choice = findChoice(choices, value)
          if (!choice) return error(`${cmd.key}: one of ${choices.map(c => c.value).join(', ')}`)
          value = choice.value
        }
        setOptions({ ...options, [key]: value })
        return { text: key.endsWith('Password') ? 'password set' : `${key} = ${value || '(empty)'}` }
      }
      case 'next': {
        if (step >= 4) return error('at review already: type run')
        if (!canAdvance()) return error(missing() ?? 'cannot go on yet')
        setStep(step + 1)
        return { text: `step ${step + 1}: ${STEPS[step]}` }
      }
      case 'back':
        if (step <= 1) return error('already at the first step')
        setStep(step - 1)
        return { text: `step ${step - 1}: ${STEPS[step - 2]}` }
      case 'run': {
        const why = missing()
        if (why) return error(why)
        setStep(4)
        void executeAction()
        return { text: action === 'sign' ? `signing ${files.inputDocument?.name}...` : `verifying ${files.signedDocument?.name}...` }
      }
      case 'cancel':
        if (!loading) return error('nothing is running')
        cancelRequest()
        return { text: 'cancelled' }
      case 'reset':
        onStartOver()
        return { text: 'reset: choose sign or verify' }
      case 'ls': {
        const loaded = Object.values(files).filter((f): f is File => f !== null)
        return { text: loaded.length ? loaded.map(f => `${f.name} (${formatSize(f.size)})`).join('  ') : 'no files loaded' }
      }
      case 'status': {
        if (!action) return { text: `step ${step}: no action yet (sign or verify)` }
        const doc = action === 'sign' ? files.inputDocument : files.signedDocument
        const keys = action === 'sign' ? ` · keys=${options.credentialSource}` : ''
        const how = action === 'sign' ? `${options.signatureLevel}/${options.packaging}/${options.digest}` : `report=${options.reportFormat}`
        return { text: `${action} · ${doc ? doc.name : 'no file'} · ${how}${keys} · step ${step} ${STEPS[step - 1]}${loading ? ' · running' : ''}` }
      }
    }
  }

  // The listener stays put; it always calls the latest command(), which sees the current state.
  const commandRef = useRef(command)
  useEffect(() => {
    commandRef.current = command
  })
  useEffect(() => {
    const onCommand = (e: Event) => {
      const { command: cmd, reply } = (e as CommandEvent).detail
      reply(commandRef.current(cmd))
    }
    window.addEventListener(APP_COMMAND_EVENT, onCommand)
    return () => window.removeEventListener(APP_COMMAND_EVENT, onCommand)
  }, [])

  const resultStatus = (): 'success' | 'warning' | 'error' | 'done' => {
    if (!result) return 'done'
    return result.kind === 'info' ? 'done' : result.kind
  }

  const onStepSelected = (e: CustomEvent<number>) => {
    const target = e.detail + 1
    // Only completed steps can be revisited; the result is reached by running the operation.
    if (target < step && !loading) {
      setStep(target)
    } else {
      e.preventDefault()
    }
  }

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <Step1Action
            action={action}
            onSelect={setAction}
            onContinue={a => {
              setAction(a)
              setStep(2)
            }}
          />
        )
      case 2:
        return <Step2Uploads files={files} setFiles={setFiles} action={action} />
      case 3:
        return <Step3Config options={options} setOptions={setOptions} files={files} setFiles={setFiles} action={action} />
      case 4:
        return <Step4Review action={action} files={files} options={options} warnings={warnings} />
      case 5:
        return (
          <Step5Result
            action={action}
            result={result}
            fullReport={fullReport}
            reportIsFull={options.reportFormat === 'full'}
            loading={loading}
            onFetchFullReport={fetchFullReport}
            onDownloadXml={() => {
              const xml = fullReport ?? result?.output
              if (xml) downloadBlob(new Blob([xml], { type: 'application/xml' }), 'validation-report.xml')
            }}
            onDownloadSignature={signature ? () => downloadBlob(signature.blob, signature.name) : undefined}
            onDownloadKeystore={generatedKeystore ? () => downloadBlob(generatedKeystore, GENERATED_KEYSTORE_NAME) : undefined}
            onBackToSummary={() => setFullReport(null)}
            onChangeOptions={() => setStep(3)}
            onStartOver={onStartOver}
          />
        )
      default:
        return null
    }
  }

  const { title, subtitle } = STEP_TITLES[step]
  const vertical = !!active.layout.stepsVertical && isWide

  return (
    <div className="page">
      <PageHeader
        title={step === 5 && result ? result.title : title}
        subtitle={step === 5 ? (action === 'sign' ? 'Signing' : 'Verification') : subtitle}
      />

      <div className={vertical ? 'wizard-layout wizard-layout--vertical' : 'wizard-layout'}>
        <div className="wizard-steps">
          <IxWorkflowSteps clickable vertical={vertical} selectedIndex={step - 1} onStepSelected={onStepSelected}>
            {STEPS.map((label, i) => (
              <IxWorkflowStep
                key={label}
                status={i < step - 1 ? 'done' : i === 4 && step === 5 ? resultStatus() : 'open'}
                disabled={i > step - 1}
              >
                {label}
              </IxWorkflowStep>
            ))}
          </IxWorkflowSteps>
        </div>

        <div className="wizard-body">{renderStep()}</div>
      </div>

      {step < 5 && (
        <div className="actions-bar">
          {step > 1 && (
            <IxButton variant="secondary" icon="chevron-left" disabled={loading} onClick={() => setStep(step - 1)}>
              Back
            </IxButton>
          )}
          <div className="actions-end">
            {step === 4 && loading && (
              <IxButton variant="secondary" icon="cancel" onClick={cancelRequest}>Cancel</IxButton>
            )}
            {step < 4 ? (
              <IxButton variant="primary" iconRight="chevron-right" disabled={!canAdvance()} onClick={() => setStep(step + 1)}>
                {step === 3 ? 'Review' : 'Next'}
              </IxButton>
            ) : (
              <IxButton
                variant="primary"
                icon={action === 'sign' ? 'ink-pen' : 'shield-check'}
                loading={loading}
                disabled={loading || !isReady}
                onClick={executeAction}
              >
                {loading ? (action === 'sign' ? 'Signing…' : 'Verifying…') : action === 'sign' ? 'Sign document' : 'Verify signature'}
              </IxButton>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
