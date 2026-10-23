/**
 * What the app tells the running theme effect about itself: a request is in flight, an operation
 * ended with a result, or the theme's own chrome was used. The wizard and the Windows 95 taskbar emit
 * these; effects/engine.ts listens and forwards them to the preset. Nothing listens while no theme
 * effect runs, so emitting is always cheap. The other way round, the terminal theme's command line
 * sends commands to the wizard (emitCommand), which answers in one line.
 */

export type Outcome = 'success' | 'warning' | 'error' | 'info'

import type { Box } from './effects/presets'

/**
 * Something happened in a theme's own working chrome, such as the Windows 95 Start menu or a window,
 * or the iPadOS lock screen, a sheet, a banner, a switch or slider, or a file flying into Files.
 */
export type ChromeEvent =
  | 'start-open' | 'start-close' | 'shutdown' | 'startup'
  | 'minimize' | 'maximize' | 'restore' | 'close' | 'navigate' | 'open' | 'assistant'
  | 'lock' | 'unlock' | 'dim' | 'sheet-open' | 'sheet-close' | 'banner' | 'long-press' | 'fly' | 'switch' | 'volume'
  | 'camera' | 'charge' | 'battery'

/** Where a window animates from and to, in viewport px. */
export interface ChromeMotion {
  from?: Box
  to?: Box
}

export type AppSignal =
  /** An operation ended; the title and message are what the result shows, `action` what was run. */
  | { type: 'outcome'; kind: Outcome; title?: string; message?: string; action?: string }
  | { type: 'busy'; on: boolean }
  | ({ type: 'chrome'; event: ChromeEvent } & ChromeMotion)
  /** The wizard moved to a step (1-5) for an action ('' until one is picked). */
  | { type: 'step'; step: number; action: string }
  /** The user chose a file to upload, or removed it again. */
  | { type: 'file'; added: boolean }
  /** A command typed into the terminal theme's command line was accepted or refused. */
  | { type: 'command'; ok: boolean }

export const APP_SIGNAL_EVENT = 'app-theme-signal'

const emit = (detail: AppSignal) => {
  window.dispatchEvent(new CustomEvent<AppSignal>(APP_SIGNAL_EVENT, { detail }))
}

export const emitOutcome = (kind: Outcome, title?: string, message?: string, action?: string) =>
  emit({ type: 'outcome', kind, title, message, action })
export const emitBusy = (on: boolean) => emit({ type: 'busy', on })
export const emitChrome = (event: ChromeEvent, motion: ChromeMotion = {}) => emit({ type: 'chrome', event, ...motion })
export const emitStep = (step: number, action: string) => emit({ type: 'step', step, action })
export const emitFile = (added: boolean) => emit({ type: 'file', added })
export const emitCommandResult = (ok: boolean) => emit({ type: 'command', ok })

/** The wizard's file slots and option keys, as the terminal names them (see components/wizard/types.ts). */
export type FileSlot = 'inputDocument' | 'signedDocument' | 'originalFile' | 'keystoreFile' | 'signerFile' | 'tsaFile'

/** What the terminal theme's command line asks of the wizard. */
export type WizardCommand =
  | { type: 'start'; action: 'sign' | 'verify' }
  | { type: 'file'; slot: FileSlot; file: File }
  | { type: 'set'; key: string; value: string }
  | { type: 'next' | 'back' | 'run' | 'cancel' | 'reset' | 'status' | 'ls' }

/** A reply to a command: one line of text, and whether it was an error. */
export interface CommandReply {
  text: string
  error?: boolean
}

export const APP_COMMAND_EVENT = 'app-command'

interface CommandDetail {
  command: WizardCommand
  reply: (r: CommandReply) => void
}

export type CommandEvent = CustomEvent<CommandDetail>

/**
 * Sends a command to the wizard and returns its reply, or null when no wizard is mounted to answer.
 * Listeners reply synchronously, during the dispatch.
 */
export function emitCommand(command: WizardCommand): CommandReply | null {
  let answer: CommandReply | null = null
  window.dispatchEvent(new CustomEvent<CommandDetail>(APP_COMMAND_EVENT, { detail: { command, reply: r => { answer = r } } }))
  return answer
}

/** Where a generated file belongs; the Windows 95 theme files it into a folder of that name. */
export type GeneratedFolder = 'signatures' | 'reports' | 'keystores'

export interface GeneratedFile {
  folder: GeneratedFolder
  name: string
  blob: Blob
}

/** A file the app produced: a signature, a report or a keystore. Only the Windows 95 desktop keeps them. */
export const GENERATED_EVENT = 'app-generated-file'

export const emitGenerated = (file: GeneratedFile) => {
  window.dispatchEvent(new CustomEvent<GeneratedFile>(GENERATED_EVENT, { detail: file }))
}
