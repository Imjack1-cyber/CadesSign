/**
 * What the app tells the running theme effect about itself: a request is in flight, an operation
 * ended with a result, or the theme's own chrome was used. The wizard and the Windows 95 taskbar emit
 * these; effects/engine.ts listens and forwards them to the preset. Nothing listens while no theme
 * effect runs, so emitting is always cheap.
 */

export type Outcome = 'success' | 'warning' | 'error' | 'info'

import type { Box } from './effects/presets'

/** Something happened in a theme's own working chrome, such as the Windows 95 Start menu or a window. */
export type ChromeEvent =
  | 'start-open' | 'start-close' | 'shutdown' | 'startup'
  | 'minimize' | 'maximize' | 'restore' | 'close' | 'navigate' | 'open' | 'assistant'

/** Where a window animates from and to, in viewport px. */
export interface ChromeMotion {
  from?: Box
  to?: Box
}

export type AppSignal =
  | { type: 'outcome'; kind: Outcome }
  | { type: 'busy'; on: boolean }
  | ({ type: 'chrome'; event: ChromeEvent } & ChromeMotion)
  /** The wizard moved to a step (1-5) for an action ('' until one is picked). */
  | { type: 'step'; step: number; action: string }

export const APP_SIGNAL_EVENT = 'app-theme-signal'

const emit = (detail: AppSignal) => {
  window.dispatchEvent(new CustomEvent<AppSignal>(APP_SIGNAL_EVENT, { detail }))
}

export const emitOutcome = (kind: Outcome) => emit({ type: 'outcome', kind })
export const emitBusy = (on: boolean) => emit({ type: 'busy', on })
export const emitChrome = (event: ChromeEvent, motion: ChromeMotion = {}) => emit({ type: 'chrome', event, ...motion })
export const emitStep = (step: number, action: string) => emit({ type: 'step', step, action })

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
