import { useCallback, useEffect, useRef } from 'react'
import { APP_SIGNAL_EVENT, type AppSignal, type CommandReply, type WizardCommand, emitCommand } from './signals'

/**
 * Works the wizard from a theme's own chrome (the terminal's command line, iPadOS Spotlight). `send`
 * delivers a command at once when the wizard is on screen; otherwise it opens the wizard and delivers
 * the command as soon as the wizard shows its first step. `later` only queues one for that moment.
 * Replies, including late ones, go to `onReply`.
 */
export function useWizardCommand(openWizard: () => void, onReply: (reply: CommandReply) => void) {
  const pending = useRef<WizardCommand | null>(null)
  const reply = useRef(onReply)
  const open = useRef(openWizard)
  useEffect(() => {
    reply.current = onReply
    open.current = openWizard
  })

  useEffect(() => {
    const onSignal = (e: Event) => {
      const d = (e as CustomEvent<AppSignal>).detail
      if (d.type !== 'step' || !pending.current) return
      // The wizard emits its first step before it listens for commands, so send after this dispatch.
      const cmd = pending.current
      pending.current = null
      window.setTimeout(() => {
        const answer = emitCommand(cmd)
        if (answer) reply.current(answer)
      })
    }
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    return () => window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
  }, [])

  const send = useCallback((cmd: WizardCommand): CommandReply | null => {
    const answer = emitCommand(cmd)
    if (answer) {
      reply.current(answer)
      return answer
    }
    pending.current = cmd
    open.current()
    return null
  }, [])

  const later = useCallback((cmd: WizardCommand) => {
    pending.current = cmd
  }, [])

  return { send, later }
}
