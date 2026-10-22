/**
 * The Retro Terminal's command line: parses one typed line and carries it out through a context the
 * component provides (TerminalLine.tsx). Wizard commands go over the command bus in signals.ts and the
 * wizard on screen answers; the rest navigates, changes the design or powers the tube off. Every
 * command answers in one line, since the status bar only has one.
 */
import { OPTION_CHOICES } from '../components/wizard/choices'
import type { OptionsState } from '../components/wizard/types'
import { type EffectLevel, type ThemeId, THEMES } from './designs'
import type { CommandReply, FileSlot, WizardCommand } from './signals'

export type TerminalView = 'wizard' | 'dashboard' | 'about'

export interface TerminalContext {
  /** Sends a command to the wizard; null when no wizard is mounted to answer. */
  wizard: (cmd: WizardCommand) => CommandReply | null
  navigate: (view: TerminalView) => void
  /** Opens the file chooser for a slot; the choice reaches the wizard later. Must run inside the key press. */
  pickFile: (slot: FileSlot, accept: string) => void
  setTheme: (id: ThemeId) => void
  setSound: (on: boolean) => void
  setEffects: (level: EffectLevel) => void
  power: (mode: 'shutdown' | 'reboot') => void
  now?: () => Date
}

export interface TerminalReply extends CommandReply {
  /** Ask for a password next, masked, and set it as this option. */
  password?: 'keystorePassword' | 'signerPassword' | 'tsaPassword'
  /** No wizard answered: it was opened, and this command should be sent again once it is mounted. */
  retry?: WizardCommand
  /** Clear the line's message. */
  clear?: boolean
}

const KEY_ACCEPT = '.p12,.pfx,.pem,.crt,.cer,.key'

/** File slots by the names the terminal accepts, with what the chooser should offer. */
const SLOTS: Record<string, { slot: FileSlot; accept: string }> = {
  doc: { slot: 'inputDocument', accept: '' },
  document: { slot: 'inputDocument', accept: '' },
  sig: { slot: 'signedDocument', accept: '.p7s,.p7m' },
  signature: { slot: 'signedDocument', accept: '.p7s,.p7m' },
  original: { slot: 'originalFile', accept: '' },
  keystore: { slot: 'keystoreFile', accept: KEY_ACCEPT },
  signer: { slot: 'signerFile', accept: KEY_ACCEPT },
  tsa: { slot: 'tsaFile', accept: KEY_ACCEPT },
}

/** Option names the terminal accepts, mapped to the wizard's option keys. */
const OPTIONS: Record<string, keyof OptionsState> = {
  level: 'signatureLevel',
  packaging: 'packaging',
  digest: 'digest',
  hash: 'digest',
  report: 'reportFormat',
  keys: 'credentialSource',
  tsa: 'tsaUrl',
  ocsp: 'ocspUrl',
  crl: 'crlUrl',
}

const PASSWORDS: Record<string, NonNullable<TerminalReply['password']>> = {
  keystore: 'keystorePassword',
  signer: 'signerPassword',
  tsa: 'tsaPassword',
}

const VIEWS: Record<string, TerminalView> = {
  sign: 'wizard', verify: 'wizard', wizard: 'wizard', '~': 'wizard', '..': 'wizard',
  analytics: 'dashboard', dashboard: 'dashboard', about: 'about',
}

const EFFECTS: readonly EffectLevel[] = ['wild', 'calm', 'off']

/** One line of usage per command; `help` lists the names, `help <cmd>` shows the line. */
const HELP: Record<string, string> = {
  sign: 'sign — start signing and choose the document',
  verify: 'verify — start verifying and choose the signature',
  load: `load <${Object.keys(SLOTS).filter(k => k !== 'document' && k !== 'signature').join('|')}> — choose a file for that slot`,
  keys: 'keys <generate|keystore|separate> — where the signing keys come from',
  set: `set <${Object.keys(OPTIONS).filter(k => k !== 'hash').join('|')}> <value> — change an option; set <name> lists the values`,
  password: 'password [keystore|signer|tsa] — enter a password, hidden',
  next: 'next — go to the next step',
  back: 'back — go to the previous step',
  run: 'run — sign or verify now',
  cancel: 'cancel — stop the running operation',
  reset: 'reset — start over',
  status: 'status — what is chosen so far',
  ls: 'ls — the files loaded so far',
  cd: 'cd <sign|analytics|about> — go to a page',
  man: 'man — the manual: what this app does, levels, packaging, trust, results',
  theme: 'theme [name] — list the themes, or switch to one',
  sound: 'sound <on|off> — theme sound',
  effects: `effects <${EFFECTS.join('|')}> — animation`,
  shutdown: 'shutdown — switch the terminal off',
  reboot: 'reboot — switch it off and on again',
  exit: 'exit — leave the Retro Terminal theme',
  clear: 'clear — clear the line',
  echo: 'echo <text> — print the text',
  whoami: 'whoami — who you are',
  date: 'date — the date and time',
  help: 'help [command] — this help',
}

export const COMMANDS = Object.keys(HELP)

const error = (text: string): TerminalReply => ({ text, error: true })

/** Sends a wizard command, opening the wizard first when it is not on screen. */
function ask(ctx: TerminalContext, cmd: WizardCommand): TerminalReply {
  const reply = ctx.wizard(cmd)
  if (reply) return reply
  ctx.navigate('wizard')
  return { text: 'opening sign / verify...', retry: cmd }
}

/** The choices of an option, for errors and completion; free text options have none. */
const choicesOf = (key: keyof OptionsState) =>
  (OPTION_CHOICES as Partial<Record<keyof OptionsState, readonly { value: string }[]>>)[key]?.map(c => c.value.toLowerCase())

function findTheme(name: string): ThemeId | undefined {
  const n = name.toLowerCase()
  return (THEMES.find(t => t.id === n) ?? THEMES.find(t => t.label.toLowerCase().replace(/[^a-z0-9]/g, '').startsWith(n.replace(/[^a-z0-9]/g, ''))))?.id
}

/** Carries out one typed line. */
export function interpret(line: string, ctx: TerminalContext): TerminalReply {
  const [word = '', ...args] = line.trim().split(/\s+/)
  const cmd = word.toLowerCase()
  const arg = args[0]?.toLowerCase() ?? ''
  switch (cmd) {
    case '':
      return { text: '', clear: true }
    case 'help':
    case '?':
      if (arg) return HELP[arg] ? { text: HELP[arg] } : error(`no help for ${arg}`)
      return { text: `${COMMANDS.join(' ')} — help <command> for more` }
    case 'sign':
    case 'verify': {
      const reply = ask(ctx, { type: 'start', action: cmd })
      if (reply.error) return reply
      const { slot, accept } = SLOTS[cmd === 'sign' ? 'doc' : 'sig']
      ctx.pickFile(slot, accept)
      return reply
    }
    case 'load': {
      const target = SLOTS[arg]
      if (!target) return error(HELP.load)
      ctx.pickFile(target.slot, target.accept)
      return { text: `choose the ${arg} file...` }
    }
    case 'keys':
      if (!arg) return error(HELP.keys)
      return ask(ctx, { type: 'set', key: 'credentialSource', value: arg })
    case 'set': {
      const key = OPTIONS[arg]
      if (!key) return error(HELP.set)
      const value = args.slice(1).join(' ')
      if (!value) {
        const choices = choicesOf(key)
        return choices ? error(`${arg}: ${choices.join('|')}`) : error(`set ${arg} <url>, or set ${arg} - to clear it`)
      }
      return ask(ctx, { type: 'set', key, value: value === '-' ? '' : value })
    }
    case 'password': {
      const key = PASSWORDS[arg || 'keystore']
      return key ? { text: `${arg || 'keystore'} password:`, password: key } : error(HELP.password)
    }
    case 'next':
    case 'back':
    case 'run':
    case 'cancel':
    case 'reset':
    case 'status':
    case 'ls':
      return ask(ctx, { type: cmd })
    case 'cd': {
      const view = VIEWS[arg || '~']
      if (!view) return error(HELP.cd)
      ctx.navigate(view)
      return { text: `cd ${arg || '~'}` }
    }
    case 'man':
    case 'about':
      ctx.navigate('about')
      return { text: 'CADES(1) — opening the manual' }
    case 'theme': {
      if (!arg) return { text: `themes: ${THEMES.map(t => t.id).join(' ')}` }
      const id = findTheme(arg)
      if (!id) return error(`no theme ${arg} (theme lists them)`)
      ctx.setTheme(id)
      return { text: `theme ${id}` }
    }
    case 'exit':
    case 'logout':
      ctx.setTheme('none')
      return { text: 'logout' }
    case 'sound':
      if (arg !== 'on' && arg !== 'off') return error(HELP.sound)
      ctx.setSound(arg === 'on')
      return { text: `sound ${arg}` }
    case 'effects': {
      const level = EFFECTS.find(l => l === arg)
      if (!level) return error(HELP.effects)
      ctx.setEffects(level)
      return { text: `effects ${level}` }
    }
    case 'shutdown':
    case 'poweroff':
    case 'halt':
    case 'reboot':
      ctx.power(cmd === 'reboot' ? 'reboot' : 'shutdown')
      return { text: cmd === 'reboot' ? 'rebooting...' : 'system halted' }
    case 'clear':
    case 'cls':
      return { text: '', clear: true }
    case 'echo':
      return { text: args.join(' ') }
    case 'whoami':
      return { text: 'operator' }
    case 'date':
      return { text: (ctx.now ?? (() => new Date()))().toString() }
    case 'sudo':
      return error('operator is not in the sudoers file. This incident will be reported.')
    default:
      return error(`command not found: ${word} (try help)`)
  }
}

/** The words that may come next after `words`, for Tab completion. */
function candidates(words: string[]): string[] {
  if (words.length <= 1) return [...COMMANDS, 'sudo']
  const [cmd, a1] = words.map(w => w.toLowerCase())
  if (words.length === 2) {
    switch (cmd) {
      case 'help': return COMMANDS
      case 'load': return Object.keys(SLOTS)
      case 'keys': return choicesOf('credentialSource') ?? []
      case 'set': return Object.keys(OPTIONS)
      case 'password': return Object.keys(PASSWORDS)
      case 'cd': return ['sign', 'analytics', 'about']
      case 'theme': return THEMES.map(t => t.id)
      case 'sound': return ['on', 'off']
      case 'effects': return [...EFFECTS]
    }
  }
  if (words.length === 3 && cmd === 'set' && OPTIONS[a1]) return choicesOf(OPTIONS[a1]) ?? []
  return []
}

/**
 * Completes the last word of `line`: to the only match, or to the longest prefix all matches share.
 * Returns the new line and the matches, so the line can show them when there are several.
 */
export function complete(line: string): { line: string; matches: string[] } {
  const words = line.replace(/^\s+/, '').split(/\s+/)
  const last = words[words.length - 1].toLowerCase()
  const matches = candidates(words).filter(c => c.startsWith(last))
  if (!matches.length) return { line, matches }
  let common = matches[0]
  for (const m of matches) while (!m.startsWith(common)) common = common.slice(0, -1)
  const head = words.slice(0, -1).join(' ')
  const done = matches.length === 1 ? `${matches[0]} ` : common
  return { line: head ? `${head} ${done}` : done, matches }
}

/**
 * Where a scrolled view stands, the way `less` shows it: (TOP), (END), or the share of the way down.
 * Null when there is nothing to scroll.
 */
export function scrollStatus(top: number, height: number, visible: number): string | null {
  const range = height - visible
  if (range <= 1) return null
  if (top <= 1) return '(TOP)'
  if (top >= range - 1) return '(END)'
  return `-- ${Math.round((top / range) * 100)}% --`
}
