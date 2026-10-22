import { describe, it, expect } from 'vitest'
import type { CommandReply, WizardCommand } from '../../design/signals'
import { COMMANDS, type TerminalContext, complete, interpret, scrollStatus } from '../../design/terminalCommands'

/** A context that records what the commands asked for; the wizard answers "ok" unless `mounted` is false. */
function fakeContext(mounted = true) {
  const calls: string[] = []
  const sent: WizardCommand[] = []
  const ctx: TerminalContext = {
    wizard: cmd => {
      if (!mounted) return null
      sent.push(cmd)
      return { text: 'ok' } satisfies CommandReply
    },
    navigate: view => calls.push(`navigate ${view}`),
    pickFile: (slot, accept) => calls.push(`pick ${slot} ${accept}`),
    setTheme: id => calls.push(`theme ${id}`),
    setSound: on => calls.push(`sound ${on}`),
    setEffects: level => calls.push(`effects ${level}`),
    power: mode => calls.push(`power ${mode}`),
    now: () => new Date(0),
  }
  return { ctx, calls, sent }
}

describe('terminal commands', () => {
  it('help lists every command; help <command> explains one', () => {
    const { ctx } = fakeContext()
    const all = interpret('help', ctx).text
    for (const c of COMMANDS) expect(all).toContain(c)
    expect(interpret('help set', ctx).text).toMatch(/^set <level\|packaging/)
    expect(interpret('help nope', ctx).error).toBe(true)
  })

  it('an unknown command says so, and an empty line just clears', () => {
    const { ctx } = fakeContext()
    expect(interpret('frobnicate now', ctx)).toEqual({ text: 'command not found: frobnicate (try help)', error: true })
    expect(interpret('   ', ctx).clear).toBe(true)
  })

  it('sign starts signing and opens the chooser for the document; verify for the signature', () => {
    const { ctx, calls, sent } = fakeContext()
    interpret('sign', ctx)
    interpret('VERIFY', ctx)
    expect(sent).toEqual([{ type: 'start', action: 'sign' }, { type: 'start', action: 'verify' }])
    expect(calls).toEqual(['pick inputDocument ', 'pick signedDocument .p7s,.p7m'])
  })

  it('load picks a file for the named slot', () => {
    const { ctx, calls } = fakeContext()
    interpret('load keystore', ctx)
    expect(calls).toEqual(['pick keystoreFile .p12,.pfx,.pem,.crt,.cer,.key'])
    expect(interpret('load banana', ctx).error).toBe(true)
  })

  it('set maps friendly names to options and lists the values when one is missing', () => {
    const { ctx, sent } = fakeContext()
    interpret('set packaging enveloping', ctx)
    interpret('set hash sha-384', ctx)
    interpret('set tsa http://tsa.example/tsr', ctx)
    interpret('set tsa -', ctx)
    interpret('keys generate', ctx)
    expect(sent).toEqual([
      { type: 'set', key: 'packaging', value: 'enveloping' },
      { type: 'set', key: 'digest', value: 'sha-384' },
      { type: 'set', key: 'tsaUrl', value: 'http://tsa.example/tsr' },
      { type: 'set', key: 'tsaUrl', value: '' },
      { type: 'set', key: 'credentialSource', value: 'generate' },
    ])
    expect(interpret('set level', ctx)).toEqual({ text: 'level: b|t|lt|lta', error: true })
    expect(interpret('set colour red', ctx).error).toBe(true)
  })

  it('password asks for a hidden entry instead of taking it on the line', () => {
    const { ctx, sent } = fakeContext()
    expect(interpret('password', ctx).password).toBe('keystorePassword')
    expect(interpret('password tsa', ctx).password).toBe('tsaPassword')
    expect(sent).toEqual([])
  })

  it('wizard commands open the wizard first when it is not on screen, and ask to be sent again', () => {
    const { ctx, calls } = fakeContext(false)
    expect(interpret('run', ctx)).toEqual({ text: 'opening sign / verify...', retry: { type: 'run' } })
    expect(calls).toEqual(['navigate wizard'])
  })

  it('navigates, changes the design and powers off', () => {
    const { ctx, calls } = fakeContext()
    for (const line of ['man', 'cd analytics', 'cd', 'theme sakura', 'theme vital', 'exit', 'sound on', 'effects calm', 'shutdown', 'reboot']) {
      expect(interpret(line, ctx).error).toBeFalsy()
    }
    expect(calls).toEqual([
      'navigate about', 'navigate dashboard', 'navigate wizard', 'theme sakura', 'theme vitals', 'theme none',
      'sound true', 'effects calm', 'power shutdown', 'power reboot',
    ])
    expect(interpret('theme plaid', ctx).error).toBe(true)
    expect(interpret('sound loud', ctx).error).toBe(true)
  })

  it('has a few small extras', () => {
    const { ctx } = fakeContext()
    expect(interpret('echo hello   world', ctx).text).toBe('hello world')
    expect(interpret('whoami', ctx).text).toBe('operator')
    expect(interpret('date', ctx).text).toBe(new Date(0).toString())
    expect(interpret('sudo run', ctx).error).toBe(true)
  })
})

describe('tab completion', () => {
  it('completes a command, an argument and an option value', () => {
    expect(complete('shu')).toEqual({ line: 'shutdown ', matches: ['shutdown'] })
    expect(complete('set pa').line).toBe('set packaging ')
    expect(complete('set packaging env').line).toBe('set packaging enveloping ')
    expect(complete('load k').line).toBe('load keystore ')
  })

  it('stops at the shared prefix when several match, and leaves the line alone when none do', () => {
    expect(complete('s')).toMatchObject({ line: 's' })
    expect(complete('s').matches).toEqual(expect.arrayContaining(['sign', 'set', 'status', 'sound', 'shutdown']))
    expect(complete('re')).toMatchObject({ line: 're', matches: ['reset', 'reboot'] })
    expect(complete('xyz')).toEqual({ line: 'xyz', matches: [] })
  })
})

describe('scroll status', () => {
  it('reads like less: top, a share of the way down, end, or nothing when it does not scroll', () => {
    expect(scrollStatus(0, 2000, 800)).toBe('(TOP)')
    expect(scrollStatus(600, 2000, 800)).toBe('-- 50% --')
    expect(scrollStatus(1200, 2000, 800)).toBe('(END)')
    expect(scrollStatus(0, 800, 800)).toBeNull()
  })
})
