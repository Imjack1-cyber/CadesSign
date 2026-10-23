import { beforeEach, describe, expect, it, vi } from 'vitest'
import { minecraftCommand } from '../../design/minecraftCommands'
import {
  MC_STATE_EVENT, type McChange, addXp, bankRun, buyPick, buySupply, readAdvancements, readBank, readGameMode, readRecords,
  readXp, saveRecord, unlock, xpToNext,
} from '../../design/minecraftState'
import { APP_COMMAND_EVENT, APP_SIGNAL_EVENT, type AppSignal, type CommandEvent } from '../../design/signals'

beforeEach(() => window.localStorage.clear())

/** Collects what the state module announces while `fn` runs. */
function heard(fn: () => void) {
  const changes: McChange[] = []
  const on = (e: Event) => changes.push((e as CustomEvent<McChange>).detail)
  window.addEventListener(MC_STATE_EVENT, on)
  fn()
  window.removeEventListener(MC_STATE_EVENT, on)
  return changes
}

describe('minecraft state', () => {
  it('levels up along the game\'s XP curve and keeps the rest', () => {
    expect(xpToNext(0)).toBe(7)
    expect(xpToNext(16)).toBe(42)
    expect(xpToNext(31)).toBe(121)
    expect(addXp(10)).toEqual({ xp: { level: 1, points: 3 }, levels: 1 })
    expect(addXp(100).xp.level).toBe(7)
    expect(readXp().level).toBe(7)
  })

  it('unlocks an advancement once, and says so', () => {
    const changes = heard(() => {
      expect(unlock('stone-age')).toBe(true)
      expect(unlock('stone-age')).toBe(false)
    })
    expect(changes).toEqual([{ kind: 'advancement', id: 'stone-age' }])
    expect(readAdvancements()['stone-age']).toBeGreaterThan(0)
  })

  it('keeps a best score only when it is better', () => {
    expect(saveRecord('runner', 300)).toBe(true)
    expect(saveRecord('runner', 200)).toBe(false)
    expect(readRecords()).toEqual({ runner: 300 })
  })

  it('banks a run\'s ores and spends them on pickaxes, torches and buckets', () => {
    bankRun({ coal: 10, iron: 4, gold: 1 }, { torches: 0, buckets: 0 })
    expect(readBank().ores).toEqual({ coal: 10, iron: 4, gold: 1, diamond: 0 })
    expect(buyPick('iron')).toBe(false)
    expect(buyPick('stone')).toBe(true)
    expect(buyPick('stone')).toBe(false)
    expect(buySupply('torches')).toBe(true)
    expect(buySupply('bucket')).toBe(true)
    const bank = readBank()
    expect(bank).toMatchObject({ pick: 'stone', owned: 'stone', torches: 4, buckets: 1 })
    expect(bank.ores).toEqual({ coal: 0, iron: 1, gold: 1, diamond: 0 })
    // What a run leaves of them is what remains.
    bankRun({}, { torches: 1, buckets: 0 })
    expect(readBank()).toMatchObject({ torches: 1, buckets: 0 })
  })
})

describe('minecraft chat commands', () => {
  const actions = { openGame: vi.fn(), openChest: vi.fn(), openAdvancements: vi.fn() }

  it('sets the time and the weather through the theme, and earns Sweet Dreams', () => {
    const events: AppSignal[] = []
    const on = (e: Event) => events.push((e as CustomEvent<AppSignal>).detail)
    window.addEventListener(APP_SIGNAL_EVENT, on)
    expect(minecraftCommand('/time set night', actions)).toEqual({ text: 'Set the time to night' })
    expect(minecraftCommand('/weather rain', actions)?.error).toBeUndefined()
    expect(minecraftCommand('/time set never', actions)?.error).toBe(true)
    window.removeEventListener(APP_SIGNAL_EVENT, on)
    expect(events).toEqual([{ type: 'chrome', event: 'time-night' }, { type: 'chrome', event: 'weather-rain' }])
    expect(readAdvancements()['sweet-dreams']).toBeTruthy()
  })

  it('switches the game mode, gives XP, opens the screens and passes other commands on', () => {
    minecraftCommand('/gamemode creative', actions)
    expect(readGameMode()).toBe('creative')
    minecraftCommand('/xp add 7', actions)
    expect(readXp().level).toBe(1)
    minecraftCommand('/play runner', actions)
    expect(actions.openGame).toHaveBeenCalledWith('runner')
    minecraftCommand('/chest', actions)
    expect(actions.openChest).toHaveBeenCalled()
    expect(minecraftCommand('/say hi there', actions)).toEqual({ text: '<Steve> hi there' })
    // Not a Minecraft command: the terminal's interpreter gets it.
    expect(minecraftCommand('/sign', actions)).toBeNull()
  })

  it('/kill starts the wizard over', () => {
    const sent: string[] = []
    const on = (e: Event) => {
      const { command, reply } = (e as CommandEvent).detail
      sent.push(command.type)
      reply({ text: 'ok' })
    }
    window.addEventListener(APP_COMMAND_EVENT, on)
    expect(minecraftCommand('/kill', actions)?.text).toBe('Steve fell out of the world')
    window.removeEventListener(APP_COMMAND_EVENT, on)
    expect(sent).toEqual(['reset'])
  })
})
