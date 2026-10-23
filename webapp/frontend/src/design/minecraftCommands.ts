/**
 * The Minecraft chat's own commands (MinecraftChat.tsx): the time, the weather, the game mode, XP, the
 * minigames, the chest and advancements, /say and /me. Everything else goes on to the Retro Terminal's
 * interpreter, so the wizard commands work here too.
 */
import { addXp, readGameMode, setGameMode, unlock } from './minecraftState'
import { type CommandReply, emitChrome, emitCommand } from './signals'

/** What the chat opens, beyond the wizard: the Minecraft HUD's own screens. */
export interface ChatActions {
  openGame: (game?: 'mining' | 'runner' | 'crafting') => void
  openChest: () => void
  openAdvancements: () => void
}

const HELP = '/sign /verify /load doc /set level LTA /run /status /reset · /time set day|night · /weather clear|rain · ' +
  '/gamemode survival|creative · /xp add <n> · /play [mining|runner|crafting] · /chest · /advancements · /say · /kill'

/**
 * The Minecraft commands; anything else goes to the Retro Terminal's interpreter (terminalCommands.ts),
 * so /sign, /load doc, /set level LTA and /run work the wizard. Returns null for "not mine".
 */
export function minecraftCommand(line: string, actions: ChatActions): CommandReply | null {
  const [word = '', ...args] = line.trim().replace(/^\//, '').split(/\s+/)
  const a0 = args[0]?.toLowerCase() ?? ''
  const a1 = args[1]?.toLowerCase() ?? ''
  switch (word.toLowerCase()) {
    case 'help':
    case '?':
      return { text: HELP }
    case 'time': {
      const want = a0 === 'set' ? a1 : a0
      if (want === 'day' || want === 'noon' || want === 'morning') emitChrome('time-day')
      else if (want === 'night' || want === 'midnight') emitChrome('time-night')
      else return { text: 'Usage: /time set day|night', error: true }
      unlock('sweet-dreams')
      return { text: `Set the time to ${want === 'noon' || want === 'morning' ? 'day' : want === 'midnight' ? 'night' : want}` }
    }
    case 'weather':
      if (a0 === 'clear') emitChrome('weather-clear')
      else if (a0 === 'rain' || a0 === 'thunder') emitChrome('weather-rain')
      else return { text: 'Usage: /weather clear|rain', error: true }
      return { text: a0 === 'clear' ? 'Set the weather to clear' : 'Set the weather to rain' }
    case 'gamemode': {
      const mode = a0 === 'creative' || a0 === '1' || a0 === 'c' ? 'creative' : a0 === 'survival' || a0 === '0' || a0 === 's' ? 'survival' : null
      if (!mode) return { text: `Usage: /gamemode survival|creative (now ${readGameMode()})`, error: true }
      setGameMode(mode)
      return { text: `Set own game mode to ${mode[0].toUpperCase()}${mode.slice(1)} Mode` }
    }
    case 'xp':
    case 'experience': {
      const n = Number(a0 === 'add' ? a1 : a0)
      if (!Number.isFinite(n) || n <= 0 || n > 1000) return { text: 'Usage: /xp add <1-1000>', error: true }
      addXp(Math.round(n))
      return { text: `Gave ${Math.round(n)} experience points to Steve` }
    }
    case 'play': {
      const game = ({ mining: 'mining', runner: 'runner', run: 'runner', creeper: 'runner', crafting: 'crafting', craft: 'crafting' } as const)[a0]
      if (a0 && !game) return { text: 'Usage: /play [mining|runner|crafting]', error: true }
      actions.openGame(game)
      return { text: game ? `Opening ${game === 'runner' ? 'Creeper Run' : game === 'mining' ? 'Mining Run' : 'Crafting'}` : 'Opening the minigames' }
    }
    case 'chest':
      actions.openChest()
      return { text: 'Opened the chest' }
    case 'advancements':
      actions.openAdvancements()
      return { text: 'Opened the advancements' }
    case 'say':
      return args.length ? { text: `<Steve> ${args.join(' ')}` } : { text: 'Usage: /say <message>', error: true }
    case 'me':
      return args.length ? { text: `* Steve ${args.join(' ')}` } : { text: 'Usage: /me <action>', error: true }
    case 'kill':
      emitCommand({ type: 'reset' })
      return { text: 'Steve fell out of the world' }
    case 'seed':
      return { text: 'Seed: [-4172144997902289642]' }
    default:
      return null
  }
}

