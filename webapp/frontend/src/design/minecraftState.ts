/**
 * What the Minecraft theme remembers in this browser: XP and level, advancements, the game mode, the
 * minigames' best scores, and Mining Run's bank of ores with the pickaxe, torches and buckets bought
 * from it. Everything lives in localStorage (and in memory when that is blocked). Changes are
 * announced with MC_STATE_EVENT so the HUD, the chat and the minigames stay in step.
 */
import { type Ore, PICKS, type Loadout, type PickId } from './miningGame'

export const MC_STATE_EVENT = 'mc-state'

export type McChange =
  | { kind: 'advancement'; id: AdvancementId }
  | { kind: 'xp'; levels: number }
  | { kind: 'gamemode'; mode: GameMode }
  | { kind: 'bank' }

const announce = (detail: McChange) => window.dispatchEvent(new CustomEvent<McChange>(MC_STATE_EVENT, { detail }))

/** Kept when storage is blocked, so the session still remembers. */
const memory = new Map<string, string>()

function read<T>(key: string, fallback: T): T {
  let raw: string | null | undefined
  try {
    raw = window.localStorage.getItem(key)
  } catch {
    raw = memory.get(key)
  }
  if (raw == null) return fallback
  try {
    const parsed: unknown = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? { ...fallback, ...(parsed as object) } as T : (parsed as T) ?? fallback
  } catch {
    return fallback
  }
}

function write(key: string, value: unknown) {
  const raw = JSON.stringify(value)
  try {
    window.localStorage.setItem(key, raw)
  } catch {
    // Storage blocked: a memory copy lasts as long as the page.
    memory.set(key, raw)
  }
}

// ---------- XP and levels, as in the game: each level needs a little more than the last. ----------

const XP_KEY = 'cades-minecraft-xp'

export interface Xp {
  level: number
  /** Points into the current level. */
  points: number
}

/** Points from one level to the next (the game's own curve). */
export const xpToNext = (level: number) => (level < 16 ? 2 * level + 7 : level < 31 ? 5 * level - 38 : 9 * level - 158)

/** XP for how an operation ended. */
export const XP_FOR = { success: 10, warning: 4, info: 2, error: 0 } as const

export const readXp = (): Xp => read<Xp>(XP_KEY, { level: 0, points: 0 })

/** Adds points, levelling up as often as they fill the bar; returns the new XP and the levels gained. */
export function addXp(points: number): { xp: Xp; levels: number } {
  let { level, points: have } = readXp()
  have += points
  let levels = 0
  while (have >= xpToNext(level)) {
    have -= xpToNext(level)
    level++
    levels++
  }
  const xp = { level, points: have }
  write(XP_KEY, xp)
  if (points) announce({ kind: 'xp', levels })
  return { xp, levels }
}

// ---------- Advancements. ----------

const ADV_KEY = 'cades-minecraft-advancements'

export type AdvancementId =
  | 'stone-age' | 'iron-pick' | 'diamonds' | 'upgrade' | 'ouch' | 'treasure' | 'deeper' | 'monster-hunter' | 'hot-stuff'
  | 'nether' | 'crafter' | 'sweet-dreams' | 'chatty'

export const ADVANCEMENTS: ReadonlyArray<{ id: AdvancementId; title: string; description: string }> = [
  { id: 'stone-age', title: 'Stone Age', description: 'Sign your first document' },
  { id: 'iron-pick', title: "Isn't It Iron Pick", description: 'Verify a signature' },
  { id: 'diamonds', title: 'Diamonds!', description: 'Sign with long-term archive (B-LTA)' },
  { id: 'upgrade', title: 'Getting an Upgrade', description: 'Reach level 5' },
  { id: 'ouch', title: 'Ouch', description: 'Lose a heart to a failed operation' },
  { id: 'treasure', title: 'Treasure Chest', description: 'Keep a generated file in the chest' },
  { id: 'deeper', title: 'We Need to Go Deeper', description: 'Reach the deep dark in Mining Run' },
  { id: 'monster-hunter', title: 'Monster Hunter', description: 'Defeat a creeper in Mining Run' },
  { id: 'hot-stuff', title: 'Hot Stuff', description: 'Turn lava into obsidian with a water bucket' },
  { id: 'nether', title: 'We Need to Go Hotter', description: 'Run into the Nether in Creeper Run' },
  { id: 'crafter', title: 'Notary Public', description: 'Craft a Timestamped Signature' },
  { id: 'sweet-dreams', title: 'Sweet Dreams', description: 'Change the time of day with /time' },
  { id: 'chatty', title: 'Hello, World', description: 'Run a command in the chat' },
]

export const readAdvancements = (): Partial<Record<AdvancementId, number>> => read(ADV_KEY, {})

/** Unlocks an advancement; true (and announced) only the first time. */
export function unlock(id: AdvancementId): boolean {
  const done = readAdvancements()
  if (done[id]) return false
  write(ADV_KEY, { ...done, [id]: Date.now() })
  announce({ kind: 'advancement', id })
  return true
}

// ---------- Game mode: in creative, failures cost no hearts. ----------

const MODE_KEY = 'cades-minecraft-gamemode'

export type GameMode = 'survival' | 'creative'

export const readGameMode = (): GameMode => (read<string>(MODE_KEY, 'survival') === 'creative' ? 'creative' : 'survival')

export function setGameMode(mode: GameMode) {
  write(MODE_KEY, mode)
  announce({ kind: 'gamemode', mode })
}

// ---------- The minigames' best scores. ----------

const RECORD_KEY = 'cades-minecraft-record'

export type GameId = 'mining' | 'runner' | 'crafting'
export type Records = Partial<Record<GameId, number>>

export const readRecords = (): Records => read<Records>(RECORD_KEY, {})

/** Keeps a score if it beats the best; true when it does. */
export function saveRecord(game: GameId, score: number): boolean {
  const records = readRecords()
  if (score <= (records[game] ?? 0)) return false
  write(RECORD_KEY, { ...records, [game]: score })
  return true
}

// ---------- Mining Run's bank and shop. ----------

const BANK_KEY = 'cades-minecraft-bank'

export interface Bank extends Loadout {
  ores: Record<Ore, number>
  /** The best pickaxe bought so far; the loadout's pick is the one taken down. */
  owned: PickId
}

export const NEW_BANK: Bank = { ores: { coal: 0, iron: 0, gold: 0, diamond: 0 }, pick: 'wood', owned: 'wood', torches: 0, buckets: 0 }

export const readBank = (): Bank => {
  const bank = read<Bank>(BANK_KEY, NEW_BANK)
  return { ...bank, ores: { ...NEW_BANK.ores, ...bank.ores } }
}

function saveBank(bank: Bank) {
  write(BANK_KEY, bank)
  announce({ kind: 'bank' })
}

/** What the shop sells besides pickaxes: torches by the bundle and water buckets. */
export const SUPPLIES = [
  { id: 'torches', label: '4 Torches', gives: { torches: 4 }, cost: { coal: 2 } },
  { id: 'bucket', label: 'Water Bucket', gives: { buckets: 1 }, cost: { iron: 3 } },
] as const

const afford = (bank: Bank, cost: Partial<Record<Ore, number>>) =>
  (Object.entries(cost) as Array<[Ore, number]>).every(([ore, n]) => bank.ores[ore] >= n)

const pay = (bank: Bank, cost: Partial<Record<Ore, number>>): Bank['ores'] => {
  const ores = { ...bank.ores }
  for (const [ore, n] of Object.entries(cost) as Array<[Ore, number]>) ores[ore] -= n
  return ores
}

export const canBuyPick = (bank: Bank, id: PickId) => {
  const order = PICKS.map(p => p.id)
  return order.indexOf(id) > order.indexOf(bank.owned) && afford(bank, PICKS.find(p => p.id === id)!.cost)
}

export function buyPick(id: PickId): boolean {
  const bank = readBank()
  if (!canBuyPick(bank, id)) return false
  saveBank({ ...bank, ores: pay(bank, PICKS.find(p => p.id === id)!.cost), owned: id, pick: id })
  return true
}

export const canBuySupply = (bank: Bank, id: (typeof SUPPLIES)[number]['id']) => afford(bank, SUPPLIES.find(s => s.id === id)!.cost)

export function buySupply(id: (typeof SUPPLIES)[number]['id']): boolean {
  const bank = readBank()
  const item = SUPPLIES.find(s => s.id === id)!
  if (!afford(bank, item.cost)) return false
  const gives = item.gives as Partial<Loadout>
  saveBank({ ...bank, ores: pay(bank, item.cost), torches: bank.torches + (gives.torches ?? 0), buckets: bank.buckets + (gives.buckets ?? 0) })
  return true
}

/** After a run: the ores mined go into the bank, and the torches and buckets left are what remain. */
export function bankRun(ores: Partial<Record<string, number>>, left: { torches: number; buckets: number }) {
  const bank = readBank()
  const next = { ...bank.ores }
  for (const ore of Object.keys(next) as Ore[]) next[ore] += ores[ore] ?? 0
  saveBank({ ...bank, ores: next, torches: left.torches, buckets: left.buckets })
}
