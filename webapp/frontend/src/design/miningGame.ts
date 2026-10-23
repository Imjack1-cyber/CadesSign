/**
 * Mining Run, one of the Minecraft theme's minigames: a side view down through the ground, a grid of
 * blocks COLS wide that goes on as deep as the player digs. Steve is two blocks tall; he walks, climbs
 * a block, mines left, right, above and below (each block takes its own time, quicker with a better
 * pickaxe), and falls into what he dug out. Under the dirt come noise-shaped caves with water and,
 * deeper, lava; abandoned mineshafts; spawners that bring creepers; and the deep dark of deepslate and
 * sculk above the bedrock. Ores score, gravel drops on his head, lava kills, and creepers come down
 * the tunnels to explode beside him. Torches light the dark and a water bucket turns lava nearby into
 * obsidian. The run ends when the time is up or his hearts are gone. Like rocketGame.ts this is the
 * whole game without a canvas: plain state stepped at a fixed rate, with events for MinecraftGame.tsx
 * to draw and sound. Rows count down from the sky (row 0); x counts columns from the left.
 */

export type Block =
  | 'air' | 'grass' | 'dirt' | 'gravel' | 'stone' | 'coal' | 'iron' | 'gold' | 'diamond' | 'lava' | 'water' | 'obsidian'
  | 'planks' | 'deepslate' | 'sculk' | 'spawner' | 'bedrock' | 'sand' | 'snow' | 'netherrack'

export const COLS = 12
/** Steve starts with his feet on the sky row, standing on the grass. */
export const START_X = 5
export const RUN_S = 180
export const HEARTS = 5
/** The deepest row; it and everything under it is bedrock, with a ragged edge just above. */
export const BEDROCK_Y = 120
/** From here down the stone is deepslate, with sculk. */
export const DEEP_Y = BEDROCK_Y - 25

/** Seconds to mine each block with a wooden pickaxe; bedrock never breaks, liquids and air are not mined. */
export const HARDNESS: Record<Block, number> = {
  air: 0, grass: 0.25, dirt: 0.25, gravel: 0.3, sand: 0.25, snow: 0.2, netherrack: 0.2, planks: 0.35, sculk: 0.25,
  stone: 0.55, coal: 0.65, iron: 0.8, gold: 0.9, diamond: 1.1, deepslate: 0.85, spawner: 1.5, obsidian: 3.5,
  lava: Infinity, water: Infinity, bedrock: Infinity,
}

/** What each ore (and a spawner) scores. */
export const ORE_POINTS: Partial<Record<Block, number>> = { coal: 1, iron: 3, gold: 5, diamond: 10, spawner: 15 }
export const CREEPER_POINTS = 5

export type PickId = 'wood' | 'stone' | 'iron' | 'diamond'
export type Ore = 'coal' | 'iron' | 'gold' | 'diamond'

/** Pickaxes from worst to best: how much faster each mines, and what it costs in the shop. Obsidian needs diamond. */
export const PICKS: ReadonlyArray<{ id: PickId; label: string; speed: number; cost: Partial<Record<Ore, number>> }> = [
  { id: 'wood', label: 'Wooden pickaxe', speed: 1, cost: {} },
  { id: 'stone', label: 'Stone pickaxe', speed: 1.35, cost: { coal: 8 } },
  { id: 'iron', label: 'Iron pickaxe', speed: 1.8, cost: { iron: 6 } },
  { id: 'diamond', label: 'Diamond pickaxe', speed: 2.5, cost: { diamond: 4 } },
]

/** What Steve takes down: his pickaxe, torches and water buckets. */
export interface Loadout {
  pick: PickId
  torches: number
  buckets: number
}

export const DEFAULT_LOADOUT: Loadout = { pick: 'wood', torches: 0, buckets: 0 }

/** Seconds per step along a tunnel, per row fallen (slower through water), between creeper steps, and its fuse. */
export const MOVE_S = 0.14
export const FALL_S = 0.07
const SWIM_FALL_S = 0.25
const CREEPER_MOVE_S = 0.45
export const FUSE_S = 1.5
/** Seconds a hit leaves Steve unhurtable, and between his punches at a creeper. */
const HURT_S = 0.6
const PUNCH_S = 0.3
const CREEPER_HP = 3
/** A fall of this many rows or more costs a heart, unless it ends in water. */
export const FALL_HURT_ROWS = 5
/** Below this row creepers come; the first one after FIRST_CREEPER_S, then about every CREEPER_S, sooner near a spawner. */
const CREEPER_ROW = 6
const FIRST_CREEPER_S = 15
const CREEPER_S = 22
const SPAWNER_REACH = 7
/** A water bucket turns lava this many blocks around Steve into obsidian. */
export const POUR_REACH = 2
/** A mining sound plays this often while a block is being mined. */
const DIG_TICK_S = 0.22
/** Rows generated ahead of Steve. */
const AHEAD = 24
/** Mineshafts run along every SHAFT_EVERY rows, from SHAFT_FROM down to above the deep dark. */
const SHAFT_FROM = 17
const SHAFT_EVERY = 26

export const STEP = 1 / 60

/**
 * What Steve is told to do: walk or mine left / right, mine down, climb a block (or, alone, mine the
 * block above his head), place a torch and pour a water bucket.
 */
export interface MineInput {
  dir: -1 | 0 | 1
  down: boolean
  up: boolean
  torch?: boolean
  pour?: boolean
}

export const NO_MINE_INPUT: MineInput = { dir: 0, down: false, up: false }

export interface Creeper {
  x: number
  y: number
  moveT: number
  /** Seconds left on the fuse, or -1 while unlit. */
  fuse: number
  hp: number
  fallT: number
}

export type MineEvent =
  | { type: 'step'; x: number; y: number }
  | { type: 'dig'; x: number; y: number; block: Block }
  | { type: 'mine'; x: number; y: number; block: Block }
  | { type: 'ore'; x: number; y: number; block: Block; points: number }
  | { type: 'land'; rows: number; water: boolean }
  | { type: 'splash' }
  | { type: 'gravel'; x: number; y: number }
  | { type: 'hurt'; hearts: number }
  | { type: 'creeper'; x: number; y: number }
  | { type: 'fuse'; x: number; y: number }
  | { type: 'punch'; x: number; y: number }
  | { type: 'kill'; x: number; y: number }
  | { type: 'boom'; x: number; y: number }
  | { type: 'torch'; x: number; y: number }
  | { type: 'pour'; count: number }
  | { type: 'deny' }
  | { type: 'over'; reason: OverReason }

export type OverReason = 'time' | 'lava' | 'creeper' | 'gravel' | 'fall'

export interface Mining {
  /** rows[y][x]; generated as Steve goes deeper. */
  rows: Block[][]
  /** Shapes the caves; drawn from the PRNG once, so a seed gives the same world. */
  seed: number
  /** Steve's feet; his head is the cell above. */
  x: number
  y: number
  /** -1 left, 1 right. */
  face: -1 | 1
  hearts: number
  time: number
  points: number
  /** The deepest row Steve has reached, counted below the grass. */
  depth: number
  ores: Partial<Record<Block, number>>
  creepers: Creeper[]
  kills: number
  pick: PickId
  torches: number
  buckets: number
  /** Torches placed, at the cell they light. */
  lights: Array<{ x: number; y: number }>
  /** The block being mined and how far along, in seconds. */
  target: { x: number; y: number } | null
  progress: number
  digT: number
  moveT: number
  fallT: number
  fallen: number
  /** Steve is in water. */
  wet: boolean
  gravelT: number
  hurtT: number
  punchT: number
  creeperT: number
  /** The torch and pour keys were already down, so holding them does not repeat. */
  held: { torch: boolean; pour: boolean }
  over: OverReason | null
  carry: number
  rnd: () => number
  events: MineEvent[]
}

const solid = (b: Block | undefined) => b !== undefined && b !== 'air' && b !== 'lava' && b !== 'water'
/** Steve and creepers can be in it: open air, water, lava (which kills), or the sky above the world. */
const passable = (b: Block | undefined) => !solid(b)
const liquid = (b: Block | undefined) => b === 'lava' || b === 'water'

/** A small integer hash to 0..1. */
function hash(seed: number, x: number, y: number) {
  let n = Math.imul(seed ^ Math.imul(x, 0x27d4eb2d) ^ Math.imul(y, 0x165667b1), 0x45d9f3b)
  n = Math.imul(n ^ (n >>> 16), 0x45d9f3b)
  return ((n ^ (n >>> 16)) >>> 0) / 4294967296
}

/** Smooth value noise, 0..1, from a lattice of hashed corners. */
export function noise(seed: number, x: number, y: number) {
  const x0 = Math.floor(x)
  const y0 = Math.floor(y)
  const fx = x - x0
  const fy = y - y0
  const sx = fx * fx * (3 - 2 * fx)
  const sy = fy * fy * (3 - 2 * fy)
  const top = hash(seed, x0, y0) + (hash(seed, x0 + 1, y0) - hash(seed, x0, y0)) * sx
  const bottom = hash(seed, x0, y0 + 1) + (hash(seed, x0 + 1, y0 + 1) - hash(seed, x0, y0 + 1)) * sx
  return top + (bottom - top) * sy
}

/** A mineshaft's run of columns along row `s` (its floor is the row below). */
function shaftSpan(seed: number, s: number) {
  const len = 5 + Math.floor(hash(seed, 71, s) * 6)
  const from = Math.floor(hash(seed, 73, s) * (COLS - len + 1))
  return [from, from + len] as const
}

/** The mineshaft row nearest `y`, if `y` is within its rows (beams, tunnel, floor). */
function shaftAt(y: number) {
  if (y < SHAFT_FROM - 2 || y >= DEEP_Y) return null
  const k = Math.round((y - SHAFT_FROM) / SHAFT_EVERY)
  const s = SHAFT_FROM + k * SHAFT_EVERY
  return k >= 0 && Math.abs(y - s) <= 2 && s < DEEP_Y - 2 ? s : null
}

function genCell(x: number, y: number, rnd: () => number, seed: number): Block {
  if (y >= BEDROCK_Y) return 'bedrock'
  if (y === 0) return 'air'
  if (y === 1) return 'grass'
  if (y <= 4) return rnd() < 0.06 ? 'gravel' : 'dirt'
  const r = rnd()
  if (y >= BEDROCK_Y - 3 && r < (y - (BEDROCK_Y - 4)) / 4) return 'bedrock'
  const deep = y >= DEEP_Y
  // An abandoned mineshaft: plank beams overhead, two rows of tunnel, a plank floor.
  const s = shaftAt(y)
  if (s !== null) {
    const [from, to] = shaftSpan(seed, s)
    if (x >= from && x < to) {
      if (y === s - 2) return (x - from) % 4 === 0 ? 'planks' : 'stone'
      if (y === s - 1 || y === s) return 'air'
      if (y === s + 1) return 'planks'
    }
  }
  // Caves, shaped by noise; deeper ones hold lava, shallower ones water.
  if (y >= 6 && noise(seed, x * 0.35, y * 0.22) > 0.66) {
    if (y >= 40 && noise(seed + 7, x * 0.2, y * 0.1) > 0.62) return 'lava'
    if (y >= 10 && y < 60 && noise(seed + 13, x * 0.3, y * 0.15) > 0.7) return 'water'
    if (y >= 25 && r < 0.006) return 'spawner'
    return 'air'
  }
  if (deep && noise(seed + 21, x * 0.4, y * 0.3) > 0.68) return 'sculk'
  // Deeper rows hold better ores.
  const depth = Math.min(1, (y - 5) / 60)
  let acc = 0
  const roll = (p: number) => r < (acc += p)
  if (y >= 20 && roll(0.008 + 0.02 * depth)) return 'diamond'
  if (y >= 14 && roll(0.02 + 0.015 * depth)) return 'gold'
  if (y >= 7 && roll(0.05)) return 'iron'
  if (roll(0.08)) return 'coal'
  if (!deep && roll(0.05)) return 'gravel'
  return deep ? 'deepslate' : 'stone'
}

/** Makes sure rows down to `y` exist. */
export function ensureRows(g: Mining, y: number) {
  while (g.rows.length <= y) {
    const row = g.rows.length
    g.rows.push(Array.from({ length: COLS }, (_, x) => genCell(x, row, g.rnd, g.seed)))
  }
}

export function blockAt(g: Mining, x: number, y: number): Block | undefined {
  if (x < 0 || x >= COLS || y < 0) return undefined
  ensureRows(g, y)
  return g.rows[y][x]
}

/** A cell is open for Steve or a creeper: inside the world and not solid; the sky above row 0 is open. */
function open(g: Mining, x: number, y: number) {
  if (x < 0 || x >= COLS) return false
  return y < 0 || passable(blockAt(g, x, y))
}

export function setBlock(g: Mining, x: number, y: number, b: Block) {
  ensureRows(g, y)
  g.rows[y][x] = b
}

export function createMining(rnd: () => number = Math.random, loadout: Loadout = DEFAULT_LOADOUT): Mining {
  const g: Mining = {
    rows: [], seed: Math.floor(rnd() * 2 ** 31), x: START_X, y: 0, face: 1, hearts: HEARTS, time: RUN_S, points: 0, depth: 0,
    ores: {}, creepers: [], kills: 0, pick: loadout.pick, torches: loadout.torches, buckets: loadout.buckets, lights: [],
    target: null, progress: 0, digT: 0, moveT: 0, fallT: 0, fallen: 0, wet: false, gravelT: 0, hurtT: 0, punchT: 0,
    creeperT: FIRST_CREEPER_S, held: { torch: false, pour: false }, over: null, carry: 0, rnd, events: [],
  }
  ensureRows(g, AHEAD)
  return g
}

/** The score: ore, spawner and creeper points plus a point for every row dug down. */
export const scoreOf = (g: Mining) => g.points + g.depth

/** Seconds this pickaxe takes for a block; Infinity when it cannot break it. */
export function mineTime(pick: PickId, b: Block) {
  if (b === 'obsidian' && pick !== 'diamond') return Infinity
  return HARDNESS[b] / PICKS.find(p => p.id === pick)!.speed
}

function end(g: Mining, reason: OverReason) {
  if (g.over) return
  g.over = reason
  g.events.push({ type: 'over', reason })
}

function hurt(g: Mining, n: number, reason: OverReason) {
  if (g.hurtT > 0 || g.over) return
  g.hearts = Math.max(0, g.hearts - n)
  g.hurtT = HURT_S
  g.events.push({ type: 'hurt', hearts: g.hearts })
  if (!g.hearts) end(g, reason)
}

function breakBlock(g: Mining, x: number, y: number) {
  const block = blockAt(g, x, y)!
  setBlock(g, x, y, 'air')
  g.lights = g.lights.filter(l => !(l.x === x && l.y === y))
  g.events.push({ type: 'mine', x, y, block })
  const points = ORE_POINTS[block]
  if (points) {
    g.points += points
    g.ores[block] = (g.ores[block] ?? 0) + 1
    g.events.push({ type: 'ore', x, y, block, points })
  }
}

/** Distance from a cell to the nearer of Steve's two cells. */
const reach = (g: Mining, x: number, y: number) =>
  Math.min(Math.max(Math.abs(g.x - x), Math.abs(g.y - y)), Math.max(Math.abs(g.x - x), Math.abs(g.y - 1 - y)))

function explode(g: Mining, c: Creeper) {
  g.events.push({ type: 'boom', x: c.x, y: c.y })
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      // A rough ball: the 5x5 square without its corners. Obsidian and bedrock stand up to it.
      if (Math.abs(dx) + Math.abs(dy) > 3) continue
      const b = blockAt(g, c.x + dx, c.y + dy)
      if (b && b !== 'bedrock' && b !== 'obsidian' && !liquid(b)) setBlock(g, c.x + dx, c.y + dy, 'air')
    }
  }
  const d = reach(g, c.x, c.y)
  if (d <= 1) hurt(g, 2, 'creeper')
  else if (d <= 2) hurt(g, 1, 'creeper')
}

/** Puts a creeper on Steve's row, 2 to 5 columns away on whichever side has a tunnel for it. */
function spawnCreeper(g: Mining): boolean {
  for (let d = 2; d <= 5; d++) {
    for (const side of g.rnd() < 0.5 ? [-1, 1] : [1, -1]) {
      const x = g.x + side * d
      if (blockAt(g, x, g.y) === 'air' && solid(blockAt(g, x, g.y + 1))) {
        g.creepers.push({ x, y: g.y, moveT: CREEPER_MOVE_S, fuse: -1, hp: CREEPER_HP, fallT: 0 })
        g.events.push({ type: 'creeper', x, y: g.y })
        return true
      }
    }
  }
  return false
}

/** A spawner within reach of Steve brings creepers sooner. */
function nearSpawner(g: Mining) {
  for (let y = Math.max(0, g.y - SPAWNER_REACH); y <= g.y + SPAWNER_REACH; y++) {
    if (g.rows[y]?.includes('spawner')) return true
  }
  return false
}

function stepCreepers(g: Mining) {
  if (g.y >= CREEPER_ROW && !g.creepers.length) {
    g.creeperT -= STEP * (nearSpawner(g) ? 2.5 : 1)
    if (g.creeperT <= 0) g.creeperT = spawnCreeper(g) ? CREEPER_S * (0.7 + g.rnd() * 0.6) : 2
  }
  for (let i = g.creepers.length - 1; i >= 0; i--) {
    const c = g.creepers[i]
    const below = blockAt(g, c.x, c.y + 1)
    if (!solid(below)) {
      c.fallT += STEP
      if (c.fallT >= FALL_S) {
        c.fallT = 0
        c.y++
        if (blockAt(g, c.x, c.y) === 'lava' || c.y >= BEDROCK_Y) g.creepers.splice(i, 1)
      }
      continue
    }
    if (c.fuse >= 0) {
      c.fuse -= STEP
      if (c.fuse <= 0) {
        g.creepers.splice(i, 1)
        explode(g, c)
      }
      continue
    }
    if (Math.abs(c.x - g.x) <= 1 && c.y >= g.y - 2 && c.y <= g.y + 1) {
      c.fuse = FUSE_S
      g.events.push({ type: 'fuse', x: c.x, y: c.y })
      continue
    }
    c.moveT -= STEP
    if (c.moveT > 0) continue
    c.moveT = CREEPER_MOVE_S
    const dir = Math.sign(g.x - c.x)
    if (dir && blockAt(g, c.x + dir, c.y) === 'air' && !g.creepers.some(o => o !== c && o.x === c.x + dir && o.y === c.y)) c.x += dir
  }
}

/** Gravel with nothing under it drops a row at a time; on Steve's head it hurts and breaks. */
function stepGravel(g: Mining) {
  g.gravelT += STEP
  if (g.gravelT < FALL_S) return
  g.gravelT = 0
  const top = Math.max(0, g.y - 12)
  for (let y = Math.min(g.rows.length - 2, g.y + AHEAD); y >= top; y--) {
    for (let x = 0; x < COLS; x++) {
      if (g.rows[y][x] !== 'gravel' || g.rows[y + 1][x] !== 'air') continue
      g.rows[y][x] = 'air'
      if (x === g.x && (y + 1 === g.y - 1 || y + 1 === g.y)) {
        g.events.push({ type: 'gravel', x, y: y + 1 })
        hurt(g, 1, 'gravel')
      } else g.rows[y + 1][x] = 'gravel'
    }
  }
}

/** Mines the block at (x, y) for one step; it breaks once it has had its mining time. */
function mineAt(g: Mining, x: number, y: number) {
  const block = blockAt(g, x, y)
  if (!block || !solid(block)) return
  const time = mineTime(g.pick, block)
  if (!g.target || g.target.x !== x || g.target.y !== y) {
    g.target = { x, y }
    g.progress = 0
    g.digT = 0
  }
  g.progress += STEP
  g.digT -= STEP
  if (g.digT <= 0) {
    g.digT = DIG_TICK_S
    g.events.push({ type: 'dig', x, y, block })
  }
  if (g.progress >= time) {
    breakBlock(g, x, y)
    g.target = null
    g.progress = 0
  }
}

/** Steve is in lava with his feet or his head. */
const inLava = (g: Mining) => blockAt(g, g.x, g.y) === 'lava' || blockAt(g, g.x, g.y - 1) === 'lava'

function moveTo(g: Mining, x: number, y: number) {
  g.x = x
  g.y = y
  g.moveT = MOVE_S
  g.events.push({ type: 'step', x, y })
  if (inLava(g)) end(g, 'lava')
}

/** Places a torch where Steve stands, or pours a water bucket over the lava near him; each once per press. */
function applyItems(g: Mining, input: MineInput) {
  if (input.torch && !g.held.torch) {
    if (g.torches > 0 && !g.lights.some(l => l.x === g.x && l.y === g.y - 1)) {
      g.torches--
      g.lights.push({ x: g.x, y: g.y - 1 })
      g.events.push({ type: 'torch', x: g.x, y: g.y - 1 })
    } else g.events.push({ type: 'deny' })
  }
  if (input.pour && !g.held.pour) {
    let count = 0
    if (g.buckets > 0) {
      for (let y = g.y - 1 - POUR_REACH; y <= g.y + POUR_REACH; y++) {
        for (let x = g.x - POUR_REACH; x <= g.x + POUR_REACH; x++) {
          if (blockAt(g, x, y) !== 'lava') continue
          setBlock(g, x, y, 'obsidian')
          count++
        }
      }
    }
    if (count) {
      g.buckets--
      g.events.push({ type: 'pour', count })
    } else g.events.push({ type: 'deny' })
  }
  g.held = { torch: !!input.torch, pour: !!input.pour }
}

/** One fixed step of the run. */
export function tick(g: Mining, input: MineInput) {
  if (g.over) return
  g.time = Math.max(0, g.time - STEP)
  g.hurtT = Math.max(0, g.hurtT - STEP)
  g.punchT = Math.max(0, g.punchT - STEP)
  g.moveT = Math.max(0, g.moveT - STEP)
  ensureRows(g, g.y + AHEAD)
  stepGravel(g)
  stepCreepers(g)
  if (g.over) return
  if (g.time <= 0) {
    end(g, 'time')
    return
  }
  applyItems(g, input)

  // In water Steve sinks slowly, and water breaks any fall.
  const wet = blockAt(g, g.x, g.y) === 'water' || blockAt(g, g.x, g.y - 1) === 'water'
  if (wet && !g.wet) g.events.push({ type: 'splash' })
  g.wet = wet

  // Nothing underfoot: fall a row at a time, and land.
  if (!solid(blockAt(g, g.x, g.y + 1))) {
    g.target = null
    g.fallT += STEP
    if (g.fallT >= (wet ? SWIM_FALL_S : FALL_S)) {
      g.fallT = 0
      g.y++
      g.fallen = wet ? 0 : g.fallen + 1
      g.depth = Math.max(g.depth, g.y - 1)
      if (inLava(g)) end(g, 'lava')
    }
    return
  }
  if (g.fallen) {
    g.events.push({ type: 'land', rows: g.fallen, water: wet })
    if (g.fallen >= FALL_HURT_ROWS && !wet) hurt(g, 1, 'fall')
    g.fallen = 0
    if (g.over) return
  }

  if (input.dir) g.face = input.dir
  if (input.down) {
    mineAt(g, g.x, g.y + 1)
    return
  }
  if (!input.dir) {
    // Up alone mines the block over his head.
    if (input.up && solid(blockAt(g, g.x, g.y - 2))) mineAt(g, g.x, g.y - 2)
    else g.target = null
    return
  }
  const nx = g.x + input.dir
  if (nx < 0 || nx >= COLS) return
  const creeper = g.creepers.find(c => c.x === nx && (c.y === g.y || c.y === g.y - 1))
  if (creeper) {
    // Punch it, and knock it back a column if there is room.
    if (g.punchT > 0) return
    g.punchT = PUNCH_S
    creeper.hp--
    g.events.push({ type: 'punch', x: nx, y: creeper.y })
    if (creeper.hp <= 0) {
      g.creepers.splice(g.creepers.indexOf(creeper), 1)
      g.kills++
      g.points += CREEPER_POINTS
      g.events.push({ type: 'kill', x: nx, y: creeper.y })
    } else {
      creeper.fuse = -1
      if (blockAt(g, nx + input.dir, creeper.y) === 'air') creeper.x += input.dir
    }
    return
  }
  const feet = blockAt(g, nx, g.y)
  const head = g.y - 1 < 0 ? undefined : blockAt(g, nx, g.y - 1)
  if (!solid(feet) && !solid(head)) {
    g.target = null
    if (!g.moveT) moveTo(g, nx, g.y)
    return
  }
  // A block ahead at his feet: with up held and room above, climb onto it.
  if (input.up && solid(feet) && open(g, nx, g.y - 1) && open(g, nx, g.y - 2) && open(g, g.x, g.y - 2)) {
    g.target = null
    if (!g.moveT) moveTo(g, nx, g.y - 1)
    return
  }
  // Otherwise mine it: his feet's block first, then the one at his head.
  mineAt(g, nx, solid(feet) ? g.y : g.y - 1)
}

/** Steps the run by `dt` seconds of real time in whole fixed steps; events collect across them. */
export function stepMining(g: Mining, input: MineInput, dt: number) {
  g.events = []
  g.carry = Math.min(g.carry + dt, 0.25)
  while (g.carry >= STEP && !g.over) {
    g.carry -= STEP
    tick(g, input)
  }
}
