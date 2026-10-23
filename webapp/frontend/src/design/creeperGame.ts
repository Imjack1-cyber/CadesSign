/**
 * Creeper Run, one of the Minecraft theme's minigames: Steve runs right on his own, faster and faster,
 * and the player jumps over what is on the ground, ducks what flies at head height and catches
 * emeralds. The run crosses biomes as the score rises: plains with creepers, a desert of cacti and
 * husks, snow where strays shoot more arrows, and the Nether with lava pits, blazes and ghast
 * fireballs. Now and then an elytra lets Steve glide (hold jump in the air) and a shield takes one
 * arrow, fireball or blaze for him. One touch of anything else ends the run. Plain state stepped at a
 * fixed rate, with events for MinecraftGame.tsx, like miningGame.ts. Units are px at scale 1: x grows
 * to the right and y is height above the ground.
 */
import type { Block } from './miningGame'

export type ObstacleKind =
  | 'creeper' | 'husk' | 'cactus' | 'hole' | 'lava' | 'arrow' | 'blaze' | 'fireball' | 'emerald' | 'elytra' | 'shield'

export interface Obstacle {
  kind: ObstacleKind
  /** Left edge, bottom (height above the ground), size. */
  x: number
  y: number
  w: number
  h: number
  /** Speed of its own on top of the run's (to the left), and falling speed (fireballs). */
  vx?: number
  vy?: number
  /** Where a blaze hovers about. */
  y0?: number
}

export type BiomeId = 'plains' | 'desert' | 'snow' | 'nether'

/** The biomes in order, from the score each one starts at, with their ground and sky. */
export const BIOMES: ReadonlyArray<{ id: BiomeId; label: string; from: number; ground: Block; under: Block; sky: [string, string] }> = [
  { id: 'plains', label: 'Plains', from: 0, ground: 'grass', under: 'dirt', sky: ['#7fb2ff', '#0c1030'] },
  { id: 'desert', label: 'Desert', from: 500, ground: 'sand', under: 'sand', sky: ['#a8ccff', '#14102a'] },
  { id: 'snow', label: 'Snowy Plains', from: 1000, ground: 'snow', under: 'dirt', sky: ['#c8dcf0', '#10162a'] },
  { id: 'nether', label: 'The Nether', from: 1500, ground: 'netherrack', under: 'netherrack', sky: ['#5a1410', '#2a0806'] },
]

/** Where Steve runs, and his box: half his width, his height standing and ducking. */
export const PLAYER_X = 90
export const PLAYER_HW = 11
export const PLAYER_H = 52
export const DUCK_H = 28
/** New obstacles come in here, past the right edge of any view. */
export const SPAWN_X = 1000

export const START_SPEED = 280
export const MAX_SPEED = 720
/** Speed gained per second of running. */
const SPEED_UP = 7
/** Arrows fly at the run speed plus this. */
export const ARROW_SPEED = 220
export const JUMP_V = 720
export const GRAVITY = 2200
/** Ducking in the air pulls Steve down this much harder. */
const DIVE = 2.5
/** Gliding: gravity is this share of normal, and holding jump keeps Steve at least this buoyant. */
const GLIDE_GRAVITY = 0.3
const GLIDE_LIFT = 140
export const GLIDE_S = 5
/** Distance runs this many px per point. */
export const PX_PER_POINT = 10
export const EMERALD_POINTS = 50
/** Seconds of run before holes and before arrows join in. */
const HOLES_AFTER_S = 6
const ARROWS_AFTER_S = 12
/** A day and a night, in seconds. */
export const DAY_S = 60

export const STEP = 1 / 120

export interface RunInput {
  jump: boolean
  duck: boolean
}

export const NO_RUN_INPUT: RunInput = { jump: false, duck: false }

export type RunEvent =
  | { type: 'jump' }
  | { type: 'land' }
  | { type: 'emerald'; x: number; y: number }
  | { type: 'milestone'; score: number }
  | { type: 'biome'; biome: BiomeId }
  | { type: 'powerup'; kind: 'elytra' | 'shield' }
  | { type: 'block'; kind: ObstacleKind; x: number; y: number }
  | { type: 'impact'; x: number }
  | { type: 'hit'; kind: ObstacleKind; x: number; y: number }

export interface Run {
  t: number
  speed: number
  /** Distance run, in px. */
  dist: number
  bonus: number
  emeralds: number
  y: number
  vy: number
  ducking: boolean
  /** The jump key was already down, so holding it does not jump again on landing. */
  held: boolean
  /** Seconds of elytra left, and shields carried (at most one). */
  glide: number
  shield: number
  biome: BiomeId
  obstacles: Obstacle[]
  /** Distance left until the next obstacle comes in. */
  gap: number
  over: ObstacleKind | null
  carry: number
  rnd: () => number
  events: RunEvent[]
}

export function createRun(rnd: () => number = Math.random): Run {
  return {
    t: 0, speed: START_SPEED, dist: 0, bonus: 0, emeralds: 0, y: 0, vy: 0, ducking: false, held: false, glide: 0, shield: 0,
    biome: 'plains', obstacles: [], gap: 500, over: null, carry: 0, rnd, events: [],
  }
}

export const scoreOfRun = (r: Run) => Math.floor(r.dist / PX_PER_POINT) + r.bonus

/** The biome for a score: the last one it has reached. */
export const biomeAt = (score: number) => [...BIOMES].reverse().find(b => score >= b.from)!

export const SHAPES: Record<ObstacleKind, Omit<Obstacle, 'x' | 'kind'>> = {
  creeper: { y: 0, w: 24, h: 50 },
  husk: { y: 0, w: 24, h: 54 },
  cactus: { y: 0, w: 22, h: 44 },
  hole: { y: 0, w: 56, h: 0 },
  lava: { y: 0, w: 64, h: 0 },
  arrow: { y: 34, w: 32, h: 6, vx: ARROW_SPEED },
  blaze: { y: 34, w: 28, h: 30, vx: 60 },
  fireball: { y: 190, w: 20, h: 20, vx: 140, vy: 110 },
  emerald: { y: 0, w: 16, h: 16 },
  elytra: { y: 80, w: 22, h: 22 },
  shield: { y: 16, w: 20, h: 22 },
}

/** What each biome sends: ground obstacles, and what flies once arrows have started. */
const SENDS: Record<BiomeId, { ground: ObstacleKind[]; air: ObstacleKind[] }> = {
  plains: { ground: ['creeper', 'creeper', 'cactus', 'hole'], air: ['arrow'] },
  desert: { ground: ['cactus', 'cactus', 'husk', 'hole'], air: ['arrow'] },
  snow: { ground: ['creeper', 'hole'], air: ['arrow', 'arrow', 'arrow'] },
  nether: { ground: ['lava', 'lava', 'hole'], air: ['blaze', 'fireball', 'blaze'] },
}

/** Things a shield takes for Steve. */
const BLOCKABLE = new Set<ObstacleKind>(['arrow', 'fireball', 'blaze'])
/** Things he collects rather than runs into. */
const PICKUPS = new Set<ObstacleKind>(['emerald', 'elytra', 'shield'])
/** Things on the ground Steve has to jump. */
export const GROUND = new Set<ObstacleKind>(['creeper', 'husk', 'cactus', 'hole', 'lava'])

function obstacle(kind: ObstacleKind, x = SPAWN_X): Obstacle {
  const o: Obstacle = { kind, x, ...SHAPES[kind] }
  if (kind === 'blaze') o.y0 = o.y
  return o
}

function spawn(r: Run) {
  const { rnd } = r
  const sends = SENDS[r.biome]
  const kinds = sends.ground.filter(k => (k !== 'hole' && k !== 'lava') || r.t >= HOLES_AFTER_S)
  if (r.t >= ARROWS_AFTER_S || r.biome === 'nether') kinds.push(...sends.air, ...sends.air)
  const kind = kinds[Math.floor(rnd() * kinds.length)]
  const o = obstacle(kind)
  // Tall cacti later on; a cactus pair now and then; blazes hover at different heights.
  if (kind === 'cactus' && rnd() < 0.3) o.h = 66
  if (kind === 'cactus' && rnd() < 0.25) o.w = 46
  if (kind === 'blaze') o.y = o.y0 = rnd() < 0.5 ? 34 : 62
  // A fireball falls so it reaches Steve at head height, whatever the speed.
  if (kind === 'fireball') o.vy = (o.y - 36) / ((SPAWN_X - PLAYER_X) / (r.speed + o.vx!))
  r.obstacles.push(o)
  // An emerald over the next gap, high (jump for it) or low; rarer, a power-up.
  const extra = rnd()
  if (extra < 0.22) r.obstacles.push({ ...obstacle('emerald', SPAWN_X + 160), y: rnd() < 0.5 ? 90 : 12 })
  else if (extra < 0.27) r.obstacles.push(obstacle('elytra', SPAWN_X + 180))
  else if (extra < 0.32 && !r.shield) r.obstacles.push(obstacle('shield', SPAWN_X + 180))
  // Room enough to land and jump again, more at speed.
  r.gap = (300 + rnd() * 320) * (r.speed / START_SPEED) ** 0.6
}

const height = (r: Run) => (r.ducking ? DUCK_H : PLAYER_H)

function touches(r: Run, o: Obstacle) {
  const left = PLAYER_X - PLAYER_HW
  const right = PLAYER_X + PLAYER_HW
  if (o.kind === 'hole' || o.kind === 'lava') return r.y <= 0 && PLAYER_X > o.x + 6 && PLAYER_X < o.x + o.w - 6
  // A little forgiveness at the edges of every box.
  return right - 3 > o.x && left + 3 < o.x + o.w && r.y + 2 < o.y + o.h && r.y + height(r) - 2 > o.y
}

/** One fixed step of the run. */
export function tickRun(r: Run, input: RunInput) {
  if (r.over) return
  const dt = STEP
  r.t += dt
  r.speed = Math.min(MAX_SPEED, r.speed + SPEED_UP * dt)
  const before = scoreOfRun(r)
  r.dist += r.speed * dt
  r.glide = Math.max(0, r.glide - dt)

  const grounded = r.y <= 0
  if (input.jump && !r.held && grounded) {
    r.vy = JUMP_V
    r.events.push({ type: 'jump' })
  }
  r.held = input.jump
  r.ducking = input.duck
  if (!grounded || r.vy > 0) {
    const gliding = r.glide > 0 && !input.duck
    r.vy -= GRAVITY * (input.duck ? DIVE : gliding ? GLIDE_GRAVITY : 1) * dt
    if (gliding && input.jump && r.vy < GLIDE_LIFT) r.vy = Math.max(r.vy, GLIDE_LIFT * 0.5)
    r.y += r.vy * dt
    if (r.y <= 0) {
      r.y = 0
      r.vy = 0
      r.events.push({ type: 'land' })
    }
  }

  r.gap -= r.speed * dt
  if (r.gap <= 0) spawn(r)
  for (let i = r.obstacles.length - 1; i >= 0; i--) {
    const o = r.obstacles[i]
    o.x -= (r.speed + (o.vx ?? 0)) * dt
    if (o.vy) o.y -= o.vy * dt
    if (o.kind === 'blaze') o.y = o.y0! + Math.sin(r.t * 4 + o.x * 0.01) * 6
    if (o.kind === 'fireball' && o.y <= 0) {
      r.obstacles.splice(i, 1)
      r.events.push({ type: 'impact', x: o.x })
      continue
    }
    if (o.x + o.w < -100) {
      r.obstacles.splice(i, 1)
      continue
    }
    if (!touches(r, o)) continue
    if (PICKUPS.has(o.kind)) {
      r.obstacles.splice(i, 1)
      if (o.kind === 'emerald') {
        r.bonus += EMERALD_POINTS
        r.emeralds++
        r.events.push({ type: 'emerald', x: o.x, y: o.y })
      } else {
        const kind = o.kind === 'elytra' ? 'elytra' : 'shield'
        if (kind === 'elytra') r.glide = GLIDE_S
        else r.shield = 1
        r.events.push({ type: 'powerup', kind })
      }
      continue
    }
    if (r.shield && BLOCKABLE.has(o.kind)) {
      r.obstacles.splice(i, 1)
      r.shield = 0
      r.events.push({ type: 'block', kind: o.kind, x: o.x, y: o.y })
      continue
    }
    r.over = o.kind
    r.events.push({ type: 'hit', kind: o.kind, x: o.x, y: o.y })
    return
  }
  const after = scoreOfRun(r)
  if (Math.floor(after / 100) > Math.floor(before / 100)) r.events.push({ type: 'milestone', score: Math.floor(after / 100) * 100 })
  const biome = biomeAt(after).id
  if (biome !== r.biome) {
    r.biome = biome
    r.events.push({ type: 'biome', biome })
  }
}

/** Steps the run by `dt` seconds of real time in whole fixed steps; events collect across them. */
export function stepRun(r: Run, input: RunInput, dt: number) {
  r.events = []
  r.carry = Math.min(r.carry + dt, 0.25)
  while (r.carry >= STEP && !r.over) {
    r.carry -= STEP
    tickRun(r, input)
  }
}

/**
 * A player for the run behind the menus: jumps what is on the ground ahead and ducks what flies at
 * head height. It plays well, not perfectly.
 */
export function autoRunInput(r: Run): RunInput {
  let jump = false
  let duck = false
  for (const o of r.obstacles) {
    const ahead = o.x - (PLAYER_X + PLAYER_HW)
    if (GROUND.has(o.kind)) {
      if (ahead > 0 && ahead < 26 + r.speed * 0.08) jump = true
    } else if (!PICKUPS.has(o.kind) && o.y >= DUCK_H - 2 && o.y < PLAYER_H && ahead > -o.w && ahead < 140) duck = true
  }
  return { jump: jump && !r.held, duck: duck && !jump }
}
