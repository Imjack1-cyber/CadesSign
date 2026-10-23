/**
 * Minecraft: a blocky world over a grass strip. Square clouds drift by under a twenty-minute day: the
 * sky darkens, stars come out, and the farm animals give way to zombies and skeletons. Now and then it
 * rains (snows in winter), and an error brings thunder. At Wild a small Steve walks the grass after the
 * mouse and a pig, a chicken or a sheep wanders about, fleeing a fast mouse; a click on one oinks,
 * drops an item or dyes its wool. A click on bare page mines a block there, which drops an item that
 * comes to the mouse; picking it up gives XP orbs that fly into the XP bar. Typing kicks up crumbs and
 * Enter places a block. A request is a turning block being mined above the XP bar, ore after ore up to
 * one that fits the operation (stone for a basic signature, diamond for an archival one); a success
 * showers XP, an error brings a creeper that hisses and explodes, a warning is an arrow thunking into
 * the result. With sound on, a sparse piano plays. While a minigame is open the world goes quiet.
 * Like the other presets it keeps its state in plain arrays so tests can step it without a canvas.
 */
import type { Block } from '../miningGame'
import { burstBits, drawBits, scaleCount, spawnBit, stepBits } from './bits'
import type { BusyInfo, Control, Preset, State, World } from './presets'
import type { Sound } from './sound'

const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

/** Where the grass strip starts, as a share of the height; matches .decor-grass in themes.css. */
const GRASS = 0.95
/** Where the XP bar sits, px above the bottom edge; matches .mc-hud in themes.css. */
const XP_BAR_UP = 46
/** Blocks mined from the page snap to a grid this many px wide. */
const CELL = 32
/** Seconds a block takes to break under a click, and per block while a request runs. */
const CLICK_BREAK_S = 0.35
const BUSY_BREAK_S = 1.2
/** The ores a running request works through, one after another, up to the one that fits it. */
export const BUSY_ORES: Block[] = ['stone', 'coal', 'iron', 'gold', 'diamond']
/** The best ore for each signature level, as an index into BUSY_ORES; verifying digs to iron. */
const LEVEL_ORE: Record<string, number> = { B: 0, T: 1, LT: 3, LTA: 4 }
const VERIFY_ORE = 2
/** Seconds a creeper's fuse burns after an error, and an item lies about before it despawns. */
export const FUSE_S = 1.2
export const ITEM_S = 12
/** Items come to a mouse this close, and are picked up this close. */
const MAGNET_PX = 80
const PICKUP_PX = 16
const ORB_S = 0.7
const MAX_ITEMS = 20
const MAX_ORBS = 60
const MAX_DROPS = 400
/** A whole day, and where in it night falls and ends (as shares of the day; 0 is sunrise). */
export const DAY_S = 1200
export const NIGHT_FROM = 0.55
export const NIGHT_TO = 0.95
/** Where a new session starts: early morning. */
const START_PHASE = 0.05
/** Rain comes about this often at Wild, for about this long; an error's storm lasts STORM_S. */
const RAIN_EVERY_S: [number, number] = [240, 480]
const RAIN_FOR_S: [number, number] = [40, 80]
export const STORM_S = 20
/** Steve's walking and running speeds on the grass, px/s, and how far ahead of the mouse he stops. */
const STEVE_WALK = 110
const STEVE_RUN = 230
const STEVE_H = 40
/** A fast mouse this close scares a mob into running off for FLEE_S. */
const SCARE_PX = 140
const SCARE_SPEED = 600
const FLEE_S = 1.5
/** What a resize keeps, so a request, the time of day, the weather and the quiet of an open game carry on. */
const KEEP = ['busy', 'quiet', 'nextMob', 'ore', 'oreMax', 'clock', 'rain', 'nextRain', 'snowy'] as const

/** Base, dark and light shades of each block's texture, and the fleck colour of an ore. */
export const BLOCK_COLORS: Record<Block, { base: string; dark: string; light: string; fleck?: string }> = {
  air: { base: 'transparent', dark: 'transparent', light: 'transparent' },
  grass: { base: '#866043', dark: '#6b4a30', light: '#9a7352', fleck: '#5d9c32' },
  dirt: { base: '#866043', dark: '#6b4a30', light: '#9a7352' },
  gravel: { base: '#857f7e', dark: '#615b5a', light: '#a49d9c' },
  sand: { base: '#dbd3a0', dark: '#c9bf86', light: '#e8e0b2' },
  snow: { base: '#f0fbfb', dark: '#d6e6ea', light: '#ffffff' },
  netherrack: { base: '#6f3533', dark: '#561f1e', light: '#8a4442' },
  stone: { base: '#7d7d7d', dark: '#686868', light: '#8f8f8f' },
  coal: { base: '#7d7d7d', dark: '#686868', light: '#8f8f8f', fleck: '#262626' },
  iron: { base: '#7d7d7d', dark: '#686868', light: '#8f8f8f', fleck: '#d8af93' },
  gold: { base: '#7d7d7d', dark: '#686868', light: '#8f8f8f', fleck: '#fcee4b' },
  diamond: { base: '#7d7d7d', dark: '#686868', light: '#8f8f8f', fleck: '#5decf5' },
  deepslate: { base: '#4d4d50', dark: '#3a3a3d', light: '#5e5e62' },
  sculk: { base: '#0d1e24', dark: '#081316', light: '#123038', fleck: '#2fd6d6' },
  planks: { base: '#a2834f', dark: '#7a5f36', light: '#b8945f' },
  spawner: { base: '#1b2430', dark: '#0d1219', light: '#36475c', fleck: '#e8792b' },
  obsidian: { base: '#14101f', dark: '#0b0814', light: '#3b2a5a' },
  lava: { base: '#d4500b', dark: '#b33a06', light: '#fc9b2b', fleck: '#ffd64a' },
  water: { base: 'rgba(48,96,220,0.75)', dark: 'rgba(36,72,190,0.75)', light: 'rgba(80,130,240,0.75)' },
  bedrock: { base: '#555', dark: '#2b2b2b', light: '#7a7a7a' },
}

/** Which material a block sounds like when mined. */
export const MATERIAL: Record<Block, 'stone' | 'dirt' | 'gravel'> = {
  air: 'dirt', grass: 'dirt', dirt: 'dirt', sand: 'dirt', snow: 'dirt', sculk: 'dirt', planks: 'dirt', gravel: 'gravel',
  stone: 'stone', coal: 'stone', iron: 'stone', gold: 'stone', diamond: 'stone', deepslate: 'stone', netherrack: 'stone',
  spawner: 'stone', obsidian: 'stone', lava: 'stone', water: 'dirt', bedrock: 'stone',
}

/** A small integer hash to 0..1, so textures look the same every frame. */
const hash = (n: number) => {
  n = Math.imul(n ^ (n >>> 16), 0x45d9f3b)
  n = Math.imul(n ^ (n >>> 16), 0x45d9f3b)
  return ((n ^ (n >>> 16)) >>> 0) / 4294967296
}

const TEX = 4

/**
 * A block `size` px square with its top-left at (x, y): a 4x4 pixel texture in its shades, ore flecks,
 * a grass top, plank seams or a spawner's cage. `seed` varies the pattern from block to block; `crack`
 * (0..1) draws the breaking stages.
 */
export function drawBlock(ctx: CanvasRenderingContext2D, x: number, y: number, size: number, kind: Block, seed = 0, crack = 0) {
  if (kind === 'air') return
  const c = BLOCK_COLORS[kind]
  const px = size / TEX
  for (let j = 0; j < TEX; j++) {
    for (let i = 0; i < TEX; i++) {
      const r = hash(seed * 31 + j * TEX + i)
      let color = r < 0.3 ? c.dark : r > 0.75 ? c.light : c.base
      if (c.fleck && kind !== 'grass' && r > 0.45 && r < 0.62) color = c.fleck
      if (kind === 'grass' && j === 0) color = r < 0.4 ? '#4c8a26' : '#5d9c32'
      if (kind === 'planks' && j % 2 === 1 && i === (j === 1 ? 3 : 1)) color = c.dark
      ctx.fillStyle = color
      // Overlap by a hair so no seams show between the pixels when scaled.
      ctx.fillRect(x + i * px, y + j * px, px + 0.5, px + 0.5)
    }
  }
  if (kind === 'grass') {
    ctx.fillStyle = '#5d9c32'
    for (let i = 0; i < TEX; i++) if (hash(seed + i * 7) > 0.5) ctx.fillRect(x + i * px, y + px, px + 0.5, px * 0.5)
  }
  if (kind === 'planks') {
    ctx.fillStyle = c.dark
    ctx.fillRect(x, y + size / 2 - px * 0.15, size, px * 0.3)
  }
  if (kind === 'spawner') {
    // The cage: dark bars over a glowing ember.
    ctx.strokeStyle = '#0a0d12'
    ctx.lineWidth = Math.max(1, size / 12)
    ctx.beginPath()
    for (let k = 1; k < 4; k++) {
      ctx.moveTo(x + (k * size) / 4, y)
      ctx.lineTo(x + (k * size) / 4, y + size)
      ctx.moveTo(x, y + (k * size) / 4)
      ctx.lineTo(x + size, y + (k * size) / 4)
    }
    ctx.stroke()
  }
  if (kind === 'water') return
  ctx.strokeStyle = 'rgba(0,0,0,0.25)'
  ctx.lineWidth = 1
  ctx.strokeRect(x + 0.5, y + 0.5, size - 1, size - 1)
  if (crack > 0) drawCracks(ctx, x, y, size, crack)
}

/** The ten breaking stages, as more and more dark crack lines across the block. */
function drawCracks(ctx: CanvasRenderingContext2D, x: number, y: number, size: number, crack: number) {
  const stages = Math.min(10, Math.floor(crack * 10) + 1)
  ctx.save()
  ctx.strokeStyle = 'rgba(0,0,0,0.65)'
  ctx.lineWidth = Math.max(1, size / 16)
  ctx.beginPath()
  for (let k = 0; k < stages; k++) {
    // Each stage adds a jagged line from near the centre outwards.
    const a = hash(k * 13 + 5) * Math.PI * 2
    const len = size * (0.2 + 0.3 * hash(k * 17 + 3))
    const cx = x + size / 2 + (hash(k * 7) - 0.5) * size * 0.2
    const cy = y + size / 2 + (hash(k * 11) - 0.5) * size * 0.2
    ctx.moveTo(cx, cy)
    ctx.lineTo(cx + Math.cos(a) * len * 0.5 + size * 0.05, cy + Math.sin(a) * len * 0.5)
    ctx.lineTo(clamp(cx + Math.cos(a) * len, x, x + size), clamp(cy + Math.sin(a) * len, y, y + size))
  }
  ctx.stroke()
  ctx.restore()
}

type Vec = [number, number, number]

/** The cube's faces: a corner, the two edges from it (in -1..1 cube space) and the outward normal. */
const FACES: ReadonlyArray<{ o: Vec; u: Vec; v: Vec; n: Vec; shade: number }> = [
  { o: [-1, 1, -1], u: [2, 0, 0], v: [0, 0, 2], n: [0, 1, 0], shade: 0 },
  { o: [-1, 1, 1], u: [2, 0, 0], v: [0, -2, 0], n: [0, 0, 1], shade: 0.18 },
  { o: [1, 1, -1], u: [-2, 0, 0], v: [0, -2, 0], n: [0, 0, -1], shade: 0.18 },
  { o: [1, 1, 1], u: [0, 0, -2], v: [0, -2, 0], n: [1, 0, 0], shade: 0.32 },
  { o: [-1, 1, -1], u: [0, 0, 2], v: [0, -2, 0], n: [-1, 0, 0], shade: 0.32 },
]

/** Texture pixels per face; the face's drawing is scaled from this. */
const FACE_PX = 16
/** How far the camera looks down on the cube. */
const TILT = 0.5

/**
 * A block as a cube centred on (cx, cy), `size` px along an edge, turned `angle` radians about its
 * upright axis and seen a little from above: the visible faces, each textured and cracked like
 * drawBlock and shaded by how it faces the light.
 */
export function drawCube(ctx: CanvasRenderingContext2D, cx: number, cy: number, size: number, kind: Block, seed = 0, crack = 0, angle = 0) {
  const half = size / 2
  const ca = Math.cos(angle)
  const sa = Math.sin(angle)
  const ct = Math.cos(TILT)
  const st = Math.sin(TILT)
  const project = ([x, y, z]: Vec): [number, number] => {
    const rx = x * ca - z * sa
    const rz = x * sa + z * ca
    return [cx + rx * half, cy + (-y * ct + rz * st) * half]
  }
  for (const f of FACES) {
    // Only faces turned towards the viewer: the top always, a side while its normal points our way.
    const facing = f.n[1] ? 1 : f.n[0] * sa + f.n[2] * ca
    if (facing <= 0.001) continue
    const p0 = project(f.o)
    const pu = project([f.o[0] + f.u[0], f.o[1] + f.u[1], f.o[2] + f.u[2]])
    const pv = project([f.o[0] + f.v[0], f.o[1] + f.v[1], f.o[2] + f.v[2]])
    ctx.save()
    ctx.transform((pu[0] - p0[0]) / FACE_PX, (pu[1] - p0[1]) / FACE_PX, (pv[0] - p0[0]) / FACE_PX, (pv[1] - p0[1]) / FACE_PX, p0[0], p0[1])
    drawBlock(ctx, 0, 0, FACE_PX, kind === 'grass' && f.n[1] ? 'grass' : kind, seed + f.shade * 100, crack)
    const shade = f.shade + (f.n[1] ? 0 : 0.15 * (1 - facing))
    if (shade > 0) {
      ctx.fillStyle = `rgba(0,0,0,${shade})`
      ctx.fillRect(0, 0, FACE_PX, FACE_PX)
    }
    ctx.restore()
  }
}

/** Paints a grid of pixels, each `u` px, from rows of characters mapped to colours ('.' is clear). */
function sprite(ctx: CanvasRenderingContext2D, x: number, y: number, u: number, rows: readonly string[], colors: Record<string, string>) {
  rows.forEach((row, j) => {
    for (let i = 0; i < row.length; i++) {
      const color = colors[row[i]]
      if (!color) continue
      ctx.fillStyle = color
      ctx.fillRect(x + i * u, y + j * u, u + 0.4, u + 0.4)
    }
  })
}

const CREEPER = [
  'gGlgGgLg', 'gLgglgGg', 'gkkggkkg', 'gkkggkkg', 'lggkkggL', 'ggkkkkgg', 'gLkkkkgl', 'ggkglkgg',
  'lgGgglgG', 'gglgGggl', 'GgglggLg', 'glgGgglg', 'gGgglgGg', 'lgglgGgg', 'gglGggLg', 'GglggglG',
  'gGlgglgg', 'glgGgLgg', 'gglggglG', 'lgGgglgg',
  'gGl..lgG', 'glg..gLg', 'Ggl..lgG', 'gLg..gGl', 'ggg..ggg', 'kkk..kkk',
]
const CREEPER_COLORS = { g: '#5aa53a', G: '#3f8a2a', l: '#76c34a', L: '#a3dc78', k: '#0d0d0d' }

/** A creeper `size` px tall standing on (x, bottom); `flash` (0..1) whitens it as the fuse burns. */
export function drawCreeper(ctx: CanvasRenderingContext2D, x: number, bottom: number, size: number, flash = 0) {
  const u = size / CREEPER.length
  const left = x - u * 4
  const top = bottom - size
  sprite(ctx, left, top, u, CREEPER, CREEPER_COLORS)
  if (flash > 0) {
    ctx.save()
    ctx.globalAlpha = clamp(flash, 0, 1) * 0.85
    ctx.fillStyle = '#fff'
    ctx.fillRect(left, top, u * 8, u * 20)
    ctx.fillRect(left, top + u * 20, u * 3, u * 6)
    ctx.fillRect(left + u * 5, top + u * 20, u * 3, u * 6)
    ctx.restore()
  }
}

const STEVE_HEAD = ['hhhhhhhh', 'hhhhhhhh', 'hsssssss', 'ssssssss', 'swewssws', 'sssnnsss', 'ssmmmmss', 'ssssssss']
const STEVE_COLORS = { h: '#3b2a1a', s: '#c69c6d', w: '#fff', e: '#493c8f', n: '#9c6e4b', m: '#7a4b33', t: '#00a8a8', T: '#008c8c', p: '#3b3fa8', P: '#2d3087', b: '#6b6b6b' }

export interface StevePose {
  /** Radians of stride: swings his legs and free arm as he walks. */
  stride?: number
  /** 0..1 through a swing of the pickaxe; 0 holds no pickaxe. */
  swing?: number
  /** Sneaking: bent forward at the hips, knees bent, head low. */
  sneak?: boolean
  /** Holding a torch in the other hand. */
  torch?: boolean
  /** Hurt: tinted red. */
  hurt?: boolean
}

/** Steve, `size` px tall standing (less sneaking), on (x, bottom), facing `face`. */
export function drawSteve(ctx: CanvasRenderingContext2D, x: number, bottom: number, size: number, face: number, pose: StevePose = {}) {
  const { stride = 0, swing = 0, sneak = false, torch = false, hurt = false } = pose
  const u = size / 32
  ctx.save()
  // Hurt: everything drawn red for a moment, as in the game.
  if (hurt) ctx.filter = 'sepia(1) saturate(6) hue-rotate(-40deg) brightness(0.9)'
  ctx.translate(x, bottom)
  ctx.scale(face < 0 ? -1 : 1, 1)
  // Legs, swinging opposite each other; sneaking bends them and lowers the hips.
  const legLen = sneak ? 9 : 12
  const hip = -u * legLen
  for (const [k, color] of [[1, STEVE_COLORS.P], [-1, STEVE_COLORS.p]] as const) {
    ctx.save()
    ctx.translate(0, hip)
    ctx.rotate(Math.sin(stride) * (sneak ? 0.35 : 0.6) * k + (sneak ? 0.35 : 0))
    ctx.fillStyle = color
    ctx.fillRect(-u * 2, 0, u * 4, u * (legLen - 2))
    ctx.fillStyle = STEVE_COLORS.b
    ctx.fillRect(-u * 2, u * (legLen - 2), u * 4, u * 2)
    ctx.restore()
  }
  // From the hips up the body leans forward when sneaking.
  ctx.translate(0, hip)
  if (sneak) ctx.rotate(0.5)
  ctx.fillStyle = STEVE_COLORS.t
  ctx.fillRect(-u * 2, -u * 12, u * 4, u * 12)
  ctx.fillStyle = STEVE_COLORS.T
  ctx.fillRect(-u * 2, -u * 2, u * 4, u * 2)
  ctx.save()
  if (sneak) ctx.rotate(-0.35)
  sprite(ctx, -u * 4, -u * 20, u, STEVE_HEAD, STEVE_COLORS)
  ctx.restore()
  // The far arm holds a torch, or swings with the stride.
  ctx.save()
  ctx.translate(0, -u * 11)
  ctx.rotate(torch ? -0.9 : Math.sin(stride) * 0.6)
  ctx.fillStyle = STEVE_COLORS.T
  ctx.fillRect(-u * 2, -u, u * 4, u * 4)
  ctx.fillStyle = '#b08a5e'
  ctx.fillRect(-u * 2, u * 3, u * 4, u * 8)
  if (torch) drawTorch(ctx, u * 0.5, u * 10, u * 10)
  ctx.restore()
  // The near arm, swinging the pickaxe when mining, else with the stride.
  ctx.save()
  ctx.translate(0, -u * 11)
  ctx.rotate(swing ? -1.6 * Math.sin(swing * Math.PI) - 0.2 : -Math.sin(stride) * 0.6)
  ctx.fillStyle = STEVE_COLORS.t
  ctx.fillRect(-u * 2, -u, u * 4, u * 4)
  ctx.fillStyle = STEVE_COLORS.s
  ctx.fillRect(-u * 2, u * 3, u * 4, u * 8)
  if (swing) {
    // A pickaxe: wooden handle and an iron head.
    ctx.fillStyle = '#8a6136'
    ctx.fillRect(-u * 0.5, u * 8, u * 1.5, u * 9)
    ctx.fillStyle = '#d8d8d8'
    ctx.fillRect(-u * 4, u * 15, u * 9, u * 2)
    ctx.fillRect(-u * 5, u * 16, u * 2, u * 2)
    ctx.fillRect(u * 4, u * 16, u * 2, u * 2)
  }
  ctx.restore()
  ctx.restore()
}

/** A torch `size` px tall with its foot at (x, y) in the current transform: a stick and a flame. */
export function drawTorch(ctx: CanvasRenderingContext2D, x: number, y: number, size: number) {
  const u = size / 10
  ctx.fillStyle = '#8a6136'
  ctx.fillRect(x - u, y - u * 7, u * 2, u * 7)
  ctx.fillStyle = '#ffd64a'
  ctx.fillRect(x - u, y - u * 9, u * 2, u * 2)
  ctx.fillStyle = '#fff6c0'
  ctx.fillRect(x - u * 0.5, y - u * 9, u, u)
}

export type MobKind = 0 | 1 | 2 | 3 | 4
/** Day mobs (pig, chicken, sheep) and night mobs (zombie, skeleton). */
const DAY_MOBS: MobKind[] = [0, 1, 2]
const NIGHT_MOBS: MobKind[] = [3, 4]
/** Wool colours a sheep goes through when clicked. */
export const WOOL = ['#ececec', '#e8792b', '#c25fd3', '#5a9be0', '#f1d63a', '#6cc04a', '#e98aa8', '#4b4b4b']

/** A mob, `size` px tall, standing on (x, bottom), facing `dir`. */
function drawMob(ctx: CanvasRenderingContext2D, kind: MobKind, x: number, bottom: number, size: number, dir: number, stride: number, wool = 0) {
  ctx.save()
  ctx.translate(x, bottom)
  ctx.scale(dir < 0 ? -1 : 1, 1)
  const u = size / 16
  const legs = (color: string, at: number[], h: number) => {
    ctx.fillStyle = color
    at.forEach((lx, i) => ctx.fillRect(lx * u, -h * u + (i % 2 ? Math.sin(stride) : -Math.sin(stride)) * u * 0.6, u * 2, h * u))
  }
  switch (kind) {
    case 0: // Pig
      legs('#e09090', [-7, -3, 2, 5], 4)
      ctx.fillStyle = '#f0a5a2'
      ctx.fillRect(-8 * u, -11 * u, 16 * u, 7 * u)
      ctx.fillRect(4 * u, -14 * u, 7 * u, 7 * u)
      ctx.fillStyle = '#e07f7f'
      ctx.fillRect(10 * u, -11 * u, 2 * u, 3 * u)
      ctx.fillStyle = '#111'
      ctx.fillRect(8 * u, -13 * u, u, u)
      break
    case 1: // Chicken
      legs('#e6a02a', [-1, 1], 4)
      ctx.fillStyle = '#fff'
      ctx.fillRect(-5 * u, -10 * u, 9 * u, 6 * u)
      ctx.fillRect(1 * u, -15 * u, 4 * u, 6 * u)
      ctx.fillStyle = '#e6a02a'
      ctx.fillRect(5 * u, -13 * u, 2 * u, u * 1.5)
      ctx.fillStyle = '#d33'
      ctx.fillRect(4 * u, -11.5 * u, u, 2 * u)
      ctx.fillStyle = '#111'
      ctx.fillRect(3 * u, -14 * u, u, u)
      break
    case 2: // Sheep
      legs('#d8c4b0', [-6, -3, 2, 5], 5)
      ctx.fillStyle = WOOL[wool % WOOL.length]
      ctx.fillRect(-8 * u, -13 * u, 16 * u, 8 * u)
      ctx.fillStyle = '#d8c4b0'
      ctx.fillRect(6 * u, -15 * u, 5 * u, 5 * u)
      ctx.fillStyle = '#111'
      ctx.fillRect(9 * u, -14 * u, u, u)
      break
    case 3: // Zombie: Steve's shape in green and torn blue, arms out front.
      legs('#3b3fa8', [-2, 0], 9)
      ctx.fillStyle = '#00a8a8'
      ctx.fillRect(-2 * u, -18 * u, 4 * u, 9 * u)
      ctx.fillStyle = '#5b8a3c'
      ctx.fillRect(-3 * u, -24 * u, 6 * u, 6 * u)
      ctx.fillRect(1 * u, -17 * u, 8 * u, 2 * u)
      ctx.fillStyle = '#111'
      ctx.fillRect(1 * u, -22 * u, u, u)
      break
    default: // Skeleton: thin grey bones and a bow.
      legs('#c8c8c8', [-1, 1], 9)
      ctx.fillStyle = '#c8c8c8'
      ctx.fillRect(-1 * u, -18 * u, 2 * u, 9 * u)
      ctx.fillRect(-3 * u, -24 * u, 6 * u, 6 * u)
      ctx.fillStyle = '#333'
      ctx.fillRect(1 * u, -22 * u, u, u)
      ctx.fillRect(-1 * u, -16 * u, 2 * u, u)
      ctx.strokeStyle = '#8a6136'
      ctx.lineWidth = u
      ctx.beginPath()
      ctx.arc(4 * u, -15 * u, 4 * u, -1.2, 1.2)
      ctx.stroke()
  }
  ctx.restore()
}

/** Items that drop: the busy ores, and what the mobs leave. */
export const ITEM_KINDS = [...BUSY_ORES, 'porkchop', 'egg', 'bone', 'flesh'] as const
type ItemKind = (typeof ITEM_KINDS)[number]

function drawItem(ctx: CanvasRenderingContext2D, kind: ItemKind, size: number, seed: number) {
  switch (kind) {
    case 'porkchop':
      ctx.fillStyle = '#f0a5a2'
      ctx.fillRect(-size / 2, -size / 3, size, (size * 2) / 3)
      ctx.fillStyle = '#d97a7a'
      ctx.fillRect(-size / 4, -size / 6, size / 2, size / 3)
      return
    case 'egg':
      ctx.fillStyle = '#efe2c4'
      ctx.beginPath()
      ctx.ellipse(0, 0, size / 3, size / 2.2, 0, 0, Math.PI * 2)
      ctx.fill()
      return
    case 'bone':
      ctx.fillStyle = '#e8e8e0'
      ctx.fillRect(-size / 2, -size / 8, size, size / 4)
      ctx.fillRect(-size / 2, -size / 4, size / 4, size / 2)
      ctx.fillRect(size / 4, -size / 4, size / 4, size / 2)
      return
    case 'flesh':
      ctx.fillStyle = '#9c4a3a'
      ctx.fillRect(-size / 2, -size / 3, size, (size * 2) / 3)
      ctx.fillStyle = '#5b8a3c'
      ctx.fillRect(-size / 4, -size / 3, size / 3, size / 3)
      return
    default:
      drawBlock(ctx, -size / 2, -size / 2, size, kind, seed)
  }
}

/** What a press sounds like, by control. Back and Next stay quiet: the step they cause sounds. */
const PRESS: Record<Control, ((sound: Sound) => void) | null> = {
  button: s => s.uiclick(), choice: s => s.uiclick(), toggle: s => s.uiclick(), nav: s => s.uiclick(),
  field: s => s.step(), upload: s => s.chest(true), download: s => s.pickup(), discard: s => s.blockbreak('gravel'),
  back: null, forward: null, disabled: s => s.hmm(true),
}

type Thing = Record<string, number>

interface Overworld extends State {
  mob: Thing
  steve: Thing
  /** Blocks being mined: from clicks, and the one a running request works on. */
  blocks: Thing[]
  items: Thing[]
  orbs: Thing[]
  arrows: Thing[]
  drops: Thing[]
  stars: Thing[]
  creeper: Thing
}

const floorOf = (world: World) => world.h * GRASS
const barOf = (world: World) => ({ x: world.w / 2, y: world.h - XP_BAR_UP })
const busyAt = (world: World) => ({ x: world.w / 2, y: world.h - XP_BAR_UP - 90 })
const oreOf = (s: State) => BUSY_ORES[Math.min(s.ore as number, s.oreMax as number)]
const phaseOf = (s: State) => ((s.clock as number) % DAY_S) / DAY_S
/** It is night: the stars are out and the night mobs walk. */
export const isNight = (s: State) => phaseOf(s) >= NIGHT_FROM && phaseOf(s) < NIGHT_TO
const panAt = (world: World, x: number) => clamp((x / world.w) * 2 - 1, -1, 1) * 0.8

/** Square bits in a block's colours flying out of where it broke. */
function breakBurst(s: Overworld, world: World, x: number, y: number, kind: Block, n = 14) {
  const c = BLOCK_COLORS[kind]
  for (const color of [c.base, c.dark, c.fleck ?? c.light]) {
    burstBits(s.bits, world.rnd, x, y, Math.ceil(n / 3), 220, { shape: 'square', size: 5, color, gravity: 900, life: 0.7 })
  }
}

function dropItem(s: Overworld, world: World, x: number, y: number, kind: ItemKind, life = ITEM_S) {
  if (s.items.length >= MAX_ITEMS) s.items.shift()
  s.items.push({ x, y, vx: between(world.rnd, -80, 80), vy: -between(world.rnd, 150, 260), kind: ITEM_KINDS.indexOf(kind), life, t: 0 })
}

/** XP orbs fly from (x, y) into the XP bar. */
function orbsFrom(s: Overworld, world: World, x: number, y: number, n: number) {
  for (let i = 0; i < n; i++) {
    if (s.orbs.length >= MAX_ORBS) s.orbs.shift()
    s.orbs.push({ x, y, vx: between(world.rnd, -260, 260), vy: -between(world.rnd, 120, 360), t: -i * 0.04, d: ORB_S + world.rnd() * 0.3 })
  }
}

function explode(s: Overworld, world: World, x: number, y: number) {
  spawnBit(s.bits, { x, y, shape: 'ring', size: 10, grow: 600, life: 0.45, color: '#fff' })
  burstBits(s.bits, world.rnd, x, y, 26, 300, { size: 12, grow: 30, color: 'rgba(200,200,200,0.55)', life: 1.2 })
  for (const kind of ['dirt', 'stone', 'grass'] as const) breakBurst(s, world, x, y, kind, 18)
  world.signal('boom', 900)
  world.sound?.explode(panAt(world, x))
  // Steve, if he stood close, is thrown up and hurt.
  const st = s.steve
  if (st.on && Math.abs(st.x - x) < 140) {
    st.hurtT = 0.6
    st.vy = 380
    st.x += Math.sign(st.x - x || 1) * 30
  }
}

/** Starts rain (or snow) for `seconds`, with its sound. */
function startRain(s: Overworld, world: World, seconds: number) {
  if (!s.rain) world.sound?.rain(true)
  s.rain = Math.max(s.rain as number, seconds)
}

function stopRain(s: Overworld, world: World) {
  if (s.rain) world.sound?.rain(false)
  s.rain = 0
  s.nextRain = between(world.rnd, ...RAIN_EVERY_S)
}

/** Sends a mob in from one side: a farm animal by day, a zombie or skeleton by night. */
function sendMob(s: Overworld, world: World) {
  const { rnd, w } = world
  const dir = rnd() < 0.5 ? 1 : -1
  const kinds = isNight(s) ? NIGHT_MOBS : DAY_MOBS
  Object.assign(s.mob, {
    on: 1, kind: kinds[Math.floor(rnd() * kinds.length)], dir, x: dir > 0 ? -30 : w + 30, walk: 1, turnT: between(rnd, 3, 7),
    life: between(rnd, 18, 30), flee: 0, hp: 2, wool: 0, stride: 0,
  })
}

function stepMob(s: Overworld, world: World, quiet: boolean) {
  const { dt, w, rnd, pointer } = world
  const m = s.mob
  if (world.wild && !quiet && !m.on) {
    s.nextMob = (s.nextMob as number) - dt
    if ((s.nextMob as number) <= 0) {
      sendMob(s, world)
      s.nextMob = between(rnd, 20, 45)
    }
  }
  if (!m.on) return
  m.life -= dt
  m.turnT -= dt
  m.flee = Math.max(0, m.flee - dt)
  // A fast mouse close by sends it running the other way.
  const speed = Math.hypot(pointer.vx, pointer.vy)
  if (pointer.active && !pointer.touch && speed > SCARE_SPEED && Math.abs(pointer.x - m.x) < SCARE_PX && pointer.y > floorOf(world) - SCARE_PX) {
    if (!m.flee && m.kind < 3) world.sound?.animal(m.kind === 0 ? 'pig' : m.kind === 1 ? 'chicken' : 'sheep')
    m.dir = Math.sign(m.x - pointer.x) || 1
    m.walk = 1
    m.flee = FLEE_S
  }
  if (!m.flee && m.turnT <= 0 && m.life > 0) {
    m.turnT = between(rnd, 2, 6)
    m.walk = rnd() < 0.25 ? 0 : 1
    if (rnd() < 0.3) m.dir = -m.dir
    // Now and then it says something.
    if (!quiet && rnd() < 0.3) {
      if (m.kind === 3) world.sound?.groan()
      else if (m.kind === 4) world.sound?.rattle()
      else world.sound?.animal(m.kind === 0 ? 'pig' : m.kind === 1 ? 'chicken' : 'sheep')
    }
  }
  // Time up, or the sun came up on a night mob: it walks off the nearer edge.
  if (m.life <= 0 || (m.kind >= 3 && !isNight(s))) {
    m.walk = 1
    m.dir = m.x < w / 2 ? -1 : 1
    m.life = Math.min(m.life, 0)
  }
  if (m.walk) {
    m.x += m.dir * 34 * (m.flee ? 3 : 1) * dt
    m.stride += dt * (m.flee ? 20 : 9)
  }
  if (m.life > 0 && !m.flee && (m.x < 20 || m.x > w - 20)) m.dir = m.x < 20 ? 1 : -1
  if (m.x < -60 || m.x > w + 60) m.on = 0
}

/** Steve walks the grass towards the mouse (or the block being mined), and jumps when told. */
function stepSteve(s: Overworld, world: World, quiet: boolean) {
  const { dt, w, pointer } = world
  const st = s.steve
  st.on = world.wild && !quiet ? 1 : 0
  if (!st.on) return
  st.swing = 0
  let target = st.x
  if (s.busy) {
    target = busyAt(world).x - 46
    if (Math.abs(st.x - target) < 6) {
      st.face = 1
      st.swing = (world.t * 3) % 1 || 0.01
    }
  } else if (pointer.active && !pointer.touch) target = clamp(pointer.x - 30 * st.face, 20, w - 20)
  const gap = target - st.x
  if (Math.abs(gap) > 4) {
    const v = Math.abs(gap) > 300 ? STEVE_RUN : STEVE_WALK
    st.x += Math.sign(gap) * Math.min(Math.abs(gap), v * dt)
    st.face = Math.sign(gap)
    st.stride += dt * (v === STEVE_RUN ? 16 : 10)
  } else st.stride = 0
  st.hurtT = Math.max(0, (st.hurtT ?? 0) - dt)
  st.vy -= 1500 * dt
  st.y = Math.max(0, st.y + st.vy * dt)
  if (!st.y) st.vy = 0
}

export const blocks: Preset = {
  layer: 'back',
  init(world, prev) {
    const { rnd, w, h } = world
    const n = scaleCount(world, world.wild ? 12 : 8)
    // Flat, square clouds at a few heights, the higher ones slower.
    const p = Array.from({ length: n }, () => {
      const y = between(rnd, 0.04, 0.45) * h
      return { x: rnd() * w, y, w: Math.round(between(rnd, 3, 9)) * 16, h: Math.round(between(rnd, 1, 3)) * 12, v: 6 + (y / h) * 18 }
    })
    const stars = Array.from({ length: scaleCount(world, 80) }, () => ({ x: rnd() * w, y: rnd() * h * 0.6, tw: rnd() * 6, r: rnd() < 0.2 ? 2 : 1 }))
    const month = new Date().getMonth()
    const world_: Overworld = {
      p, bits: [], max: n, stars, drops: [],
      mob: { on: 0, kind: 0, x: 0, dir: 1, walk: 1, turnT: 0, stride: 0, life: 0, flee: 0, hp: 2, wool: 0 },
      steve: { on: 0, x: w * 0.2, y: 0, vy: 0, face: 1, stride: 0, swing: 0, hurtT: 0 },
      blocks: [], items: [], orbs: [], arrows: [],
      creeper: { on: 0, x: 0, y: 0, fuse: 0 },
      busy: 0, quiet: 0, nextMob: 8, ore: 0, oreMax: BUSY_ORES.length - 1,
      clock: DAY_S * START_PHASE, rain: 0, nextRain: between(rnd, ...RAIN_EVERY_S), snowy: month === 11 || month < 2 ? 1 : 0,
      nightT: 0, angle: 0,
    }
    if (prev) for (const k of KEEP) world_[k] = prev[k]
    return world_
  },
  start(_s, world) {
    world.sound?.music(true)
  },
  step(state, world) {
    const s = state as Overworld
    const { dt, w, rnd, pointer } = world
    const floor = floorOf(world)
    const quiet = !!s.quiet

    // The day goes round; at night the page gets the app-night class (refreshed while it lasts).
    s.clock = ((s.clock as number) + dt) % DAY_S
    s.nightT = (s.nightT as number) - dt
    if ((s.nightT as number) <= 0) {
      s.nightT = 0.5
      if (isNight(s)) world.signal('night', 1500)
    }
    s.angle = (s.angle as number) + dt * 0.8

    for (const q of s.p) {
      q.x += q.v * dt * (s.rain ? 2.5 : 1)
      if (q.x > w + 20) q.x = -q.w - 20
    }

    // Weather: now and then at Wild a shower; rain falls as streaks, snow drifts.
    if (world.wild && !quiet && !s.rain) {
      s.nextRain = (s.nextRain as number) - dt
      if ((s.nextRain as number) <= 0) startRain(s, world, between(rnd, ...RAIN_FOR_S))
    }
    if (s.rain) {
      s.rain = Math.max(0, (s.rain as number) - dt)
      if (!s.rain) stopRain(s, world)
      else {
        world.signal('rain', 1500)
        const n = Math.round(dt * (s.snowy ? 60 : 260) * (world.wild ? 1 : 0.5))
        for (let i = 0; i < n && s.drops.length < MAX_DROPS; i++) {
          s.drops.push(s.snowy
            ? { x: rnd() * (w + 100) - 50, y: -10, vx: between(rnd, -20, 20), vy: between(rnd, 40, 80), s: rnd() < 0.3 ? 3 : 2 }
            : { x: rnd() * (w + 200) - 100, y: -20, vx: -60, vy: between(rnd, 700, 950), s: between(rnd, 10, 18) })
        }
      }
    }
    for (let i = s.drops.length - 1; i >= 0; i--) {
      const d = s.drops[i]
      d.x += d.vx * dt + (s.snowy ? Math.sin(world.t * 2 + d.y * 0.05) * 10 * dt : 0)
      d.y += d.vy * dt
      if (d.y > floor) {
        if (!s.snowy && rnd() < 0.3) spawnBit(s.bits, { x: d.x, y: floor, vy: -60, vx: between(rnd, -30, 30), size: 1.5, gravity: 400, life: 0.25, color: 'rgba(160,190,255,0.8)' })
        s.drops.splice(i, 1)
      }
    }

    stepMob(s, world, quiet)
    stepSteve(s, world, quiet)

    // Blocks being mined crack, then break and drop their item.
    for (let i = s.blocks.length - 1; i >= 0; i--) {
      const b = s.blocks[i]
      b.t += dt
      const kind = b.busy ? oreOf(s) : BUSY_ORES[b.kind]
      b.digT -= dt
      if (b.digT <= 0) {
        b.digT = 0.24
        world.sound?.dig(MATERIAL[kind])
      }
      if (b.t < b.dur) continue
      breakBurst(s, world, b.x, b.y, kind)
      world.sound?.blockbreak(MATERIAL[kind])
      dropItem(s, world, b.x, b.y, kind as ItemKind)
      if (b.busy && s.busy) {
        // The request is still running: on to the next ore, up to the one that fits it.
        b.t = 0
        s.ore = Math.min((s.ore as number) + 1, s.oreMax as number)
      } else s.blocks.splice(i, 1)
    }

    // Items bounce on the grass and come to a mouse that is near, which picks them up.
    const mouse = pointer.active && !pointer.touch
    for (let i = s.items.length - 1; i >= 0; i--) {
      const it = s.items[i]
      it.life -= dt
      it.t += dt
      const dx = pointer.x - it.x
      const dy = pointer.y - it.y
      const d = Math.hypot(dx, dy)
      if (mouse && d < MAGNET_PX) {
        it.vx += (dx / Math.max(d, 1)) * 2200 * dt
        it.vy += (dy / Math.max(d, 1)) * 2200 * dt
        it.vx *= 1 - 4 * dt
        it.vy *= 1 - 4 * dt
      } else it.vy += 900 * dt
      it.x += it.vx * dt
      it.y += it.vy * dt
      if (it.y > floor - 6) {
        it.y = floor - 6
        it.vy = Math.abs(it.vy) > 60 ? -it.vy * 0.35 : 0
        it.vx *= 1 - 5 * dt
      }
      if (mouse && d < PICKUP_PX) {
        s.items.splice(i, 1)
        world.sound?.pickup()
        orbsFrom(s, world, it.x, it.y, 2)
        continue
      }
      if (it.life <= 0) s.items.splice(i, 1)
    }

    // XP orbs pop out, then home in on the bar and chime as they land.
    const bar = barOf(world)
    for (let i = s.orbs.length - 1; i >= 0; i--) {
      const o = s.orbs[i]
      o.t += dt
      if (o.t < 0) continue
      const k = clamp(o.t / o.d, 0, 1)
      o.vx += (bar.x - o.x) * 18 * k * dt
      o.vy += (bar.y - o.y) * 18 * k * dt
      o.vx *= 1 - 3 * k * dt
      o.vy *= 1 - 3 * k * dt
      o.x += o.vx * dt
      o.y += o.vy * dt
      if (o.t > o.d && Math.hypot(bar.x - o.x, bar.y - o.y) < 24) {
        s.orbs.splice(i, 1)
        world.sound?.xp(1 + rnd() * 0.5)
        spawnBit(s.bits, { x: o.x, y: o.y, shape: 'star', size: 4, life: 0.3, color: '#c8ff6a' })
      } else if (o.t > o.d + 2) s.orbs.splice(i, 1)
    }

    // Arrows fly to the result they were shot at and stick there, quivering, for a while.
    for (let i = s.arrows.length - 1; i >= 0; i--) {
      const a = s.arrows[i]
      if (!a.stuck) {
        a.x += a.vx * dt
        if (a.x >= a.tx) {
          a.x = a.tx
          a.stuck = 1
          world.sound?.thunk()
          burstBits(s.bits, rnd, a.x, a.y, 6, 120, { shape: 'square', size: 3, color: '#8a6136', gravity: 600 })
        }
      } else if ((a.stuck += dt) > 3) s.arrows.splice(i, 1)
    }

    // After an error the creeper's fuse burns, it swells and flashes, and blows up.
    const c = s.creeper
    if (c.on) {
      c.fuse -= dt
      if (c.fuse <= 0) {
        c.on = 0
        explode(s, world, c.x, c.y - 24)
      }
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, state, world) {
    const s = state as Overworld
    const { t } = world
    const floor = floorOf(world)

    if (isNight(s)) {
      ctx.fillStyle = '#fff'
      for (const q of s.stars) {
        ctx.globalAlpha = 0.4 + 0.6 * Math.abs(Math.sin(t * 0.8 + q.tw))
        ctx.fillRect(q.x, q.y, q.r, q.r)
      }
      ctx.globalAlpha = 1
    }

    ctx.fillStyle = s.rain ? 'rgba(200,205,215,0.9)' : 'rgba(255,255,255,0.85)'
    for (const q of s.p) {
      ctx.fillRect(Math.round(q.x), Math.round(q.y), q.w, q.h)
      ctx.fillRect(Math.round(q.x + q.w * 0.25), Math.round(q.y - q.h * 0.5), q.w * 0.5, q.h * 0.5)
    }

    if (s.drops.length) {
      if (s.snowy) {
        ctx.fillStyle = '#fff'
        for (const d of s.drops) ctx.fillRect(d.x, d.y, d.s, d.s)
      } else {
        ctx.fillStyle = 'rgba(90,120,220,0.55)'
        for (const d of s.drops) ctx.fillRect(d.x, d.y, 2, d.s)
      }
    }

    if (s.mob.on) drawMob(ctx, s.mob.kind as MobKind, s.mob.x, floor + 2, s.mob.kind >= 3 ? 44 : 30, s.mob.dir, s.mob.stride, s.mob.wool)
    if (s.steve.on) drawSteve(ctx, s.steve.x, floor + 2 - s.steve.y, STEVE_H, s.steve.face, { stride: s.steve.stride, swing: s.steve.swing, torch: isNight(s), hurt: s.steve.hurtT > 0 })

    for (const b of s.blocks) {
      const kind = b.busy ? oreOf(s) : BUSY_ORES[b.kind]
      if (b.busy) drawCube(ctx, b.x, b.y, b.size, kind, 99 + (s.ore as number), b.t / b.dur, s.angle as number)
      else drawBlock(ctx, b.x - b.size / 2, b.y - b.size / 2, b.size, kind, b.seed, b.t / b.dur)
    }

    // Items: small, bobbing and turning slowly.
    for (const it of s.items) {
      const bob = Math.sin(it.t * 3) * 2
      ctx.save()
      ctx.globalAlpha = Math.min(1, it.life)
      ctx.translate(it.x, it.y - 6 + bob)
      ctx.scale(Math.cos(it.t * 2) * 0.4 + 0.6, 1)
      drawItem(ctx, ITEM_KINDS[it.kind] ?? 'stone', 12, it.kind)
      ctx.restore()
    }

    for (const o of s.orbs) {
      if (o.t < 0) continue
      const r = 4 + Math.sin(t * 12 + o.d * 40) * 1
      ctx.fillStyle = '#b8f83a'
      ctx.fillRect(o.x - r, o.y - r, r * 2, r * 2)
      ctx.fillStyle = '#eaff9a'
      ctx.fillRect(o.x - r / 2, o.y - r / 2, r, r)
    }

    ctx.lineWidth = 2
    for (const a of s.arrows) {
      const quiver = a.stuck && a.stuck < 0.5 ? Math.sin(a.stuck * 60) * 3 * (0.5 - a.stuck) * 2 : 0
      ctx.save()
      ctx.translate(a.x, a.y)
      ctx.rotate(quiver * 0.05)
      ctx.strokeStyle = '#8a6136'
      ctx.beginPath()
      ctx.moveTo(-34, 0)
      ctx.lineTo(0, 0)
      ctx.stroke()
      ctx.fillStyle = '#ccc'
      ctx.fillRect(-2, -3, 4, 6)
      ctx.fillStyle = '#eee'
      ctx.fillRect(-36, -4, 6, 3)
      ctx.fillRect(-36, 1, 6, 3)
      ctx.restore()
    }

    const c = s.creeper
    if (c.on) {
      const lit = 1 - c.fuse / FUSE_S
      // It swells as the fuse burns, and flashes faster and faster.
      const flash = Math.sin(t * (10 + lit * 30)) > 0 ? lit : 0
      drawCreeper(ctx, c.x, c.y, 52 * (1 + lit * 0.15), flash)
    }

    drawBits(ctx, s.bits)
  },
  burst(state, world, x, y) {
    const s = state as Overworld
    if (s.quiet) return
    const floor = floorOf(world)
    const m = s.mob
    // A click on a mob: an animal answers (and drops something, or changes colour); a monster takes a hit.
    if (m.on && Math.abs(x - m.x) < 22 && y > floor - (m.kind >= 3 ? 48 : 32) && y < floor + 6) {
      switch (m.kind) {
        case 0:
          dropItem(s, world, m.x, floor - 20, 'porkchop')
          world.sound?.animal('pig')
          break
        case 1:
          dropItem(s, world, m.x, floor - 20, 'egg')
          world.sound?.animal('chicken')
          break
        case 2:
          m.wool = (m.wool + 1) % WOOL.length
          world.sound?.animal('sheep')
          break
        default:
          m.hp--
          m.x -= Math.sign(x - m.x || 1) * 18
          if (m.kind === 3) world.sound?.groan()
          else world.sound?.rattle()
          if (m.hp <= 0) {
            m.on = 0
            burstBits(s.bits, world.rnd, m.x, floor - 20, 14, 160, { size: 6, grow: 20, color: 'rgba(220,220,220,0.8)', life: 0.6 })
            dropItem(s, world, m.x, floor - 20, m.kind === 3 ? 'flesh' : 'bone')
            orbsFrom(s, world, m.x, floor - 20, 3)
          }
      }
      return
    }
    if (world.pointer.bare) {
      // Steve hops when the grass is clicked near him.
      if (s.steve.on && !s.steve.y && Math.abs(x - s.steve.x) < 120 && y > floor - 60) s.steve.vy = 420
      const gx = Math.floor(x / CELL) * CELL + CELL / 2
      const gy = Math.floor(y / CELL) * CELL + CELL / 2
      if (s.blocks.some(b => !b.busy && b.x === gx && b.y === gy)) return
      const kind = world.rnd() < 0.7 ? 0 : 1 + Math.floor(world.rnd() * (BUSY_ORES.length - 1))
      s.blocks.push({ x: gx, y: gy, size: CELL, kind, t: 0, dur: CLICK_BREAK_S, digT: 0, seed: gx * 7 + gy, busy: 0 })
    } else if (world.pointer.control) {
      const voice = PRESS[world.pointer.control]
      if (voice && world.sound) voice(world.sound)
    }
  },
  key(state, world, k) {
    const s = state as Overworld
    // Keys played in a minigame or typed in the chat are not typing.
    if (s.quiet) return
    const { rnd } = world
    switch (k.kind) {
      case 'tab':
        return
      case 'delete':
        breakBurst(s, world, k.x, k.y, 'stone', 4)
        world.sound?.dig('gravel')
        return
      case 'enter':
        spawnBit(s.bits, { x: k.x, y: k.y, shape: 'square', size: 14, grow: 40, life: 0.3, color: 'rgba(134,96,67,0.6)' })
        breakBurst(s, world, k.x, k.y, 'dirt', 6)
        world.sound?.place()
        return
      default:
        for (let i = 0; i < 2; i++) {
          spawnBit(s.bits, {
            x: k.x, y: k.y, vx: between(rnd, -50, 50), vy: -between(rnd, 40, 120), shape: 'square', size: 3, gravity: 700, life: 0.5,
            color: rnd() < 0.5 ? BLOCK_COLORS.dirt.base : '#5d9c32',
          })
        }
        world.sound?.step()
    }
  },
  focus(_state, world) {
    world.sound?.uiclick()
  },
  browse(_state, world, index) {
    world.sound?.option(index)
  },
  activity(state, world, a) {
    const s = state as Overworld
    const { w, h } = world
    switch (a) {
      case 'forward':
        world.sound?.place()
        return
      case 'back':
        world.sound?.blockbreak('stone')
        return
      case 'file-in':
        // An item pops up in the middle and is pulled into the XP bar, the way pickups go to the hotbar.
        breakBurst(s, world, w / 2, h / 2, 'diamond', 8)
        orbsFrom(s, world, w / 2, h / 2, 3)
        world.sound?.pickup()
        return
      case 'file-out':
        dropItem(s, world, w / 2, h / 2, 'stone', 1.5)
        world.sound?.blockbreak('dirt')
        return
      case 'saved':
        orbsFrom(s, world, w / 2, h / 2, 4)
        world.sound?.chest(false)
        return
      case 'panel-open':
        world.sound?.chest(true)
        return
      case 'panel-close':
        world.sound?.chest(false)
        return
      default:
        world.sound?.uiclick()
    }
  },
  scroll(state, world, dy) {
    const s = state as Overworld
    for (const q of s.p) {
      q.y -= dy * 0.04 * (q.v / 24)
      if (q.y < -q.h) q.y += world.h * 0.5
      if (q.y > world.h * 0.5) q.y -= world.h * 0.5
    }
  },
  chrome(state, world, event) {
    const s = state as Overworld
    switch (event) {
      case 'game-open':
        s.quiet = 1
        s.mob.on = 0
        world.sound?.music(false)
        if (s.rain) world.sound?.rain(false)
        return
      case 'game-close':
        s.quiet = 0
        world.sound?.music(true)
        if (s.rain) world.sound?.rain(true)
        world.sound?.uiclick()
        return
      case 'time-day':
        s.clock = DAY_S * START_PHASE
        world.signal('night', 0)
        if (s.mob.kind >= 3) s.mob.life = 0
        return
      case 'time-night':
        s.clock = DAY_S * (NIGHT_FROM + 0.02)
        s.nightT = 0
        return
      case 'weather-rain':
        startRain(s, world, between(world.rnd, ...RAIN_FOR_S))
        return
      case 'weather-clear':
        stopRain(s, world)
        world.signal('rain', 0)
        return
      case 'sheet-open':
        world.sound?.chest(true)
        return
      case 'sheet-close':
        world.sound?.chest(false)
    }
  },
  busy(state, world, on, info?: BusyInfo) {
    const s = state as Overworld
    s.busy = on ? 1 : 0
    world.signal('mine', on ? 60_000 : 0)
    if (on && !s.blocks.some(b => b.busy)) {
      const at = busyAt(world)
      s.ore = 0
      s.oreMax = info?.action === 'verify' ? VERIFY_ORE : LEVEL_ORE[info?.level ?? ''] ?? BUSY_ORES.length - 1
      s.blocks.push({ x: at.x, y: at.y, size: 44, kind: 0, t: 0, dur: BUSY_BREAK_S, digT: 0, seed: 99, busy: 1 })
    }
    // Ended: the block in hand breaks at once, whatever its cracks.
    if (!on) for (const b of s.blocks) if (b.busy) b.t = b.dur
  },
  outcome(state, world, kind, box) {
    const s = state as Overworld
    const { w, rnd } = world
    const floor = floorOf(world)
    const x = box ? (box.left + box.right) / 2 : w / 2
    const y = box ? (box.top + box.bottom) / 2 : world.h / 2
    switch (kind) {
      case 'success':
        orbsFrom(s, world, x, y, 16)
        burstBits(s.bits, rnd, x, y, 24, 380, { shape: 'star', size: 5, color: '#c8ff6a', gravity: 300 })
        world.signal('advancement', 4000)
        world.sound?.levelup()
        return
      case 'warning':
        // An arrow from a skeleton off to the left, into the result's left edge.
        s.arrows.push({ x: -40, y, vx: 1800, tx: box ? box.left + 6 : w * 0.4, stuck: 0 })
        world.sound?.swish(-0.8)
        return
      case 'error': {
        // A creeper steps up beside the result and lights its fuse; at Wild a storm rolls in.
        const cx = box ? clamp(box.right + 34, 40, w - 40) : w * 0.7
        const cy = box ? Math.min(floor, box.bottom) : floor
        Object.assign(s.creeper, { on: 1, x: cx, y: cy, fuse: FUSE_S })
        world.sound?.hiss()
        if (world.wild) {
          world.signal('lightning', 300)
          world.sound?.thunder()
          startRain(s, world, STORM_S)
        }
        return
      }
      default:
        burstBits(s.bits, rnd, x, y, 10, 120, { shape: 'star', size: 4, color: '#5ee05e', gravity: -60 })
        world.sound?.hmm(false)
    }
  },
}
