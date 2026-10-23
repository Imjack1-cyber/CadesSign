import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { type Crafting, createCrafting, tickCrafting } from './craftingGame'
import {
  BIOMES, DAY_S, DUCK_H, PLAYER_H, PLAYER_X, type ObstacleKind, type Run, type RunEvent, autoRunInput, createRun,
  scoreOfRun, stepRun,
} from './creeperGame'
import { type Bit, burstBits, drawBits, spawnBit, stepBits } from './effects/bits'
import { BLOCK_COLORS, MATERIAL, drawBlock, drawCreeper, drawSteve, drawTorch } from './effects/minecraft'
import { type Sound, createSound } from './effects/sound'
import { MinecraftCrafting } from './MinecraftCrafting'
import {
  type Bank, type GameId, type Records, SUPPLIES, bankRun, buyPick, buySupply, canBuyPick, canBuySupply, readBank, readRecords,
  saveRecord, unlock,
} from './minecraftState'
import {
  type Block, COLS, DEEP_Y, FUSE_S, HEARTS, type MineEvent, type Mining, type OverReason, PICKS, createMining, mineTime, scoreOf,
  stepMining,
} from './miningGame'
import { emitChrome } from './signals'
import { trapFocus } from './trapFocus'
import { useDesign } from './useDesign'

type Screen = 'menu' | 'shop' | 'playing' | 'paused' | 'over'
type Action = 'left' | 'right' | 'up' | 'down' | 'torch' | 'pour'

const GAMES: ReadonlyArray<{ id: GameId; label: string; blurb: string }> = [
  { id: 'mining', label: 'Mining Run', blurb: 'Three minutes to dig as deep as you can. Ores score and fill your bank; mind the lava, gravel and creepers.' },
  { id: 'runner', label: 'Creeper Run', blurb: 'Steve runs through plains, desert, snow and the Nether: jump, duck, grab emeralds, elytras and shields.' },
  { id: 'crafting', label: 'Crafting', blurb: 'Ninety seconds at the crafting table. Lay out each order in its recipe; the recipe book helps if you wait.' },
]

/** The title screen's yellow splash; one is picked each time it opens. */
const SPLASHES = [
  'Now with signatures!', 'Also try Windows 95!', 'Now with timestamps!', '100% B-LT!', 'Long-term validation!',
  'SHA-256 compliant!', 'Trust the list!', 'Not a notary!', 'Detached or enveloping!', 'Creeper-free PKI!',
  'Also try Deep Sea!', 'OCSP-approved!', 'Sideswipe is next door!', 'Archive timestamps!', 'Blocks all the way down!',
]

/** Death messages, as the game words them; one is picked for each death. */
const DIED: Record<OverReason | ObstacleKind | 'crafting', string[]> = {
  time: ['The clock ran out', 'Steve ran out of daylight'],
  lava: ['Steve tried to swim in lava', 'Steve walked into lava', 'Steve was burnt to a crisp'],
  creeper: ['Steve was blown up by Creeper', 'Steve was blown up by Creeper whilst trying to escape'],
  husk: ['Steve was slain by Husk', 'Steve was eaten by a desert zombie'],
  gravel: ['Steve was squashed by falling gravel', 'Steve suffocated in a wall'],
  fall: ['Steve hit the ground too hard', 'Steve fell from a high place'],
  cactus: ['Steve was pricked to death', 'Steve walked into a cactus whilst trying to escape'],
  hole: ['Steve fell out of the world', 'Steve fell into a ravine'],
  arrow: ['Steve was shot by Skeleton', 'Steve was shot by Stray'],
  blaze: ['Steve was burnt by Blaze', 'Steve was fireballed by Blaze'],
  fireball: ['Steve was fireballed by Ghast', 'Steve was blown up by a Ghast'],
  emerald: ['Steve got rich'],
  elytra: ['Steve experienced kinetic energy'],
  shield: ['Steve hid behind a shield'],
  crafting: ['The crafting table closed for the day', 'Time to put the tools away'],
}

const pick = <T,>(list: readonly T[]) => list[Math.floor(Math.random() * list.length)]

const ORES: ReadonlyArray<[Block, string]> = [['coal', 'Coal'], ['iron', 'Iron'], ['gold', 'Gold'], ['diamond', 'Diamonds']]

/** What the HUD shows; only re-rendered when it changes. */
interface Hud {
  hearts?: number
  items: Array<[label: string, value: string]>
  banner?: string
}

const sameHud = (a: Hud, b: Hud) => JSON.stringify(a) === JSON.stringify(b)

const clock = (s: number) => `${Math.floor(Math.ceil(s) / 60)}:${String(Math.ceil(s) % 60).padStart(2, '0')}`

const miningHud = (g: Mining): Hud => ({
  hearts: g.hearts,
  items: [
    ['Time', clock(g.time)], ['Score', String(scoreOf(g))], ['Depth', String(g.depth)],
    ['Torches', String(g.torches)], ['Buckets', String(g.buckets)],
  ],
})

const runHud = (r: Run, best: number, banner?: string): Hud => ({
  items: [
    ['Score', String(scoreOfRun(r))], ['Best', String(Math.max(best, scoreOfRun(r)))], ['Emeralds', String(r.emeralds)],
    ...(r.glide > 0 ? [['Elytra', `${Math.ceil(r.glide)}s`] as [string, string]] : []),
    ...(r.shield ? [['Shield', 'ready'] as [string, string]] : []),
  ],
  banner,
})

const craftHud = (c: Crafting, best: number): Hud => ({
  items: [['Time', clock(c.time)], ['Score', String(c.score)], ['Crafted', String(c.crafted.length)], ['Best', String(Math.max(best, c.score))]],
})

interface Result {
  game: GameId
  score: number
  best: boolean
  reason: OverReason | ObstacleKind | 'crafting'
  message: string
  stats: Array<[string, string]>
}

/** The keys the games use, and what they do. */
const KEYS: Record<string, Action> = {
  ArrowLeft: 'left', a: 'left', A: 'left',
  ArrowRight: 'right', d: 'right', D: 'right',
  ArrowUp: 'up', w: 'up', W: 'up', ' ': 'up',
  ArrowDown: 'down', s: 'down', S: 'down',
  e: 'torch', E: 'torch',
  q: 'pour', Q: 'pour',
}

/** A swipe this many px long counts as a direction; shorter is a tap. */
const SWIPE_PX = 24

interface MinecraftGameProps {
  onClose: () => void
  /** Start straight into this game instead of the title screen. */
  initial?: GameId
}

/**
 * The Minecraft theme's minigames, in one modal styled as the title screen: Mining Run (miningGame.ts),
 * Creeper Run (creeperGame.ts) and Crafting (craftingGame.ts), each with its best score, and Mining
 * Run's shop for pickaxes, torches and buckets paid for with the ores mined. A pause menu on Esc, a
 * death screen with the score and stats, and behind the menus Steve running on his own. On touch
 * screens, swipes and taps on the play area and on-screen buttons stand in for the keys.
 */
export function MinecraftGame({ onClose, initial }: MinecraftGameProps) {
  const { soundPick } = useDesign()
  const dialogRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [screen, setScreen] = useState<Screen>('menu')
  const [game, setGame] = useState<GameId>('mining')
  const [records, setRecords] = useState<Records>(readRecords)
  const [bank, setBank] = useState<Bank>(readBank)
  const [hud, setHud] = useState<Hud | null>(null)
  const [announce, setAnnounce] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [splash] = useState(() => pick(SPLASHES))
  const [craftGame, setCraftGame] = useState<Crafting | null>(null)

  const mining = useRef<Mining | null>(null)
  const run = useRef<Run | null>(null)
  const crafting = useRef<Crafting | null>(null)
  /** Steve running behind the menus. */
  const attract = useRef<Run>(createRun())
  const screenRef = useRef(screen)
  const gameRef = useRef(game)
  const bestRef = useRef(records)
  useEffect(() => {
    screenRef.current = screen
    gameRef.current = game
    bestRef.current = records
  }, [screen, game, records])
  const keys = useRef(new Set<Action>())
  const touches = useRef(new Map<number, Action>())
  /** Torch and bucket presses, kept until the game has seen them, so a quick tap is not lost between frames. */
  const taps = useRef(new Set<Action>())
  const swipes = useRef(new Map<number, { x: number; y: number }>())
  const sound = useRef<Sound | null>(null)

  // Audio of its own, following the user's sound pick; the world behind goes quiet meanwhile.
  useEffect(() => {
    emitChrome('game-open')
    return () => emitChrome('game-close')
  }, [])
  useEffect(() => {
    if (soundPick !== 'on') return
    const s = createSound()
    sound.current = s
    return () => {
      s.dispose()
      sound.current = null
    }
  }, [soundPick])

  useEffect(() => {
    dialogRef.current?.focus()
  }, [])

  const start = useCallback((id: GameId) => {
    keys.current.clear()
    touches.current.clear()
    setGame(id)
    gameRef.current = id
    setResult(null)
    if (id === 'mining') {
      const b = readBank()
      mining.current = createMining(Math.random, { pick: b.pick, torches: b.torches, buckets: b.buckets })
      setHud(miningHud(mining.current))
    } else if (id === 'runner') {
      run.current = createRun()
      setHud(runHud(run.current, bestRef.current.runner ?? 0))
    } else {
      crafting.current = createCrafting()
      setCraftGame(crafting.current)
      setHud(craftHud(crafting.current, bestRef.current.crafting ?? 0))
    }
    setAnnounce(`${GAMES.find(g => g.id === id)?.label} started`)
    setScreen('playing')
    dialogRef.current?.focus()
  }, [])

  // Straight into a game when the chat asked for one.
  useEffect(() => {
    if (!initial) return
    const t = window.setTimeout(() => start(initial))
    return () => window.clearTimeout(t)
  }, [initial, start])

  const end = useCallback((r: Omit<Result, 'best' | 'message'>) => {
    const best = saveRecord(r.game, r.score)
    if (best) {
      setRecords(readRecords())
      sound.current?.levelup()
    }
    if (r.game === 'mining') setBank(readBank())
    const message = pick(DIED[r.reason])
    setResult({ ...r, best, message })
    setAnnounce(`${message}. Score ${r.score}${best ? ', a new best' : ''}`)
    setScreen('over')
  }, [])

  // Keyboard: the game keys while playing; Esc pauses, resumes or leaves the menus.
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return
      if (e.key === 'Escape') {
        e.preventDefault()
        e.stopPropagation()
        const now = screenRef.current
        if (now === 'playing') setScreen('paused')
        else if (now === 'paused') setScreen('playing')
        else if (now === 'shop') setScreen('menu')
        else onClose()
        return
      }
      if (e.key === 'Tab') {
        trapFocus(e, dialogRef.current)
        return
      }
      // The crafting table is all buttons; its keys are the page's own.
      if (gameRef.current === 'crafting') return
      const action = KEYS[e.key]
      if (!action || screenRef.current !== 'playing') return
      e.preventDefault()
      keys.current.add(action)
      if (action === 'torch' || action === 'pour') taps.current.add(action)
    }
    const up = (e: KeyboardEvent) => {
      const action = KEYS[e.key]
      if (action) keys.current.delete(action)
    }
    const blur = () => keys.current.clear()
    window.addEventListener('keydown', down, true)
    window.addEventListener('keyup', up, true)
    window.addEventListener('blur', blur)
    return () => {
      window.removeEventListener('keydown', down, true)
      window.removeEventListener('keyup', up, true)
      window.removeEventListener('blur', blur)
    }
  }, [onClose])

  // Switching tabs pauses the game.
  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden && screenRef.current === 'playing') setScreen('paused')
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => document.removeEventListener('visibilitychange', onVisibility)
  }, [])

  // The loop: steps the game being played (or Steve running behind the menus), sounds its events, draws.
  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    const bits: Bit[] = []
    let shake = 0
    let hurtFlash = 0
    let last = performance.now()
    let frame = 0
    let t = 0
    let shown: Hud | null = null
    let banner = ''
    let bannerT = 0
    /** The mining view: cell size, left edge, the row at the top (smoothed) and Steve's drawn place. */
    const view = { cell: 40, left: 0, camY: -2, px: 0, py: 0, stride: 0 }
    /** The dark of the mines, drawn off screen with holes where the light is. */
    const shade = document.createElement('canvas')
    const shadeCtx = shade.getContext('2d')

    const held = () => new Set([...keys.current, ...touches.current.values()])

    const cellCenter = (x: number, y: number) => ({
      x: view.left + (x + 0.5) * view.cell, y: (y - view.camY + 0.5) * view.cell,
    })

    const reactMining = (g: Mining) => {
      const s = sound.current
      for (const e of g.events as MineEvent[]) {
        switch (e.type) {
          case 'step':
            s?.step()
            break
          case 'dig':
            s?.dig(MATERIAL[e.block])
            break
          case 'mine': {
            const at = cellCenter(e.x, e.y)
            const c = BLOCK_COLORS[e.block]
            for (const color of [c.base, c.dark, c.fleck ?? c.light]) {
              burstBits(bits, Math.random, at.x, at.y, 5, view.cell * 5, { shape: 'square', size: view.cell / 8, color, gravity: view.cell * 25, life: 0.6 })
            }
            s?.blockbreak(MATERIAL[e.block])
            break
          }
          case 'ore': {
            const at = cellCenter(e.x, e.y)
            burstBits(bits, Math.random, at.x, at.y, 8, view.cell * 4, { shape: 'star', size: view.cell / 8, color: '#c8ff6a', life: 0.5 })
            s?.pickup()
            s?.xp(1 + e.points / 10)
            break
          }
          case 'land':
            if (e.rows > 1) s?.place()
            break
          case 'splash':
            s?.bubble?.(1.2)
            s?.swish()
            break
          case 'gravel':
            s?.blockbreak('gravel')
            break
          case 'hurt':
            hurtFlash = 0.6
            shake = Math.max(shake, 0.3)
            setAnnounce(`Hurt: ${e.hearts} hearts left`)
            s?.hurt()
            break
          case 'creeper':
            setAnnounce('A creeper is coming')
            break
          case 'fuse':
            s?.hiss()
            break
          case 'punch':
            s?.dig('dirt')
            break
          case 'kill': {
            const at = cellCenter(e.x, e.y)
            burstBits(bits, Math.random, at.x, at.y, 14, view.cell * 4, { size: view.cell / 5, grow: 20, color: 'rgba(220,220,220,0.7)', life: 0.6 })
            setAnnounce('Creeper defeated')
            s?.pickup()
            s?.xp(1.5)
            unlock('monster-hunter')
            break
          }
          case 'boom': {
            const at = cellCenter(e.x, e.y)
            spawnBit(bits, { x: at.x, y: at.y, shape: 'ring', size: view.cell / 2, grow: view.cell * 12, life: 0.45, color: '#fff' })
            burstBits(bits, Math.random, at.x, at.y, 24, view.cell * 6, { size: view.cell / 3, grow: 30, color: 'rgba(200,200,200,0.6)', life: 1.1 })
            burstBits(bits, Math.random, at.x, at.y, 24, view.cell * 10, { shape: 'square', size: view.cell / 6, color: BLOCK_COLORS.stone.dark, gravity: view.cell * 25 })
            shake = 1
            s?.explode()
            break
          }
          case 'torch':
            s?.place()
            setAnnounce(`Torch placed, ${g.torches} left`)
            break
          case 'pour':
            s?.swish()
            s?.blockbreak('stone')
            setAnnounce(`${e.count} lava turned to obsidian`)
            unlock('hot-stuff')
            break
          case 'deny':
            s?.hmm(true)
            break
        }
      }
      if (g.depth >= DEEP_Y - 1) unlock('deeper')
    }

    const reactRun = (events: RunEvent[], live: boolean, scale: number, ground: number) => {
      const s = live ? sound.current : null
      for (const e of events) {
        switch (e.type) {
          case 'jump':
          case 'land':
            s?.step()
            break
          case 'emerald':
            burstBits(bits, Math.random, PLAYER_X * scale, ground - (e.y + 8) * scale, 10, 200 * scale, { shape: 'star', size: 4 * scale, color: '#41f08a', life: 0.5 })
            s?.pickup()
            s?.xp(1.4)
            break
          case 'milestone':
            s?.xp(2)
            break
          case 'biome': {
            const b = BIOMES.find(x => x.id === e.biome)!
            banner = b.label
            bannerT = 2.5
            if (live) {
              setAnnounce(`Entering ${b.label}`)
              if (e.biome === 'nether') unlock('nether')
            }
            s?.levelup()
            break
          }
          case 'powerup':
            if (live) setAnnounce(e.kind === 'elytra' ? 'Elytra: hold jump in the air to glide' : 'Shield ready')
            s?.pickup()
            s?.chest(true)
            break
          case 'block':
            burstBits(bits, Math.random, PLAYER_X * scale + 20, ground - (e.y + 10) * scale, 10, 200 * scale, { shape: 'square', size: 3 * scale, color: '#c9a36b', life: 0.4 })
            s?.thunk()
            break
          case 'impact':
            burstBits(bits, Math.random, e.x * scale, ground, 16, 260 * scale, { shape: 'square', size: 4 * scale, color: '#ff8a2a', gravity: 600 * scale })
            s?.explode()
            break
          case 'hit':
            if (e.kind === 'creeper' || e.kind === 'fireball') {
              const x = (e.x + 12) * scale
              burstBits(bits, Math.random, x, ground - 25 * scale, 24, 400 * scale, { size: 10 * scale, grow: 30, color: 'rgba(200,200,200,0.6)', life: 1 })
              shake = 1
              s?.explode()
            } else {
              shake = Math.max(shake, 0.4)
            }
            s?.hurt()
            break
        }
      }
    }

    const size = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const cw = canvas.clientWidth
      const ch = canvas.clientHeight
      if (canvas.width !== Math.round(cw * dpr) || canvas.height !== Math.round(ch * dpr)) {
        canvas.width = Math.round(cw * dpr)
        canvas.height = Math.round(ch * dpr)
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.imageSmoothingEnabled = false
      ctx.clearRect(0, 0, cw, ch)
      return { cw, ch }
    }

    const drawMining = (g: Mining, dt: number, cw: number, ch: number) => {
      view.cell = Math.floor(Math.min(cw / COLS, ch / 9))
      view.left = Math.floor((cw - COLS * view.cell) / 2)
      const rows = Math.ceil(ch / view.cell) + 1
      const want = Math.max(-3, g.y - rows * 0.45)
      view.camY += (want - view.camY) * Math.min(1, dt * 6)
      view.px += (g.x - view.px) * Math.min(1, dt * 18)
      view.py += (g.y - view.py) * Math.min(1, dt * 18)
      const moving = Math.abs(g.x - view.px) > 0.05
      view.stride = moving ? view.stride + dt * 14 : 0

      const sky = ctx.createLinearGradient(0, 0, 0, ch)
      sky.addColorStop(0, '#7fb2ff')
      sky.addColorStop(1, '#bcd8ff')
      ctx.fillStyle = sky
      ctx.fillRect(0, 0, cw, ch)
      ctx.save()
      ctx.translate(shake ? (Math.random() - 0.5) * 16 * shake : 0, shake ? (Math.random() - 0.5) * 16 * shake : 0)
      const top = Math.floor(view.camY)
      for (let y = top; y <= top + rows; y++) {
        const sy = (y - view.camY) * view.cell
        for (let x = 0; x < COLS; x++) {
          const sx = view.left + x * view.cell
          const b: Block = y < 0 ? 'air' : g.rows[y]?.[x] ?? 'stone'
          // Dug-out space and water underground show the dark cave wall behind; above the grass, the sky.
          if ((b === 'air' || b === 'water') && y >= 2) {
            ctx.fillStyle = y >= DEEP_Y ? ((x + y) % 2 ? '#1e1e22' : '#1a1a1e') : (x + y) % 2 ? '#2e2e2e' : '#2a2a2a'
            ctx.fillRect(sx, sy, view.cell + 0.5, view.cell + 0.5)
          }
          if (b === 'air') continue
          const target = g.target && g.target.x === x && g.target.y === y
          const crack = target ? g.progress / mineTime(g.pick, b) : 0
          const seed = b === 'lava' || b === 'water' ? y * COLS + x + Math.floor(t * 3) : y * COLS + x
          drawBlock(ctx, sx, sy, view.cell, b, seed, crack)
        }
      }
      // Torches on the walls.
      for (const l of g.lights) {
        const at = cellCenter(l.x, l.y)
        drawTorch(ctx, at.x, at.y + view.cell * 0.3, view.cell * 0.6)
      }
      // The edges of the world, beyond the columns.
      ctx.fillStyle = '#1b1b1b'
      ctx.fillRect(0, 0, view.left, ch)
      ctx.fillRect(view.left + COLS * view.cell, 0, cw, ch)

      for (const c of g.creepers) {
        const at = cellCenter(c.x, c.y)
        const lit = c.fuse >= 0 ? 1 - c.fuse / FUSE_S : 0
        drawCreeper(ctx, at.x, at.y + view.cell / 2, view.cell * 1.6 * (1 + lit * 0.15), lit && Math.sin(t * (10 + lit * 30)) > 0 ? lit : 0)
      }
      // Steve, two blocks tall, his feet on the bottom of his cell.
      const me = cellCenter(view.px, view.py)
      const swing = g.target ? (t * 3) % 1 || 0.01 : 0
      drawSteve(ctx, me.x, me.y + view.cell / 2, view.cell * 1.9, g.face, {
        stride: view.stride, swing, torch: g.torches > 0 && g.y > 6, hurt: g.hurtT > 0, sneak: held().has('down') && !g.target,
      })

      // Deeper is darker, but for the light Steve and the torches give.
      const dark = Math.min(0.88, Math.max(0, (g.y - 4) / 26))
      if (dark > 0 && shadeCtx) {
        if (shade.width !== cw || shade.height !== ch) {
          shade.width = cw
          shade.height = ch
        }
        shadeCtx.globalCompositeOperation = 'source-over'
        shadeCtx.clearRect(0, 0, cw, ch)
        shadeCtx.fillStyle = `rgba(0,0,0,${dark})`
        shadeCtx.fillRect(0, 0, cw, ch)
        shadeCtx.globalCompositeOperation = 'destination-out'
        const light = (x: number, y: number, r: number) => {
          const grad = shadeCtx.createRadialGradient(x, y, r * 0.25, x, y, r)
          grad.addColorStop(0, 'rgba(0,0,0,1)')
          grad.addColorStop(1, 'rgba(0,0,0,0)')
          shadeCtx.fillStyle = grad
          shadeCtx.fillRect(x - r, y - r, r * 2, r * 2)
        }
        light(me.x, me.y - view.cell / 2, view.cell * (g.torches > 0 ? 4.5 : 3.2))
        for (const l of g.lights) {
          const at = cellCenter(l.x, l.y)
          light(at.x, at.y, view.cell * (5 + Math.sin(t * 9 + l.x) * 0.15))
        }
        ctx.drawImage(shade, 0, 0, cw, ch)
      }
      stepBits(bits, dt)
      drawBits(ctx, bits)
      ctx.restore()
      if (hurtFlash > 0) {
        ctx.fillStyle = `rgba(200,0,0,${hurtFlash * 0.5})`
        ctx.fillRect(0, 0, cw, ch)
      }
    }

    const runScale = (cw: number, ch: number) => Math.max(cw / 1000, Math.min(ch / 320, cw / 560))

    /** A husk, a blaze, a fireball, a lava pit or a power-up, at screen x `ox`. */
    const drawObstacle = (r: Run, o: Run['obstacles'][number], scale: number, ground: number, ch: number) => {
      const ox = o.x * scale
      const top = ground - (o.y + o.h) * scale
      switch (o.kind) {
        case 'hole':
        case 'lava':
          ctx.fillStyle = o.kind === 'lava' ? '#d4500b' : '#111'
          ctx.fillRect(ox, ground, o.w * scale, ch - ground)
          if (o.kind === 'lava') {
            ctx.fillStyle = '#ffd64a'
            for (let k = 0; k < 4; k++) ctx.fillRect(ox + ((k * 17 + t * 30) % o.w) * scale, ground + 6 * scale, 4 * scale, 3 * scale)
          }
          return
        case 'creeper':
          drawCreeper(ctx, ox + (o.w / 2) * scale, ground, o.h * scale)
          return
        case 'husk':
          // A desert zombie: sandy skin, torn brown clothes, arms out.
          ctx.fillStyle = '#5c4a2e'
          ctx.fillRect(ox + 6 * scale, ground - 22 * scale, 12 * scale, 22 * scale)
          ctx.fillStyle = '#7a6a48'
          ctx.fillRect(ox + 6 * scale, ground - 40 * scale, 12 * scale, 18 * scale)
          ctx.fillStyle = '#b39c6b'
          ctx.fillRect(ox + 4 * scale, ground - 54 * scale, 16 * scale, 14 * scale)
          ctx.fillRect(ox - 8 * scale, ground - 38 * scale, 16 * scale, 4 * scale)
          ctx.fillStyle = '#222'
          ctx.fillRect(ox + 6 * scale, ground - 48 * scale, 3 * scale, 3 * scale)
          return
        case 'cactus':
          for (let cx = 0; cx < o.w; cx += 22) {
            ctx.fillStyle = '#0f7a2a'
            ctx.fillRect(ox + cx * scale, top, 20 * scale, o.h * scale)
            ctx.fillStyle = '#0a5c1f'
            for (let k = 4; k < o.h; k += 10) ctx.fillRect(ox + (cx + 4) * scale, ground - k * scale, 3 * scale, 3 * scale)
          }
          return
        case 'arrow': {
          const y = ground - (o.y + o.h / 2) * scale
          ctx.strokeStyle = '#8a6136'
          ctx.lineWidth = 2 * scale
          ctx.beginPath()
          ctx.moveTo(ox, y)
          ctx.lineTo(ox + o.w * scale, y)
          ctx.stroke()
          ctx.fillStyle = '#ccc'
          ctx.fillRect(ox - 2 * scale, y - 3 * scale, 5 * scale, 6 * scale)
          ctx.fillStyle = r.biome === 'snow' ? '#9fd8ff' : '#eee'
          ctx.fillRect(ox + (o.w - 6) * scale, y - 4 * scale, 6 * scale, 8 * scale)
          return
        }
        case 'blaze': {
          // A golden head over spinning rods, and its smoke.
          ctx.fillStyle = '#f2c22a'
          ctx.fillRect(ox + 6 * scale, top, 16 * scale, 14 * scale)
          ctx.fillStyle = '#5a3a08'
          ctx.fillRect(ox + 9 * scale, top + 5 * scale, 3 * scale, 2 * scale)
          ctx.fillStyle = '#e8902a'
          for (let k = 0; k < 4; k++) {
            const a = t * 5 + (k * Math.PI) / 2
            ctx.fillRect(ox + (14 + Math.cos(a) * 12) * scale - 2 * scale, top + (20 + Math.sin(a) * 4) * scale, 4 * scale, 9 * scale)
          }
          if (Math.random() < 0.3) spawnBit(bits, { x: ox + 14 * scale, y: top + 26 * scale, vy: 40, size: 4 * scale, grow: 10, life: 0.6, color: 'rgba(60,60,60,0.4)' })
          return
        }
        case 'fireball': {
          const cx = ox + (o.w / 2) * scale
          const cy = ground - (o.y + o.h / 2) * scale
          ctx.fillStyle = '#ff6a1a'
          ctx.fillRect(cx - (o.w / 2) * scale, cy - (o.h / 2) * scale, o.w * scale, o.h * scale)
          ctx.fillStyle = '#ffd64a'
          ctx.fillRect(cx - 5 * scale, cy - 5 * scale, 10 * scale, 10 * scale)
          spawnBit(bits, { x: cx + 6 * scale, y: cy - 4 * scale, vx: 60, vy: -40, size: 3 * scale, grow: 8, life: 0.4, color: 'rgba(255,140,40,0.6)' })
          return
        }
        case 'emerald': {
          const cx = ox + (o.w / 2) * scale
          const cy = ground - (o.y + o.h / 2) * scale + Math.sin(t * 4) * 2 * scale
          const h = (o.h / 2) * scale
          ctx.fillStyle = '#17dd62'
          ctx.beginPath()
          ctx.moveTo(cx, cy - h)
          ctx.lineTo(cx + h * 0.7, cy)
          ctx.lineTo(cx, cy + h)
          ctx.lineTo(cx - h * 0.7, cy)
          ctx.closePath()
          ctx.fill()
          ctx.fillStyle = '#a5ffc9'
          ctx.fillRect(cx - h * 0.25, cy - h * 0.5, h * 0.3, h * 0.5)
          return
        }
        case 'elytra': {
          const cy = ground - (o.y + o.h / 2) * scale + Math.sin(t * 4) * 3 * scale
          ctx.fillStyle = '#8f8fa8'
          ctx.fillRect(ox, cy - 10 * scale, 10 * scale, 20 * scale)
          ctx.fillRect(ox + 12 * scale, cy - 10 * scale, 10 * scale, 20 * scale)
          ctx.fillStyle = '#b8b8d0'
          ctx.fillRect(ox + 2 * scale, cy - 8 * scale, 4 * scale, 14 * scale)
          return
        }
        case 'shield': {
          const cy = ground - (o.y + o.h / 2) * scale + Math.sin(t * 4) * 2 * scale
          ctx.fillStyle = '#9c7a48'
          ctx.fillRect(ox, cy - 11 * scale, o.w * scale, 22 * scale)
          ctx.fillStyle = '#c0c0c0'
          ctx.fillRect(ox + 8 * scale, cy - 11 * scale, 4 * scale, 22 * scale)
          return
        }
      }
    }

    const drawRun = (r: Run, dt: number, cw: number, ch: number) => {
      const scale = runScale(cw, ch)
      const ground = Math.round(ch * 0.78)
      const biome = BIOMES.find(b => b.id === r.biome)!
      // Day into night and back; the Nether has neither.
      const day = r.biome === 'nether' ? 1 : 0.5 + 0.5 * Math.cos(((r.t % DAY_S) / DAY_S) * Math.PI * 2)
      const rgb = (hex: string) => [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16))
      const [dayRgb, nightRgb] = biome.sky.map(rgb)
      ctx.fillStyle = `rgb(${dayRgb.map((v, i) => Math.round(v * day + nightRgb[i] * (1 - day))).join(',')})`
      ctx.fillRect(0, 0, cw, ch)
      if (r.biome !== 'nether') {
        // The sun by day, the moon by night, square, crossing the sky.
        const arc = ((r.t % DAY_S) / DAY_S + 0.25) % 1
        const f = arc < 0.5 ? arc * 2 : (arc - 0.5) * 2
        ctx.fillStyle = arc < 0.5 ? '#fff6a0' : '#e8e8f0'
        ctx.fillRect(cw * f - 18 * scale, ch * 0.55 - Math.sin(f * Math.PI) * ch * 0.45 - 18 * scale, 36 * scale, 36 * scale)
        // Square clouds, drifting slower than the ground.
        ctx.fillStyle = `rgba(255,255,255,${0.5 + 0.35 * day})`
        for (let i = 0; i < 6; i++) {
          const w = (60 + (i % 3) * 40) * scale
          const x = ((i * 260 - r.dist * 0.15) % (cw + 400) + cw + 400) % (cw + 400) - 200
          ctx.fillRect(x, ch * (0.1 + (i % 3) * 0.08), w, 16 * scale)
        }
      } else {
        // The Nether's rock ceiling, glowing from below.
        const tile = 24 * scale
        const off = -((r.dist * 0.5 * scale) % tile)
        for (let x = off; x < cw; x += tile) drawBlock(ctx, x, 0, tile, 'netherrack', Math.floor((x - off) / tile))
        if (r.biome === 'nether') {
          ctx.fillStyle = 'rgba(255,90,20,0.12)'
          ctx.fillRect(0, 0, cw, ch)
        }
      }
      if (r.biome === 'snow' && Math.random() < 0.6) spawnBit(bits, { x: Math.random() * cw, y: 0, vx: -30, vy: 60, size: 2 * scale, life: 4, color: '#fff' })
      ctx.save()
      ctx.translate(shake ? (Math.random() - 0.5) * 14 * shake : 0, shake ? (Math.random() - 0.5) * 14 * shake : 0)
      // The ground: a row of the biome's blocks, scrolling with the run.
      const tile = 24 * scale
      const off = -((r.dist * scale) % tile)
      for (let x = off; x < cw; x += tile) {
        const k = Math.floor((x - off + r.dist * scale) / tile)
        drawBlock(ctx, x, ground, tile, biome.ground, k)
        for (let y = ground + tile; y < ch; y += tile) drawBlock(ctx, x, y, tile, biome.under, k * 7 + y)
      }
      for (const o of r.obstacles) drawObstacle(r, o, scale, ground, ch)
      // Steve: sneaking when he ducks, wings out while gliding, a shield on his arm.
      const sx = PLAYER_X * scale
      const sy = ground - r.y * scale
      if (r.glide > 0 && r.y > 0) {
        ctx.fillStyle = 'rgba(143,143,168,0.9)'
        ctx.fillRect(sx - 26 * scale, sy - 46 * scale, 22 * scale, 10 * scale)
        ctx.fillRect(sx + 4 * scale, sy - 46 * scale, 22 * scale, 10 * scale)
      }
      drawSteve(ctx, sx, sy, PLAYER_H * scale, 1, { stride: r.y > 0 ? 0.8 : r.dist * 0.05, sneak: r.ducking, hurt: !!r.over })
      if (r.shield) {
        ctx.fillStyle = '#9c7a48'
        ctx.fillRect(sx + 8 * scale, sy - (r.ducking ? DUCK_H : 30) * scale, 8 * scale, 16 * scale)
      }
      stepBits(bits, dt)
      drawBits(ctx, bits)
      ctx.restore()
      // Night darkens everything a little.
      if (day < 0.5) {
        ctx.fillStyle = `rgba(0,0,30,${(0.5 - day) * 0.6})`
        ctx.fillRect(0, 0, cw, ch)
      }
      return { scale, ground }
    }

    const show = (next: Hud) => {
      if (!shown || !sameHud(shown, next)) {
        shown = next
        setHud(next)
      }
    }

    const loop = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000)
      last = now
      const live = screenRef.current === 'playing' || screenRef.current === 'paused' || screenRef.current === 'over'
      const paused = screenRef.current !== 'playing'
      const step = paused ? 0 : dt
      t += step
      shake = Math.max(0, shake - step * 2.5)
      hurtFlash = Math.max(0, hurtFlash - step * 1.5)
      bannerT = Math.max(0, bannerT - step)
      if (!bannerT) banner = ''
      const { cw, ch } = size()
      const which = gameRef.current

      if (live && which === 'mining' && mining.current) {
        const g = mining.current
        if (!paused) {
          const h = held()
          const dir = (h.has('right') ? 1 : 0) - (h.has('left') ? 1 : 0)
          const torch = h.has('torch') || taps.current.has('torch')
          const pour = h.has('pour') || taps.current.has('pour')
          const before = g.time
          stepMining(g, { dir: dir as -1 | 0 | 1, down: h.has('down'), up: h.has('up'), torch, pour }, dt)
          // Kept until a fixed step has run with them.
          if (g.time !== before) taps.current.clear()
          reactMining(g)
          show(miningHud(g))
          if (g.over) {
            bankRun(g.ores, { torches: g.torches, buckets: g.buckets })
            end({
              game: 'mining', score: scoreOf(g), reason: g.over,
              stats: [...ORES.map(([b, label]): [string, string] => [label, String(g.ores[b] ?? 0)]), ['Depth', String(g.depth)], ['Creepers', String(g.kills)]],
            })
          }
        }
        drawMining(g, step, cw, ch)
      } else if (live && which === 'runner' && run.current) {
        const r = run.current
        if (!paused) {
          const h = held()
          stepRun(r, { jump: h.has('up'), duck: h.has('down') }, dt)
        }
        const { scale, ground } = drawRun(r, step, cw, ch)
        if (!paused) {
          reactRun(r.events, true, scale, ground)
          show(runHud(r, bestRef.current.runner ?? 0, banner || undefined))
          if (r.over) {
            end({
              game: 'runner', score: scoreOfRun(r), reason: r.over,
              stats: [['Distance', `${Math.floor(r.dist / 24)} blocks`], ['Emeralds', String(r.emeralds)], ['Biome', BIOMES.find(b => b.id === r.biome)!.label]],
            })
          }
        }
      } else {
        // Behind the menus (and the crafting table) Steve runs on his own, silently, and starts over when he trips.
        const a = attract.current
        stepRun(a, autoRunInput(a), dt)
        const { scale, ground } = drawRun(a, dt, cw, ch)
        reactRun(a.events, false, scale, ground)
        if (a.over) attract.current = createRun()
        const c = crafting.current
        if (live && which === 'crafting' && c && !paused) {
          tickCrafting(c, dt)
          show(craftHud(c, bestRef.current.crafting ?? 0))
          if (c.over) {
            end({ game: 'crafting', score: c.score, reason: 'crafting', stats: [['Crafted', String(c.crafted.length)], ['Last order', c.target.label]] })
          }
        }
      }
      frame = requestAnimationFrame(loop)
    }
    frame = requestAnimationFrame(loop)
    return () => cancelAnimationFrame(frame)
  }, [end])

  const press = (action: Action) => ({
    onPointerDown: (e: ReactPointerEvent<HTMLButtonElement>) => {
      e.preventDefault()
      e.currentTarget.setPointerCapture?.(e.pointerId)
      touches.current.set(e.pointerId, action)
    },
    onPointerUp: (e: ReactPointerEvent) => touches.current.delete(e.pointerId),
    onPointerCancel: (e: ReactPointerEvent) => touches.current.delete(e.pointerId),
    onContextMenu: (e: React.MouseEvent) => e.preventDefault(),
  })

  /**
   * Swipes on the play area: a swipe holds its direction until the finger lifts. In Creeper Run a tap
   * jumps at once (and a swipe down ducks); in Mining Run a tap mines towards the side it is on.
   */
  const swipe = {
    onPointerDown: (e: ReactPointerEvent<HTMLCanvasElement>) => {
      if (screenRef.current !== 'playing' || e.pointerType === 'mouse') return
      swipes.current.set(e.pointerId, { x: e.clientX, y: e.clientY })
      if (gameRef.current === 'runner') touches.current.set(e.pointerId, 'up')
    },
    onPointerMove: (e: ReactPointerEvent<HTMLCanvasElement>) => {
      const from = swipes.current.get(e.pointerId)
      if (!from) return
      const dx = e.clientX - from.x
      const dy = e.clientY - from.y
      if (Math.hypot(dx, dy) < SWIPE_PX) return
      touches.current.set(e.pointerId, Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? 'right' : 'left') : dy > 0 ? 'down' : 'up')
    },
    onPointerUp: (e: ReactPointerEvent<HTMLCanvasElement>) => {
      const from = swipes.current.get(e.pointerId)
      swipes.current.delete(e.pointerId)
      // A tap in Mining Run: one step of digging towards that side of the screen, until lifted.
      if (from && gameRef.current === 'mining' && !touches.current.has(e.pointerId)) {
        const action: Action = from.x < window.innerWidth / 2 ? 'left' : 'right'
        keys.current.add(action)
        window.setTimeout(() => keys.current.delete(action), 250)
      }
      touches.current.delete(e.pointerId)
    },
    onPointerCancel: (e: ReactPointerEvent<HTMLCanvasElement>) => {
      swipes.current.delete(e.pointerId)
      touches.current.delete(e.pointerId)
    },
  }

  const label = GAMES.find(g => g.id === game)?.label
  // Every menu button clicks, as the game's do.
  const click = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('.mc-button')) sound.current?.uiclick()
  }

  return (
    <div
      ref={dialogRef}
      className="mc-game"
      role="dialog"
      aria-modal="true"
      aria-label="Minecraft minigames"
      tabIndex={-1}
      data-screen={screen}
      data-game={game}
      onClickCapture={click}
    >
      <canvas ref={canvasRef} className="mc-game-canvas" aria-hidden="true" {...swipe} />

      {screen !== 'menu' && screen !== 'shop' && hud && (
        <div className="mc-game-hud">
          {hud.hearts !== undefined && (
            <span className="mc-hearts" aria-label={`Hearts ${hud.hearts}`}>
              {Array.from({ length: HEARTS }, (_, i) => <i key={i} data-full={i < hud.hearts! || undefined} />)}
            </span>
          )}
          {hud.items.map(([name, value]) => (
            <span key={name} aria-label={`${name} ${value}`}>
              <small>{name}</small> {value}
            </span>
          ))}
        </div>
      )}
      {hud?.banner && screen === 'playing' && <div className="mc-banner" aria-hidden="true">{hud.banner}</div>}
      <p className="mc-sr" aria-live="polite">{announce}</p>

      <button type="button" className="mc-game-close" aria-label="Close the minigames" onClick={onClose}>×</button>

      {screen === 'playing' && game === 'crafting' && craftGame && (
        <MinecraftCrafting
          game={craftGame}
          sound={sound}
          onCrafted={(id, name, points) => {
            setAnnounce(`Crafted ${name}, ${points} points`)
            if (id === 'timestamped') unlock('crafter')
          }}
        />
      )}

      {screen === 'playing' && game !== 'crafting' && (
        <div className="mc-touch">
          {game === 'mining' ? (
            <>
              <div className="mc-touch-group">
                <button type="button" aria-label="Left" {...press('left')}>◀</button>
                <button type="button" aria-label="Right" {...press('right')}>▶</button>
              </div>
              <div className="mc-touch-group">
                <button type="button" aria-label="Torch" {...press('torch')}>🔥</button>
                <button type="button" aria-label="Water bucket" {...press('pour')}>💧</button>
                <button type="button" aria-label="Climb" {...press('up')}>▲</button>
                <button type="button" aria-label="Mine down" {...press('down')}>▼</button>
              </div>
            </>
          ) : (
            <>
              <div className="mc-touch-group">
                <button type="button" aria-label="Duck" {...press('down')}>DUCK</button>
              </div>
              <div className="mc-touch-group">
                <button type="button" aria-label="Jump" {...press('up')}>JUMP</button>
              </div>
            </>
          )}
        </div>
      )}

      {screen === 'menu' && (
        <div className="mc-panel">
          <h2 className="mc-logo">Minecraft</h2>
          <p className="mc-splash" aria-hidden="true">{splash}</p>
          {GAMES.map(g => (
            <div key={g.id} className="mc-choice">
              <button type="button" className="mc-button" onClick={() => start(g.id)}>{g.label}</button>
              <p>{g.blurb}</p>
              <p className="mc-best">{records[g.id] ? `Best: ${records[g.id]}` : 'Not played yet'}</p>
            </div>
          ))}
          <button type="button" className="mc-button" onClick={() => setScreen('shop')}>Mining Shop</button>
          <p className="mc-rotate">Turn your phone sideways for a wider view.</p>
          <dl className="mc-controls">
            <dt>A D / ← →</dt><dd>Mining: walk, or mine sideways</dd>
            <dt>S / ↓</dt><dd>Mining: mine down · Run: duck</dd>
            <dt>W / ↑ / Space</dt><dd>Mining: climb a block, or mine overhead · Run: jump (hold to glide)</dd>
            <dt>E · Q</dt><dd>Mining: place a torch · pour a water bucket</dd>
            <dt>Swipe · tap</dt><dd>The same on a touch screen; tap to jump</dd>
            <dt>Esc</dt><dd>Pause</dd>
          </dl>
          <button type="button" className="mc-button" onClick={onClose}>Quit</button>
        </div>
      )}

      {screen === 'shop' && (
        <Shop
          bank={bank}
          onBuy={ok => {
            setBank(readBank())
            if (ok) sound.current?.pickup()
            else sound.current?.hmm(true)
          }}
          onBack={() => setScreen('menu')}
        />
      )}

      {screen === 'paused' && (
        <div className="mc-panel">
          <h2>Paused</h2>
          <p>{label}</p>
          <button type="button" className="mc-button" onClick={() => setScreen('playing')}>Back to Game</button>
          <button type="button" className="mc-button" onClick={() => start(game)}>Restart</button>
          <button type="button" className="mc-button" onClick={() => setScreen('menu')}>Main menu</button>
          <button type="button" className="mc-button" onClick={onClose}>Quit</button>
        </div>
      )}

      {screen === 'over' && result && (
        <div className="mc-panel mc-panel--died" data-reason={result.reason}>
          <h2>{result.reason === 'time' || result.reason === 'crafting' ? "Time's up!" : 'You died!'}</h2>
          <p>{result.message}</p>
          <p className="mc-score">Score: <b>{result.score}</b>{result.best && <span className="mc-new-best"> New best!</span>}</p>
          <dl className="mc-stats">
            {result.stats.map(([name, value]) => (
              <div key={name}><dt>{name}</dt><dd>{value}</dd></div>
            ))}
          </dl>
          {result.game === 'mining' && <p className="mc-best">The ores went into your bank: spend them in the Mining Shop.</p>}
          <button type="button" className="mc-button" onClick={() => start(result.game)}>{result.reason === 'crafting' ? 'Play again' : 'Respawn'}</button>
          <button type="button" className="mc-button" onClick={() => setScreen('menu')}>Main menu</button>
          <button type="button" className="mc-button" onClick={onClose}>Quit</button>
        </div>
      )}
    </div>
  )
}

const ORE_LABEL: Record<string, string> = { coal: 'coal', iron: 'iron', gold: 'gold', diamond: 'diamonds' }
const costText = (cost: Partial<Record<string, number>>) =>
  Object.entries(cost).map(([ore, n]) => `${n} ${ORE_LABEL[ore]}`).join(', ') || 'free'

/** Mining Run's shop: the bank of ores, better pickaxes, torches and water buckets. */
function Shop({ bank, onBuy, onBack }: { bank: Bank; onBuy: (ok: boolean) => void; onBack: () => void }) {
  const order = PICKS.map(p => p.id)
  return (
    <div className="mc-panel mc-shop">
      <h2>Mining Shop</h2>
      <p className="mc-bank" aria-label="Your bank">
        {(['coal', 'iron', 'gold', 'diamond'] as const).map(ore => (
          <span key={ore} data-ore={ore}>{bank.ores[ore]} {ORE_LABEL[ore]}</span>
        ))}
      </p>
      <p>Pickaxe: <b>{PICKS.find(p => p.id === bank.pick)!.label}</b> · Torches: <b>{bank.torches}</b> · Buckets: <b>{bank.buckets}</b></p>
      <ul className="mc-shop-list">
        {PICKS.slice(1).map(p => {
          const owned = order.indexOf(p.id) <= order.indexOf(bank.owned)
          return (
            <li key={p.id}>
              <span>{p.label} <small>mines {p.speed}× as fast{p.id === 'diamond' ? ', breaks obsidian' : ''}</small></span>
              <button type="button" className="mc-button" disabled={owned || !canBuyPick(bank, p.id)} onClick={() => onBuy(buyPick(p.id))}>
                {owned ? 'Owned' : `Buy: ${costText(p.cost)}`}
              </button>
            </li>
          )
        })}
        {SUPPLIES.map(s => (
          <li key={s.id}>
            <span>{s.label} <small>{s.id === 'torches' ? 'light the dark (E)' : 'lava to obsidian (Q)'}</small></span>
            <button type="button" className="mc-button" disabled={!canBuySupply(bank, s.id)} onClick={() => onBuy(buySupply(s.id))}>
              Buy: {costText(s.cost)}
            </button>
          </li>
        ))}
      </ul>
      <button type="button" className="mc-button" onClick={onBack}>Back</button>
    </div>
  )
}
