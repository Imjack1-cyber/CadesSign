import { describe, expect, it } from 'vitest'
import {
  BEDROCK_Y, COLS, CREEPER_POINTS, DEEP_Y, FALL_HURT_ROWS, FUSE_S, HARDNESS, HEARTS, type MineEvent, type MineInput, type Mining,
  NO_MINE_INPUT, ORE_POINTS, STEP, blockAt, createMining, ensureRows, mineTime, scoreOf, setBlock, tick,
} from '../../design/miningGame'
import {
  BIOMES, EMERALD_POINTS, GLIDE_S, NO_RUN_INPUT, type Obstacle, PLAYER_HW, PLAYER_X, PX_PER_POINT, type Run, type RunEvent,
  type RunInput, SHAPES, START_SPEED, STEP as RUN_STEP, autoRunInput, biomeAt, createRun, scoreOfRun, tickRun,
} from '../../design/creeperGame'
import {
  BASE_POINTS, HINT_S, RECIPES, ROUND_S, craft, createCrafting, emptyGrid, layOut, matchRecipe, place, showsHint, tickCrafting,
} from '../../design/craftingGame'

/** Deterministic PRNG so failures reproduce. */
function seeded(seed: number) {
  return () => {
    seed = (seed * 16807) % 2147483647
    return (seed - 1) / 2147483646
  }
}

/** Runs `seconds` of fixed steps with the given input, collecting every event. */
function mine(g: Mining, seconds: number, input: MineInput = NO_MINE_INPUT) {
  const events: MineEvent[] = []
  for (let i = 0; i < Math.round(seconds / STEP); i++) {
    g.events = []
    tick(g, input)
    events.push(...g.events)
  }
  return events
}

/**
 * Steve underground with his feet at row `y`, column 5, in a tunnel of air two blocks high (columns
 * `from` to `to`) cut through solid stone, so nothing random falls in or opens up around him.
 */
function tunnel(y = 10, from = 5, to = 5, g = createMining(seeded(3))) {
  ensureRows(g, y + 12)
  for (let row = y - 5; row <= y + 10; row++) for (let x = 0; x < COLS; x++) setBlock(g, x, row, 'stone')
  for (let x = from; x <= to; x++) {
    setBlock(g, x, y, 'air')
    setBlock(g, x, y - 1, 'air')
  }
  g.x = 5
  g.y = y
  return g
}

const right: MineInput = { dir: 1, down: false, up: false }
const down: MineInput = { dir: 0, down: true, up: false }

describe('mining run', () => {
  it('generates the same world from the same seed: sky, grass, dirt, then stone with ores', () => {
    const a = createMining(seeded(7))
    const b = createMining(seeded(7))
    ensureRows(a, 80)
    ensureRows(b, 80)
    expect(a.rows).toEqual(b.rows)
    expect(a.rows[0].every(x => x === 'air')).toBe(true)
    expect(a.rows[1].every(x => x === 'grass')).toBe(true)
    expect(a.rows.slice(20).flat()).toContain('coal')
    // Caves open up below the dirt, and some cells hold water.
    expect(a.rows.slice(6, 80).flat().filter(b => b === 'air').length).toBeGreaterThan(20)
  })

  it('has mineshafts, deepslate in the deep dark and ragged bedrock at the bottom', () => {
    const g = createMining(seeded(11))
    ensureRows(g, BEDROCK_Y + 1)
    expect(g.rows.slice(10, DEEP_Y).flat()).toContain('planks')
    expect(g.rows.slice(DEEP_Y, BEDROCK_Y - 4).flat()).toContain('deepslate')
    expect(g.rows.slice(0, DEEP_Y).flat()).not.toContain('deepslate')
    expect(g.rows[BEDROCK_Y].every(b => b === 'bedrock')).toBe(true)
    expect(g.rows[BEDROCK_Y - 1]).toContain('bedrock')
  })

  it('mining down takes the block its hardness in time, then Steve falls into the hole and lands', () => {
    const g = createMining(seeded(1))
    setBlock(g, 5, 2, 'stone')
    const early = mine(g, HARDNESS.grass - 0.05, down)
    expect(blockAt(g, 5, 1)).toBe('grass')
    expect(early.some(e => e.type === 'dig')).toBe(true)
    const events = mine(g, 0.4, NO_MINE_INPUT)
    expect(blockAt(g, 5, 1)).toBe('grass')
    // Letting go resets the progress; it takes the full time again.
    const done = mine(g, HARDNESS.grass + 0.05, down)
    expect(events.some(e => e.type === 'mine')).toBe(false)
    expect(done).toContainEqual({ type: 'mine', x: 5, y: 1, block: 'grass' })
    const fall = mine(g, 0.3)
    expect(g.y).toBe(1)
    expect(fall).toContainEqual({ type: 'land', rows: 1, water: false })
    expect(g.depth).toBe(0)
  })

  it('ores score their points; the score adds the depth', () => {
    const g = tunnel()
    setBlock(g, 6, 10, 'diamond')
    const events = mine(g, HARDNESS.diamond + 0.05, right)
    expect(events).toContainEqual({ type: 'ore', x: 6, y: 10, block: 'diamond', points: ORE_POINTS.diamond })
    expect(g.ores.diamond).toBe(1)
    g.depth = 9
    expect(scoreOf(g)).toBe(ORE_POINTS.diamond! + 9)
  })

  it('walks along a tunnel and climbs a block with up held', () => {
    const g = tunnel(10, 5, 7)
    mine(g, 0.5, right)
    expect(g.x).toBe(7)
    // A step up: the block ahead is solid, the rows above Steve and above it are air.
    setBlock(g, 7, 8, 'air')
    setBlock(g, 8, 9, 'air')
    setBlock(g, 8, 8, 'air')
    mine(g, 0.3, { dir: 1, down: false, up: true })
    expect([g.x, g.y]).toEqual([8, 9])
  })

  it('bedrock never breaks', () => {
    const g = tunnel()
    setBlock(g, 5, 11, 'bedrock')
    const events = mine(g, 3, down)
    expect(blockAt(g, 5, 11)).toBe('bedrock')
    expect(events.some(e => e.type === 'mine')).toBe(false)
  })

  it('walking into lava ends the run', () => {
    const g = tunnel(10, 5, 6)
    setBlock(g, 6, 10, 'lava')
    const events = mine(g, 0.5, right)
    expect(g.over).toBe('lava')
    expect(events).toContainEqual({ type: 'over', reason: 'lava' })
  })

  it('gravel with nothing under it drops, and on his head it costs a heart', () => {
    const g = tunnel()
    setBlock(g, 5, 8, 'gravel')
    const events = mine(g, 0.2)
    expect(events).toContainEqual({ type: 'gravel', x: 5, y: 9 })
    expect(g.hearts).toBe(HEARTS - 1)
    expect(blockAt(g, 5, 8)).toBe('air')
  })

  it('mines the block in front of his head when his feet are clear, and up alone mines the one overhead', () => {
    const g = tunnel()
    setBlock(g, 6, 10, 'air')
    mine(g, HARDNESS.stone + 0.05, right)
    expect(blockAt(g, 6, 9)).toBe('air')
    expect(g.x).toBe(6)
    mine(g, HARDNESS.stone + 0.05, { dir: 0, down: false, up: true })
    expect(blockAt(g, 6, 8)).toBe('air')
  })

  it('a long fall costs a heart; a short one does not', () => {
    const g = tunnel()
    for (let y = 11; y <= 10 + FALL_HURT_ROWS; y++) setBlock(g, 5, y, 'air')
    const events = mine(g, 1)
    expect(events).toContainEqual({ type: 'land', rows: FALL_HURT_ROWS, water: false })
    expect(g.hearts).toBe(HEARTS - 1)
    expect(g.depth).toBe(9 + FALL_HURT_ROWS)
  })

  it('water breaks a fall: Steve sinks slowly and lands unhurt', () => {
    const g = tunnel()
    for (let y = 11; y <= 10 + FALL_HURT_ROWS + 2; y++) setBlock(g, 5, y, y > 10 + FALL_HURT_ROWS - 1 ? 'water' : 'air')
    const events = mine(g, 4)
    expect(events.some(e => e.type === 'splash')).toBe(true)
    expect(g.hearts).toBe(HEARTS)
    expect(g.y).toBe(10 + FALL_HURT_ROWS + 2)
  })

  it('a better pickaxe mines faster; obsidian needs a diamond one', () => {
    expect(mineTime('iron', 'stone')).toBeLessThan(mineTime('wood', 'stone'))
    expect(mineTime('iron', 'obsidian')).toBe(Infinity)
    const g = tunnel(10, 5, 5, createMining(seeded(3), { pick: 'diamond', torches: 0, buckets: 0 }))
    setBlock(g, 6, 10, 'obsidian')
    mine(g, mineTime('diamond', 'obsidian') + 0.05, right)
    expect(blockAt(g, 6, 10)).toBe('air')
  })

  it('places a torch once per press while it has some, and refuses when out', () => {
    const g = tunnel(10, 5, 5, createMining(seeded(3), { pick: 'wood', torches: 1, buckets: 0 }))
    const events = mine(g, 0.5, { ...NO_MINE_INPUT, torch: true })
    expect(g.lights).toEqual([{ x: 5, y: 9 }])
    expect(g.torches).toBe(0)
    expect(events.filter(e => e.type === 'torch')).toHaveLength(1)
    mine(g, STEP)
    expect(mine(g, STEP, { ...NO_MINE_INPUT, torch: true })).toContainEqual({ type: 'deny' })
  })

  it('a water bucket turns the lava around Steve into obsidian', () => {
    const g = tunnel(10, 5, 5, createMining(seeded(3), { pick: 'wood', torches: 0, buckets: 1 }))
    setBlock(g, 6, 10, 'lava')
    setBlock(g, 4, 11, 'lava')
    const events = mine(g, STEP, { ...NO_MINE_INPUT, pour: true })
    expect(events).toContainEqual({ type: 'pour', count: 2 })
    expect(blockAt(g, 6, 10)).toBe('obsidian')
    expect(g.buckets).toBe(0)
  })

  it('a creeper next to Steve lights its fuse and explodes, costing two hearts and the blocks around it', () => {
    const g = tunnel(10, 5, 6)
    g.creepers.push({ x: 6, y: 10, moveT: 1, fuse: -1, hp: 3, fallT: 0 })
    const events = mine(g, FUSE_S + 0.1)
    expect(events.map(e => e.type)).toEqual(expect.arrayContaining(['fuse', 'boom', 'hurt']))
    expect(g.hearts).toBe(HEARTS - 2)
    expect(g.creepers).toHaveLength(0)
    expect(blockAt(g, 7, 10)).toBe('air')
  })

  it('three punches knock a creeper back and kill it before it blows', () => {
    const g = tunnel(10, 5, 10)
    g.creepers.push({ x: 6, y: 10, moveT: 1, fuse: -1, hp: 3, fallT: 0 })
    const events = mine(g, 1.5, right)
    expect(g.kills).toBe(1)
    expect(g.points).toBe(CREEPER_POINTS)
    expect(events.filter(e => e.type === 'punch')).toHaveLength(3)
    expect(events.some(e => e.type === 'boom')).toBe(false)
  })

  it('creepers come down the tunnel on their own once Steve is deep enough', () => {
    const g = tunnel(10, 0, COLS - 1)
    const events = mine(g, 20)
    expect(events.some(e => e.type === 'creeper')).toBe(true)
  })

  it('ends when the time is up', () => {
    const g = tunnel()
    g.time = STEP * 2
    mine(g, STEP * 3)
    expect(g.over).toBe('time')
  })
})

/** Runs `seconds` of fixed steps, the input given per step, collecting every event. */
function runFor(r: Run, seconds: number, input: RunInput | ((i: number) => RunInput) = NO_RUN_INPUT) {
  const events: RunEvent[] = []
  for (let i = 0; i < Math.round(seconds / RUN_STEP); i++) {
    r.events = []
    tickRun(r, typeof input === 'function' ? input(i) : input)
    events.push(...r.events)
  }
  return events
}

/** A run with nothing coming but `o`, which starts `ahead` px in front of Steve. */
function facing(kind: Obstacle['kind'], ahead: number, extra: Partial<Obstacle> = {}) {
  const r = createRun(seeded(5))
  r.gap = 1e9
  r.obstacles.push({ kind, x: PLAYER_X + PLAYER_HW + ahead, ...SHAPES[kind], ...extra })
  return r
}

const jumpOnce = (i: number): RunInput => ({ jump: i === 0, duck: false })

describe('creeper run', () => {
  it('a creeper ends a run that does not jump', () => {
    const r = facing('creeper', 60)
    const events = runFor(r, 1)
    expect(r.over).toBe('creeper')
    expect(events.some(e => e.type === 'hit')).toBe(true)
  })

  it('jumping in time clears a creeper and lands again', () => {
    const r = facing('creeper', 60)
    const events = runFor(r, 0.8, jumpOnce)
    expect(r.over).toBeNull()
    expect(events.map(e => e.type)).toEqual(['jump', 'land'])
    expect(r.obstacles).toHaveLength(1)
    expect(r.obstacles[0].x + r.obstacles[0].w).toBeLessThan(PLAYER_X - PLAYER_HW)
  })

  it('holding jump jumps once, not again on landing', () => {
    const r = createRun(seeded(1))
    r.gap = 1e9
    const events = runFor(r, 2, { jump: true, duck: false })
    expect(events.filter(e => e.type === 'jump')).toHaveLength(1)
  })

  it('ducking passes under an arrow; standing, it hits', () => {
    const ducked = facing('arrow', 120)
    runFor(ducked, 1, { jump: false, duck: true })
    expect(ducked.over).toBeNull()
    const stood = facing('arrow', 120)
    runFor(stood, 1)
    expect(stood.over).toBe('arrow')
  })

  it('a hole swallows a runner who does not jump it', () => {
    const r = facing('hole', 40)
    runFor(r, 1)
    expect(r.over).toBe('hole')
    const jumped = facing('hole', 40)
    runFor(jumped, 1.2, jumpOnce)
    expect(jumped.over).toBeNull()
  })

  it('an emerald adds its points', () => {
    const r = facing('emerald', 40, { y: 12 })
    const events = runFor(r, 0.5)
    expect(events.some(e => e.type === 'emerald')).toBe(true)
    expect(r.emeralds).toBe(1)
    expect(r.bonus).toBe(EMERALD_POINTS)
  })

  it('speeds up as it goes and scores the distance', () => {
    const r = createRun(seeded(1))
    r.gap = 1e9
    const events = runFor(r, 10)
    expect(r.speed).toBeGreaterThan(START_SPEED)
    expect(scoreOfRun(r)).toBe(Math.floor(r.dist / PX_PER_POINT))
    expect(events.some(e => e.type === 'milestone')).toBe(true)
  })

  it('obstacles keep coming, and the player behind the menus gets past them', () => {
    const r = createRun(seeded(2))
    let seen = 0
    for (let i = 0; i < Math.round(30 / RUN_STEP) && !r.over; i++) {
      r.events = []
      const before = r.obstacles.length
      tickRun(r, autoRunInput(r))
      seen += Math.max(0, r.obstacles.length - before)
    }
    expect(seen).toBeGreaterThan(10)
    expect(r.t).toBeGreaterThan(15)
  })

  it('crosses into the next biome as the score rises, and the Nether sends its own', () => {
    expect(biomeAt(0).id).toBe('plains')
    expect(biomeAt(BIOMES[3].from).id).toBe('nether')
    const r = createRun(seeded(4))
    r.gap = 1e9
    r.dist = (BIOMES[1].from - 1) * PX_PER_POINT
    const events = runFor(r, 0.1)
    expect(events).toContainEqual({ type: 'biome', biome: 'desert' })
    r.biome = 'nether'
    r.t = 30
    r.gap = 0
    const kinds = new Set<string>()
    for (let i = 0; i < 40; i++) {
      r.obstacles = []
      r.gap = 0
      r.events = []
      tickRun(r, NO_RUN_INPUT)
      for (const o of r.obstacles) kinds.add(o.kind)
    }
    expect([...kinds].some(k => k === 'blaze' || k === 'fireball' || k === 'lava')).toBe(true)
    expect(kinds.has('creeper')).toBe(false)
  })

  it('a shield takes one arrow; the next one hits', () => {
    const r = facing('shield', 20)
    runFor(r, 0.2)
    expect(r.shield).toBe(1)
    r.obstacles.push({ kind: 'arrow', x: PLAYER_X + PLAYER_HW + 60, ...SHAPES.arrow })
    const events = runFor(r, 0.5)
    expect(events.some(e => e.type === 'block')).toBe(true)
    expect(r.over).toBeNull()
    r.obstacles.push({ kind: 'arrow', x: PLAYER_X + PLAYER_HW + 60, ...SHAPES.arrow })
    runFor(r, 0.5)
    expect(r.over).toBe('arrow')
  })

  it('an elytra lets Steve glide while jump is held, and runs out', () => {
    const r = facing('elytra', 20, { y: 0 })
    runFor(r, 0.2)
    expect(r.glide).toBeGreaterThan(0)
    const plain = createRun(seeded(5))
    plain.gap = 1e9
    runFor(r, 1, i => ({ jump: i === 0 || i > 10, duck: false }))
    runFor(plain, 1, i => ({ jump: i === 0 || i > 10, duck: false }))
    expect(r.y).toBeGreaterThan(plain.y)
    runFor(r, GLIDE_S)
    expect(r.glide).toBe(0)
  })

  it('a ghast fireball comes down to head height where Steve runs', () => {
    const r = createRun(seeded(6))
    r.gap = 1e9
    r.obstacles.push({ kind: 'fireball', x: 1000, ...SHAPES.fireball, vy: (SHAPES.fireball.y - 36) / ((1000 - PLAYER_X) / (START_SPEED + SHAPES.fireball.vx!)) })
    runFor(r, 3)
    expect(r.over).toBe('fireball')
  })
})

describe('crafting', () => {
  const recipe = (id: string) => RECIPES.find(r => r.id === id)!

  it('matches a shaped recipe anywhere in the grid and mirrored, and nothing else', () => {
    const grid = emptyGrid()
    // A torch in the bottom-right column: coal over a stick.
    grid[5] = 'coal'
    grid[8] = 'stick'
    expect(matchRecipe(grid)?.id).toBe('torch')
    grid[0] = 'planks'
    expect(matchRecipe(grid)).toBeNull()
    expect(matchRecipe(emptyGrid())).toBeNull()
    // The bow faces either way.
    const bow = layOut(recipe('bow'))
    const mirrored = [0, 1, 2].flatMap(y => [2, 1, 0].map(x => bow[y * 3 + x]))
    expect(matchRecipe(mirrored)?.id).toBe('bow')
  })

  it('tells the signing recipes apart: a seal, and a seal with a timestamp', () => {
    expect(matchRecipe(layOut(recipe('sealed')))?.label).toBe('Sealed Document')
    expect(matchRecipe(layOut(recipe('timestamped')))?.label).toBe('Timestamped Signature')
  })

  it('every recipe is reachable: its own layout matches it', () => {
    for (const r of RECIPES) expect(matchRecipe(layOut(r))?.id).toBe(r.id)
  })

  it('crafting the order scores, with a bonus for speed, and brings a new order on a clear grid', () => {
    const c = createCrafting(seeded(1))
    const first = c.target
    expect(craft(c)).toEqual({ result: 'empty' })
    c.grid = layOut(first)
    const quick = craft(c)
    expect(quick.result).toBe('ok')
    expect(quick.result === 'ok' && quick.points).toBeGreaterThan(BASE_POINTS)
    expect(c.target.id).not.toBe(first.id)
    expect(c.grid.every(cell => cell === null)).toBe(true)
    // Once the recipe book shows the shape, only the base points.
    tickCrafting(c, HINT_S)
    expect(showsHint(c)).toBe(true)
    c.grid = layOut(c.target)
    const slow = craft(c)
    expect(slow.result === 'ok' && slow.points).toBe(BASE_POINTS)
    expect(c.crafted).toHaveLength(2)
  })

  it('the wrong item is refused and the grid kept; the round ends with the clock', () => {
    const c = createCrafting(seeded(2))
    const other = RECIPES.find(r => r.id !== c.target.id)!
    c.grid = layOut(other)
    expect(craft(c)).toEqual({ result: 'wrong' })
    expect(c.grid.some(Boolean)).toBe(true)
    tickCrafting(c, ROUND_S)
    expect(c.over).toBe(true)
    place(c, 0, 'planks')
    expect(craft(c)).toEqual({ result: 'empty' })
  })
})
