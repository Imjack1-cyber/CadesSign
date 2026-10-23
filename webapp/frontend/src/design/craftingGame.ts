/**
 * Crafting, the Minecraft theme's third minigame: a 3x3 crafting grid and a timed round of orders.
 * Each order names an item; lay the ingredients out in its recipe's shape and craft it. As in the game,
 * a shaped recipe may sit anywhere in the grid and may be mirrored. Most recipes are the game's own;
 * two are this app's: a key over a document seals it, and a clock under them timestamps the signature.
 * After a while the recipe book shows the shape. Plain state, like the other minigames; the grid and
 * its buttons are drawn by MinecraftCrafting.tsx.
 */

export type Item =
  | 'planks' | 'stick' | 'cobblestone' | 'coal' | 'iron' | 'diamond' | 'string' | 'paper' | 'document' | 'key' | 'clock'

/** The ingredients, in the order the inventory shows them. */
export const ITEMS: ReadonlyArray<{ id: Item; label: string }> = [
  { id: 'planks', label: 'Oak Planks' },
  { id: 'stick', label: 'Stick' },
  { id: 'cobblestone', label: 'Cobblestone' },
  { id: 'coal', label: 'Coal' },
  { id: 'iron', label: 'Iron Ingot' },
  { id: 'diamond', label: 'Diamond' },
  { id: 'string', label: 'String' },
  { id: 'paper', label: 'Paper' },
  { id: 'document', label: 'Document' },
  { id: 'key', label: 'Private Key' },
  { id: 'clock', label: 'Clock' },
]

export interface Recipe {
  id: string
  label: string
  /** Rows of the shape, one character per cell, '.' empty; `key` says which item each letter is. */
  shape: readonly string[]
  key: Readonly<Record<string, Item>>
}

export const RECIPES: readonly Recipe[] = [
  { id: 'crafting-table', label: 'Crafting Table', shape: ['PP', 'PP'], key: { P: 'planks' } },
  { id: 'stick', label: 'Sticks', shape: ['P', 'P'], key: { P: 'planks' } },
  { id: 'torch', label: 'Torches', shape: ['C', 'S'], key: { C: 'coal', S: 'stick' } },
  { id: 'chest', label: 'Chest', shape: ['PPP', 'P.P', 'PPP'], key: { P: 'planks' } },
  { id: 'furnace', label: 'Furnace', shape: ['CCC', 'C.C', 'CCC'], key: { C: 'cobblestone' } },
  { id: 'stone-pickaxe', label: 'Stone Pickaxe', shape: ['CCC', '.S.', '.S.'], key: { C: 'cobblestone', S: 'stick' } },
  { id: 'iron-pickaxe', label: 'Iron Pickaxe', shape: ['III', '.S.', '.S.'], key: { I: 'iron', S: 'stick' } },
  { id: 'diamond-pickaxe', label: 'Diamond Pickaxe', shape: ['DDD', '.S.', '.S.'], key: { D: 'diamond', S: 'stick' } },
  { id: 'diamond-sword', label: 'Diamond Sword', shape: ['D', 'D', 'S'], key: { D: 'diamond', S: 'stick' } },
  { id: 'bow', label: 'Bow', shape: ['.St', 'S.t', '.St'], key: { S: 'stick', t: 'string' } },
  { id: 'shield', label: 'Shield', shape: ['PIP', 'PPP', '.P.'], key: { P: 'planks', I: 'iron' } },
  { id: 'book', label: 'Book', shape: ['p', 'p', 'p'], key: { p: 'paper' } },
  { id: 'sealed', label: 'Sealed Document', shape: ['K', 'D'], key: { K: 'key', D: 'document' } },
  { id: 'timestamped', label: 'Timestamped Signature', shape: ['K', 'D', 'C'], key: { K: 'key', D: 'document', C: 'clock' } },
]

/** A grid: nine cells, row by row, each an item or empty. */
export type Grid = Array<Item | null>

export const ROUND_S = 90
/** Seconds into an order before the recipe book shows its shape. */
export const HINT_S = 12
/** Points for an order: a base, and a bonus that runs out over BONUS_S. */
export const BASE_POINTS = 10
const BONUS_POINTS = 10
const BONUS_S = 20

export const emptyGrid = (): Grid => Array.from({ length: 9 }, () => null)

/** A recipe's shape as rows of items, padded to a rectangle. */
export function pattern(r: Recipe): Array<Array<Item | null>> {
  const w = Math.max(...r.shape.map(row => row.length))
  return r.shape.map(row => Array.from({ length: w }, (_, i) => (row[i] && row[i] !== '.' ? r.key[row[i]] : null)))
}

/** The grid cut down to the rectangle around its items. */
function trimmed(grid: Grid): Array<Array<Item | null>> {
  const cells = [0, 1, 2].map(y => [0, 1, 2].map(x => grid[y * 3 + x]))
  const rows = cells.map(r => r.some(Boolean))
  const cols = [0, 1, 2].map(x => cells.some(r => r[x]))
  const y0 = rows.indexOf(true)
  if (y0 < 0) return []
  const y1 = rows.lastIndexOf(true)
  const x0 = cols.indexOf(true)
  const x1 = cols.lastIndexOf(true)
  return cells.slice(y0, y1 + 1).map(r => r.slice(x0, x1 + 1))
}

const same = (a: Array<Array<Item | null>>, b: Array<Array<Item | null>>) =>
  a.length === b.length && a.every((row, y) => row.length === b[y].length && row.every((c, x) => c === b[y][x]))

/** The recipe the grid makes, anywhere in the grid and either way round, or null. */
export function matchRecipe(grid: Grid): Recipe | null {
  const laid = trimmed(grid)
  if (!laid.length) return null
  return RECIPES.find(r => {
    const p = pattern(r)
    return same(laid, p) || same(laid, p.map(row => [...row].reverse()))
  }) ?? null
}

export interface Crafting {
  time: number
  score: number
  /** Orders crafted so far, by recipe id. */
  crafted: string[]
  target: Recipe
  /** Seconds the current order has been open. */
  orderT: number
  grid: Grid
  over: boolean
  rnd: () => number
}

function nextTarget(c: Pick<Crafting, 'rnd'> & { target?: Recipe }) {
  const choices = RECIPES.filter(r => r.id !== c.target?.id)
  return choices[Math.floor(c.rnd() * choices.length)]
}

export function createCrafting(rnd: () => number = Math.random): Crafting {
  return { time: ROUND_S, score: 0, crafted: [], target: nextTarget({ rnd }), orderT: 0, grid: emptyGrid(), over: false, rnd }
}

/** Runs the clock; the round ends when it is out. */
export function tickCrafting(c: Crafting, dt: number) {
  if (c.over) return
  c.time = Math.max(0, c.time - dt)
  c.orderT += dt
  if (!c.time) c.over = true
}

/** Puts an item in a cell, or empties it with null. */
export function place(c: Crafting, cell: number, item: Item | null) {
  if (c.over || cell < 0 || cell > 8) return
  c.grid[cell] = item
}

export const showsHint = (c: Crafting) => c.orderT >= HINT_S

/**
 * Takes what the grid makes. The order: points (fewer once the hint is showing or time has passed),
 * a new order and an empty grid. Anything else is 'wrong' and the grid stays, or 'empty'.
 */
export function craft(c: Crafting): { result: 'ok'; points: number; recipe: Recipe } | { result: 'wrong' | 'empty' } {
  if (c.over) return { result: 'empty' }
  const made = matchRecipe(c.grid)
  if (!c.grid.some(Boolean)) return { result: 'empty' }
  if (!made || made.id !== c.target.id) return { result: 'wrong' }
  const bonus = showsHint(c) ? 0 : Math.round(BONUS_POINTS * Math.max(0, 1 - c.orderT / BONUS_S))
  const points = BASE_POINTS + bonus
  c.score += points
  c.crafted.push(made.id)
  c.target = nextTarget(c)
  c.orderT = 0
  c.grid = emptyGrid()
  return { result: 'ok', points, recipe: made }
}

/** Lays a recipe out in the grid's top-left corner. */
export function layOut(r: Recipe): Grid {
  const grid = emptyGrid()
  pattern(r).forEach((row, y) => row.forEach((item, x) => { grid[y * 3 + x] = item }))
  return grid
}
