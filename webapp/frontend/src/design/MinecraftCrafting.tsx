import { type DragEvent, type KeyboardEvent as ReactKeyboardEvent, type RefObject, useState } from 'react'
import { type Crafting, ITEMS, type Item, craft, matchRecipe, pattern, place, showsHint } from './craftingGame'
import type { Sound } from './effects/sound'

const label = (item: Item | null) => (item ? ITEMS.find(i => i.id === item)!.label : 'empty')

interface MinecraftCraftingProps {
  game: Crafting
  sound: RefObject<Sound | null>
  /** An order was crafted, for the stats and the announcement. */
  onCrafted: (recipeId: string, label: string, points: number) => void
}

/**
 * The crafting table: the order and (after a while) its recipe, the 3x3 grid, the result slot and the
 * inventory. Pick an ingredient, then click the cells it goes in; or drag ingredients onto the grid.
 * A click on a cell with that ingredient, a right-click or Delete empties it. Everything is a button,
 * so the grid works from the keyboard too.
 */
export function MinecraftCrafting({ game, sound, onCrafted }: MinecraftCraftingProps) {
  const [held, setHeld] = useState<Item>('planks')
  const [, setVersion] = useState(0)
  const [wrong, setWrong] = useState(0)
  const redraw = () => setVersion((v: number) => v + 1)

  const put = (cell: number, item: Item | null) => {
    place(game, cell, item)
    if (item) sound.current?.place()
    else sound.current?.dig('dirt')
    redraw()
  }

  const onCell = (cell: number) => put(cell, game.grid[cell] === held ? null : held)

  const onCraft = () => {
    const r = craft(game)
    if (r.result === 'ok') {
      sound.current?.pickup()
      sound.current?.xp(1.3)
      onCrafted(r.recipe.id, r.recipe.label, r.points)
    } else if (r.result === 'wrong') {
      sound.current?.hmm(true)
      setWrong((n: number) => n + 1)
    }
    redraw()
  }

  const made = matchRecipe(game.grid)
  const hint = showsHint(game)
  const shape = pattern(game.target)

  return (
    <div className="mc-crafting">
      <div className="mc-order">
        <p>Craft: <b>{game.target.label}</b></p>
        <div className="mc-book" aria-label="Recipe book">
          {hint ? (
            <>
              <div className="mc-book-grid" style={{ '--cols': shape[0].length } as React.CSSProperties} aria-hidden="true">
                {shape.flat().map((item, i) => <span key={i} className="mc-item" data-item={item ?? undefined} />)}
              </div>
              <p className="mc-sr">
                {shape.map((row, y) => `Row ${y + 1}: ${row.map(label).join(', ')}`).join('. ')}
              </p>
            </>
          ) : (
            <p className="mc-book-closed">The recipe book opens in a moment…</p>
          )}
        </div>
      </div>

      <div className="mc-table">
        <div className="mc-grid" role="group" aria-label="Crafting grid" data-wrong={wrong || undefined} key={wrong}>
          {game.grid.map((item, i) => (
            <button
              key={i}
              type="button"
              className="mc-slot"
              aria-label={`Slot ${i + 1}: ${label(item)}`}
              onClick={() => onCell(i)}
              onContextMenu={(e: React.MouseEvent) => {
                e.preventDefault()
                put(i, null)
              }}
              onKeyDown={(e: ReactKeyboardEvent) => {
                if (e.key === 'Delete' || e.key === 'Backspace') {
                  e.preventDefault()
                  put(i, null)
                }
              }}
              onDragOver={(e: DragEvent) => e.preventDefault()}
              onDrop={(e: DragEvent) => {
                e.preventDefault()
                const item = e.dataTransfer.getData('text/x-mc-item') as Item
                if (ITEMS.some(it => it.id === item)) put(i, item)
              }}
            >
              {item && <span className="mc-item" data-item={item} aria-hidden="true" />}
            </button>
          ))}
        </div>
        <span className="mc-arrow" aria-hidden="true">➜</span>
        <button
          type="button"
          className="mc-slot mc-result"
          aria-label={made ? `Craft ${made.label}` : 'Craft (nothing yet)'}
          onClick={onCraft}
          data-ready={made?.id === game.target.id || undefined}
        >
          {made && <span className="mc-result-name">{made.label}</span>}
        </button>
        <button
          type="button"
          className="mc-button mc-clear"
          onClick={() => {
            game.grid.forEach((_, i) => place(game, i, null))
            redraw()
          }}
        >
          Clear
        </button>
      </div>

      <div className="mc-inventory" role="radiogroup" aria-label="Inventory">
        {ITEMS.map(it => (
          <button
            key={it.id}
            type="button"
            role="radio"
            aria-checked={held === it.id}
            className="mc-slot"
            title={it.label}
            aria-label={it.label}
            draggable
            onDragStart={(e: DragEvent) => {
              e.dataTransfer.setData('text/x-mc-item', it.id)
              setHeld(it.id)
            }}
            onClick={() => {
              setHeld(it.id)
              sound.current?.uiclick()
            }}
          >
            <span className="mc-item" data-item={it.id} aria-hidden="true" />
          </button>
        ))}
      </div>
    </div>
  )
}
