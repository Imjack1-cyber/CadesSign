import { useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { AppIcon, Glyph } from './IosIcons'
import { type SearchAction, type SearchFile, type SearchItem, search } from './iosSearch'
import { useIosModal } from './useIosModal'

interface IosSpotlightProps {
  files: readonly SearchFile[]
  onRun: (action: SearchAction) => void
  onClose: () => void
}

function ItemIcon({ item, size }: { item: SearchItem; size: number }) {
  if (item.app) return <AppIcon app={item.app} size={size} />
  return <span className="ios-spot-glyph" style={{ width: size, height: size }}><Glyph name={item.glyph ?? 'search'} size={size * 0.55} /></span>
}

/**
 * Spotlight: a glass search field over the blurred screen that finds actions, apps, files, settings
 * and help as you type, the best match first as the Top Hit. Arrow keys move through the results,
 * Enter opens one, Tab completes the field with it, Escape closes.
 */
export function IosSpotlight({ files, onRun, onClose }: IosSpotlightProps) {
  const ref = useRef<HTMLDivElement>(null)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const listId = useId()
  useIosModal(ref, onClose)

  const result = useMemo(() => search(query, files), [query, files])
  const flat = [...(result.top ? [result.top] : []), ...result.groups.flatMap(g => g.items)]
  const at = Math.min(active, Math.max(0, flat.length - 1))
  const optionId = (i: number) => `${listId}-${i}`

  const run = (item: SearchItem | undefined) => {
    if (!item) return
    onClose()
    onRun(item.action)
  }

  const onKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case 'ArrowDown': setActive(Math.min(flat.length - 1, at + 1)); break
      case 'ArrowUp': setActive(Math.max(0, at - 1)); break
      case 'Enter': run(flat[at]); break
      case 'Tab':
        if (!flat[at] || e.shiftKey) return
        setQuery(flat[at].title)
        break
      default: return
    }
    e.preventDefault()
  }

  let index = 0
  const option = (item: SearchItem, top = false) => {
    const i = index++
    return (
      <div
        key={item.id}
        id={optionId(i)}
        role="option"
        aria-selected={i === at}
        className={`ios-spot-item${top ? ' ios-spot-top' : ''}`}
        onPointerMove={() => i !== at && setActive(i)}
        onClick={() => run(item)}
      >
        <ItemIcon item={item} size={top ? 52 : 32} />
        <span className="ios-spot-text">
          <b>{item.title}</b>
          {item.subtitle && <span>{item.subtitle}</span>}
        </span>
        {i === at && <Glyph name="chevron-right" size={14} />}
      </div>
    )
  }

  return (
    <div className="ios-scrim ios-scrim--spotlight" onPointerDown={e => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className="ios-spotlight" role="dialog" aria-modal="true" aria-label="Spotlight">
        <div className="ios-spot-field ios-glass">
          <Glyph name="search" size={20} />
          <input
            data-autofocus
            type="search"
            role="combobox"
            aria-expanded={flat.length > 0}
            aria-controls={listId}
            aria-activedescendant={flat.length ? optionId(at) : undefined}
            aria-label="Search"
            placeholder="Spotlight Search"
            autoComplete="off"
            spellCheck={false}
            value={query}
            onChange={e => {
              setQuery(e.target.value)
              setActive(0)
            }}
            onKeyDown={onKey}
          />
          {query && (
            <button type="button" className="ios-spot-clear" aria-label="Clear search" onClick={() => setQuery('')}>
              <Glyph name="x-circle" size={18} />
            </button>
          )}
        </div>
        {(flat.length > 0 || query) && (
          <div className="ios-spot-results ios-glass">
            <div id={listId} role="listbox" aria-label="Results">
              {result.top && (
                <div role="group" aria-label="Top Hit" className="ios-spot-section">
                  <div className="ios-spot-heading" aria-hidden="true">Top Hit</div>
                  {option(result.top, true)}
                </div>
              )}
              {result.groups.map(g => (
                <div key={g.section} role="group" aria-label={g.section} className="ios-spot-section">
                  <div className="ios-spot-heading" aria-hidden="true">{g.section}</div>
                  {g.items.map(item => option(item))}
                </div>
              ))}
            </div>
            {!flat.length && <p className="ios-spot-none">No Results for “{query}”</p>}
          </div>
        )}
      </div>
    </div>
  )
}
