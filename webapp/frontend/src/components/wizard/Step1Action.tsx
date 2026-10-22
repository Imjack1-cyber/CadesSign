import { IxActionCard, IxTypography } from '@siemens/ix-react'
import type { KeyboardEvent, MouseEvent } from 'react'
import type { Action } from './types'
import { TOUCH_QUERY, useMediaQuery } from '../../design/useMediaQuery'

interface Step1ActionProps {
  action: Action
  onSelect: (a: Action) => void
  /** Selects and moves on in one go: double-click, double-tap, or Enter on the selected card. */
  onContinue: (a: Exclude<Action, ''>) => void
}

/**
 * Whether a pointer event landed on text, including text inside IX's shadow DOM: some element on
 * the event's composed path has a text node whose line boxes contain the point. A double-click
 * there selects a word as usual; anywhere else on the card (icon, empty space) it continues.
 * (Chrome selects the nearest word even on empty space, so the selection itself cannot tell.)
 */
function isOverText(e: MouseEvent): boolean {
  const range = document.createRange()
  if (typeof range.getClientRects !== 'function') return false
  return e.composedPath().some((node: EventTarget) =>
    node instanceof Element && Array.from(node.childNodes).some(child => {
      if (child.nodeType !== Node.TEXT_NODE || !child.textContent?.trim()) return false
      range.selectNodeContents(child)
      return Array.from(range.getClientRects()).some(r =>
        e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom)
    }))
}

const CHOICES: Array<{ value: Exclude<Action, ''>; icon: string; heading: string; subheading: string }> = [
  { value: 'sign', icon: 'ink-pen', heading: 'Sign a document', subheading: 'Create a CAdES B, B-T, B-LT or B-LTA signature (.p7s) for any file.' },
  { value: 'verify', icon: 'shield-check', heading: 'Verify a signature', subheading: 'Validate a .p7s signature and get a simple or full ETSI validation report.' },
]

export function Step1Action({ action, onSelect, onContinue }: Step1ActionProps) {
  const touch = useMediaQuery(TOUCH_QUERY)
  return (
    <div className="stack">
      <div className="grid grid-wide" role="radiogroup" aria-label="Choose action">
        {CHOICES.map(c => (
          <IxActionCard
            key={c.value}
            data-value={c.value}
            role="radio"
            aria-checked={action === c.value}
            tabIndex={0}
            icon={c.icon}
            heading={c.heading}
            subheading={c.subheading}
            selected={action === c.value}
            variant={action === c.value ? 'primary' : 'outline'}
            onClick={() => onSelect(c.value)}
            onDoubleClick={(e: MouseEvent<HTMLElement>) => {
              if (isOverText(e.nativeEvent)) return
              // Chrome has already selected the nearest word; that is not what this double-click was for.
              window.getSelection?.()?.removeAllRanges()
              onContinue(c.value)
            }}
            onKeyDown={(e: KeyboardEvent) => {
              if (e.key === 'Enter' && action === c.value) {
                e.preventDefault()
                onContinue(c.value)
              } else if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onSelect(c.value)
              }
            }}
          />
        ))}
      </div>
      <IxTypography format="label-sm" textColor="soft">
        {touch
          ? 'Tip: double-tap a card, or press Enter on the selected one, to continue.'
          : 'Tip: double-click a card next to its text, or press Enter on the selected one, to continue. Double-clicking a word selects it as usual.'}
      </IxTypography>
    </div>
  )
}
