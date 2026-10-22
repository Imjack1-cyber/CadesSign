import { useEffect, useState } from 'react'

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => typeof window.matchMedia === 'function' && window.matchMedia(query).matches)
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return
    const mql = window.matchMedia(query)
    const onChange = () => setMatches(mql.matches)
    onChange()
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [query])
  return matches
}

/** Phone width, matching IX's small breakpoint where the header collapses into its overflow menu. */
export const PHONE_QUERY = '(max-width: 40rem)'
/** A finger rather than a mouse: no hover, no drag and drop. */
export const TOUCH_QUERY = '(pointer: coarse)'
