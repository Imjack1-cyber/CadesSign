import type { ColorId, LayoutId, ThemeId } from './designs'

interface ThumbnailProps {
  layout: LayoutId
  /** The palette to draw; omitted for a theme, which brings its own. */
  colors?: ColorId
  theme?: ThemeId
}

/**
 * A miniature of the app: header, navigation, step line, two cards and a button. previews.css
 * draws the arrangement from `data-layout` and the palette from `data-colors` or `data-theme`, so
 * every option in the Appearance panel can show what it looks like before it is chosen.
 */
export function Thumbnail({ layout, colors, theme }: ThumbnailProps) {
  return (
    <span className="thumb" data-layout={layout} data-colors={colors} data-theme={theme} aria-hidden="true">
      <span className="thumb-header" />
      <span className="thumb-nav"><i /><i /><i /></span>
      <span className="thumb-body">
        <span className="thumb-steps"><i /><i /><i /><i /></span>
        <span className="thumb-cards"><span className="thumb-card" /><span className="thumb-card" /></span>
        <span className="thumb-button" />
      </span>
    </span>
  )
}
