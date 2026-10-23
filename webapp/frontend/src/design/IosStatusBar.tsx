import { Glyph } from './IosIcons'
import { type Battery, dateText, LOW_BATTERY, type Network, timeText } from './iosDevice'

interface IosStatusBarProps {
  phone: boolean
  now: Date
  battery: Battery
  network: Network
  busy: boolean
  focus: boolean
  silent: boolean
  onNotifications: () => void
  onControl: () => void
}

/** Wi-Fi: three arcs, lit up to the signal's strength. */
function Wifi({ network }: { network: Network }) {
  if (!network.online) return <Glyph name="wifi-slash" size={16} />
  return (
    <svg className="ios-wifi" viewBox="0 0 18 13" width="17" height="12" aria-hidden="true">
      <path d="M9 12.6L6.6 10a3.4 3.4 0 0 1 4.8 0z" />
      <path d="M4.3 7.6a6.6 6.6 0 0 1 9.4 0L12.3 9a4.6 4.6 0 0 0-6.6 0z" opacity={network.bars >= 2 ? 1 : 0.3} />
      <path d="M2 5.2a9.9 9.9 0 0 1 14 0l-1.4 1.5a7.9 7.9 0 0 0-11.2 0z" opacity={network.bars >= 3 ? 1 : 0.3} />
    </svg>
  )
}

/** The cellular signal on a phone: four bars of rising height. */
function Cellular({ network }: { network: Network }) {
  const lit = network.online ? network.bars + 1 : 0
  return (
    <svg className="ios-cellular" viewBox="0 0 18 12" width="17" height="11" aria-hidden="true">
      {[0, 1, 2, 3].map(i => <rect key={i} x={i * 4.6} y={9 - i * 3} width="3.2" height={3 + i * 3} rx="1" opacity={i < lit ? 1 : 0.3} />)}
    </svg>
  )
}

/** The battery: its level as a fill (yellow when low, green while charging) and, on a phone, the percentage inside. */
function BatteryIcon({ battery, inside }: { battery: Battery; inside: boolean }) {
  const level = battery.level ?? 1
  const tone = battery.charging ? 'charging' : level <= LOW_BATTERY ? 'low' : 'normal'
  return (
    <span className="ios-battery" data-tone={tone} aria-hidden="true">
      <svg viewBox="0 0 27 13" width="27" height="13">
        <rect x="0.5" y="0.5" width="23" height="12" rx="3.8" fill="none" stroke="currentColor" opacity="0.4" />
        <rect x="2" y="2" width={Math.max(1.5, 20 * level)} height="9" rx="2.4" className="ios-battery-fill" />
        <path d="M25 4.5v4a2 2 0 0 0 0-4z" fill="currentColor" opacity="0.4" />
        {battery.charging && <path d="M12.5 1.5L8 7.2h3.4l-1.2 4.3L15 5.8h-3.4z" className="ios-battery-bolt" />}
      </svg>
      {inside && battery.level !== null && !battery.charging && <b>{Math.round(level * 100)}</b>}
    </span>
  )
}

/**
 * The status bar along the top. On iPad: time and date on the left, and on the right Focus, the
 * activity spinner while a request runs, Wi-Fi and the battery with its percentage. On a phone the
 * middle is the Dynamic Island's, so the time sits left and the signal, Wi-Fi and battery right.
 * Its halves are the way into Notification Center (left) and Control Center (right).
 */
export function IosStatusBar({ phone, now, battery, network, busy, focus, silent, onNotifications, onControl }: IosStatusBarProps) {
  const pct = battery.level === null ? null : Math.round(battery.level * 100)
  const state = [
    network.online ? 'Wi-Fi connected' : 'Offline',
    pct === null ? null : `battery ${pct}%${battery.charging ? ', charging' : ''}`,
    focus ? 'Do Not Disturb on' : null,
    silent ? 'Silent' : null,
  ].filter(Boolean).join(', ')

  return (
    <div className="ios-status" data-phone={phone || undefined}>
      <button type="button" className="ios-status-half ios-status-left" aria-label={`Notification Center, ${timeText(now)}`} onClick={onNotifications}>
        <time dateTime={now.toISOString()}>{timeText(now)}</time>
        {!phone && <span className="ios-status-date">{dateText(now)}</span>}
      </button>
      <button type="button" className="ios-status-half ios-status-right" aria-label={`Control Center: ${state}`} onClick={onControl}>
        {busy && <span className="ios-spinner" aria-hidden="true" />}
        {focus && <Glyph name="moon" size={13} />}
        {silent && !phone && <Glyph name="bell-slash" size={13} />}
        {phone && <Cellular network={network} />}
        <Wifi network={network} />
        {!phone && pct !== null && <span className="ios-status-pct">{pct}%</span>}
        <BatteryIcon battery={battery} inside={phone} />
      </button>
    </div>
  )
}
