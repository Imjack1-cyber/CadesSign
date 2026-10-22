/* oxlint-disable react/only-export-components -- test-only mocks, fast refresh does not apply */
/*
 * Lightweight DOM stand-ins for @siemens/ix-react used by unit tests. Stencil web components do
 * not render in jsdom, so each mock maps the IX props and custom events the app relies on
 * (onValueChange, onFilesChanged, ...) onto plain elements that Testing Library can drive.
 */
import type { ReactNode } from 'react'

type P = Record<string, any> & { children?: ReactNode }

const box = (testId: string) => ({ children, label, ...rest }: P) => (
  <div data-testid={testId} aria-label={rest['aria-label']} role={rest.role}>
    {label && <span>{label}</span>}
    {children}
  </div>
)
const text = (testId: string) => ({ children, id }: P) => <span data-testid={testId} id={id}>{children}</span>

export const IxApplication = box('IxApplication')
export const IxApplicationHeader = ({ name, children }: P) => <header><span>{name}</span>{children}</header>
export const IxMenu = box('IxMenu')
export const IxMenuItem = ({ children, onClick, active }: P) => <button aria-current={active ? 'page' : undefined} onClick={onClick}>{children}</button>
export const IxMenuAbout = box('IxMenuAbout')
export const IxMenuAboutItem = box('IxMenuAboutItem')
export const IxContent = box('IxContent')
export const IxDropdownButton = ({ children, label, ariaLabelDropdownButton, disabled }: P) => (
  <div data-testid="IxDropdownButton" role="menu" aria-label={ariaLabelDropdownButton} aria-disabled={disabled ? 'true' : undefined}>
    <span>{label}</span>{children}
  </div>
)
export const IxDivider = () => <hr />
export const IxDropdownHeader = ({ label }: P) => <span>{label}</span>
// A plain action item (no `checked`) is a button here; IX gives it the menuitem role inside its own menu.
export const IxDropdownItem = ({ label, checked, disabled, onClick }: P) =>
  checked === undefined
    ? <button disabled={disabled} onClick={onClick}>{label}</button>
    : <button role="menuitemradio" aria-checked={!!checked} disabled={disabled} onClick={onClick}>{label}</button>
export const IxTabs = ({ children }: P) => <div role="tablist">{children}</div>
export const IxTabItem = ({ children, tabKey, onClick, ...rest }: P) => (
  <button role="tab" data-tab-key={tabKey} aria-label={rest['aria-label']} aria-selected={rest.selected} onClick={onClick}>{children}</button>
)
export const IxContentHeader = ({ headerTitle, headerSubtitle, children }: P) => (
  <div data-testid="IxContentHeader"><h1>{headerTitle}</h1>{headerSubtitle && <p>{headerSubtitle}</p>}{children}</div>
)
export const IxWorkflowSteps = ({ children }: P) => <ol data-testid="IxWorkflowSteps">{children}</ol>
export const IxWorkflowStep = ({ children, status, disabled }: P) => (
  <li data-testid="IxWorkflowStep" data-status={status} aria-disabled={disabled ? 'true' : undefined}>{children}</li>
)
export const IxCard = box('IxCard')
export const IxCardContent = box('IxCardContent')
export const IxBlind = box('IxBlind')
export const IxTypography = text('IxTypography')
export const IxPill = text('IxPill')
export const IxIcon = () => null
export const IxSpinner = () => <span data-testid="IxSpinner" />
export const IxFieldLabel = ({ children, htmlFor }: P) => <label htmlFor={htmlFor}>{children}</label>
export const IxMessageBar = ({ children, type, role }: P) => <div data-testid="IxMessageBar" data-type={type} role={role}>{children}</div>
export const IxKpi = ({ label, value }: P) => <div data-testid="IxKpi"><span>{label}</span><span>{value}</span></div>
export const IxKeyValueList = box('IxKeyValueList')
export const IxKeyValue = ({ label, value }: P) => <div data-testid="IxKeyValue">{label}: {value}</div>
export const IxPagination = ({ count }: P) => <nav data-testid="IxPagination" data-count={count} />

export const IxButton = ({ children, onClick, disabled, loading, ...rest }: P) => (
  <button
    onClick={onClick} disabled={disabled} aria-busy={loading ? 'true' : undefined}
    aria-label={rest['aria-label']} aria-expanded={rest['aria-expanded']} aria-haspopup={rest['aria-haspopup']}
  >
    {children}
  </button>
)
export const IxIconButton = ({ onClick, title, disabled, ...rest }: P) => <button aria-label={rest['aria-label']} title={title} disabled={disabled} onClick={onClick} />
export const IxToggleButton = ({ children, pressed, onPressedChange }: P) => (
  <button aria-pressed={!!pressed} onClick={() => onPressedChange?.(new CustomEvent('pressedChange', { detail: !pressed }))}>{children}</button>
)
export const IxActionCard = ({ heading, subheading, selected, onClick, onDoubleClick, onKeyDown, ...rest }: P) => (
  <button
    role="radio" aria-checked={!!selected} data-value={rest['data-value']}
    onClick={onClick} onDoubleClick={onDoubleClick} onKeyDown={onKeyDown}
  >
    {heading}
    <span>{subheading}</span>
  </button>
)
export const IxSelect = ({ children, label, value, onValueChange, name }: P) => (
  <select aria-label={label} name={name} value={value} onChange={e => onValueChange?.(new CustomEvent('valueChange', { detail: e.target.value }))}>
    {children}
  </select>
)
export const IxSelectItem = ({ value, label }: P) => <option value={value}>{label}</option>
export const IxInput = ({ label, value, type, name, disabled, onValueChange }: P) => (
  <input aria-label={label} type={type ?? 'text'} name={name} value={value} disabled={disabled}
    onChange={e => onValueChange?.(new CustomEvent('valueChange', { detail: e.target.value }))} />
)
export const IxDateInput = ({ label, value, onValueChange }: P) => (
  <input aria-label={label} value={value} onChange={e => onValueChange?.(new CustomEvent('valueChange', { detail: e.target.value }))} />
)
export const IxCheckbox = ({ label, checked, onCheckedChange }: P) => (
  <label><input type="checkbox" checked={!!checked} onChange={e => onCheckedChange?.(new CustomEvent('checkedChange', { detail: e.target.checked }))} />{label}</label>
)
export const IxUpload = ({ id, selectFileText, accept, onFilesChanged }: P) => (
  <input type="file" data-testid={id} aria-label={selectFileText} accept={accept}
    onChange={e => onFilesChanged?.(new CustomEvent('filesChanged', { detail: Array.from(e.target.files ?? []) }))} />
)
export const IxEmptyState = ({ header, subHeader, action, onActionClick }: P) => (
  <div data-testid="IxEmptyState">
    <p>{header}</p>
    {subHeader && <p>{subHeader}</p>}
    {action && <button onClick={() => onActionClick?.()}>{action}</button>}
  </div>
)

export const showToast = () => Promise.resolve()
