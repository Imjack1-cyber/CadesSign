import type { ReactNode } from 'react'
import { IxContentHeader, IxTypography } from '@siemens/ix-react'
import { PHONE_QUERY, useMediaQuery } from '../../design/useMediaQuery'

interface PageHeaderProps {
  title: string
  subtitle?: string
  children?: ReactNode
}

/**
 * IxContentHeader with a subtitle that stays readable on phones. IX keeps the subtitle on one line
 * (white-space: nowrap inside its shadow DOM), so on narrow screens it is rendered below instead,
 * where it can wrap.
 */
export function PageHeader({ title, subtitle, children }: PageHeaderProps) {
  const phone = useMediaQuery(PHONE_QUERY)
  return (
    <div className="page-header">
      <IxContentHeader variant="primary" headerTitle={title} headerSubtitle={phone ? undefined : subtitle}>
        {children}
      </IxContentHeader>
      {phone && subtitle && <IxTypography format="body-sm" textColor="soft">{subtitle}</IxTypography>}
    </div>
  )
}
