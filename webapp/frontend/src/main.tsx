import * as React from 'react'
import { createRoot } from 'react-dom/client'
import { defineCustomElements } from '@siemens/ix/loader'
import { addIcons } from '@siemens/ix-icons'
import {
  iconAbout,
  iconAuditReport,
  iconCertificate,
  iconChartDiagrams,
  iconCheckboxes,
  iconChevronLeft,
  iconChevronRight,
  iconClearFilter,
  iconClock,
  iconClose,
  iconCode,
  iconDocument,
  iconDownload,
  iconError,
  iconFilter,
  iconInfo,
  iconInkPen,
  iconKey,
  iconLightDark,
  iconList,
  iconMinus,
  iconPalette,
  iconQuestion,
  iconRefresh,
  iconSearch,
  iconShieldCheck,
  iconSort,
  iconSortAscending,
  iconSortDescending,
  iconSuccess,
  iconTrashcan,
  iconWarning,
  iconWarningRhomb,
} from '@siemens/ix-icons/icons'

import './index.css'
import './styles/designs/soft.css'
import './styles/designs/accent.css'
import './styles/designs/colors.css'
import './styles/designs/layouts.css'
import './styles/designs/themes.css'
import './styles/designs/effects.css'
import './styles/designs/previews.css'
import './styles/app.css'
import App from './App'

defineCustomElements(window)

// Register the icons used by the app so ix-icon resolves them by name without fetching SVG assets.
addIcons({
  iconAbout,
  iconAuditReport,
  iconCertificate,
  iconChartDiagrams,
  iconCheckboxes,
  iconChevronLeft,
  iconChevronRight,
  iconClearFilter,
  iconClock,
  iconClose,
  iconCode,
  iconDocument,
  iconDownload,
  iconError,
  iconFilter,
  iconInfo,
  iconInkPen,
  iconKey,
  iconLightDark,
  iconList,
  iconMinus,
  iconPalette,
  iconQuestion,
  iconRefresh,
  iconSearch,
  iconShieldCheck,
  iconSort,
  iconSortAscending,
  iconSortDescending,
  iconSuccess,
  iconTrashcan,
  iconWarning,
  iconWarningRhomb,
})

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
