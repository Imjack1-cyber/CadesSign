import { useState, useEffect } from 'react'
import { AppShell, AboutPage, type View } from './components/layout'
import { Wizard } from './components/wizard'
import { Dashboard } from './components/dashboard/Dashboard'
import { DesignProvider } from './design/DesignProvider'
import { useDesign } from './design/useDesign'

const VIEWS: readonly View[] = ['wizard', 'dashboard', 'about']

const viewFromHash = (): View => {
  const hash = typeof window !== 'undefined' ? window.location.hash.replace('#', '') : ''
  return (VIEWS as readonly string[]).includes(hash) ? (hash as View) : 'wizard'
}

function Routes() {
  const { active } = useDesign()
  const [hashView, setHashView] = useState<View>(viewFromHash)
  // About is a page only in the top-nav layout; the side menu shows it as an overlay instead.
  const view: View = hashView === 'about' && active.layout.nav !== 'topnav' ? 'wizard' : hashView

  // The URL hash is the source of truth, so views can be linked to and browser back/forward works.
  useEffect(() => {
    const onHashChange = () => setHashView(viewFromHash())
    window.addEventListener('hashchange', onHashChange)
    if (!window.location.hash) {
      window.history.replaceState(null, '', '#wizard')
    }
    // Pick up a hash that changed between the first render and this effect.
    onHashChange()
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const navigate = (next: View) => {
    window.location.hash = next
  }

  return (
    <AppShell view={view} onViewChange={navigate}>
      {view === 'wizard' && <Wizard />}
      {view === 'dashboard' && <Dashboard onNavigateToWizard={() => navigate('wizard')} />}
      {view === 'about' && <AboutPage />}
    </AppShell>
  )
}

export default function App() {
  return (
    <DesignProvider>
      <Routes />
    </DesignProvider>
  )
}
