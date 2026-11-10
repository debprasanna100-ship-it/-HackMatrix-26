import { Outlet } from 'react-router-dom'
import EmergencyBanner from './components/EmergencyBanner'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import { LanguageProvider } from './context/LanguageContext'

export default function App() {
  return (
    <LanguageProvider>
      <div className="min-h-screen flex flex-col bg-surface-canvas text-on-surface">
        {/* Urgent National 1930 Cyber Crime Advisory Header */}
        <EmergencyBanner />

        {/* Top App Bar & Brand Header */}
        <Navbar />

        {/* Main Content Area */}
        <main className="flex-1 flex flex-col">
          <Outlet />
        </main>

        {/* Civic Coordination Footer */}
        <Footer />
      </div>
    </LanguageProvider>
  )
}
