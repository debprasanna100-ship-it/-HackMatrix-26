import { useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { LANGUAGES } from '../context/languages'
import { useLanguage } from '../context/useLanguage'
import AuthBar from './AuthBar'

export default function Navbar() {
  const { language, setLanguage, t } = useLanguage()
  const [langOpen, setLangOpen] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <header className="bg-surface-card shadow-sm sticky top-0 z-40 border-b border-border-subtle">
      <div className="w-full flex items-center justify-between px-space-md md:px-margin max-w-[1200px] mx-auto py-3">
        {/* Brand Logo */}
        <Link
          to="/"
          className="flex items-center gap-space-xs text-headline-sm font-headline-sm font-extrabold text-primary-container group"
        >
          <span className="material-symbols-outlined text-primary-container text-[28px] material-symbols-fill group-hover:scale-105 transition-transform">
            verified_user
          </span>
          <span>TrustLens</span>
          <span className="text-[10px] font-label-sm bg-primary-fixed text-primary px-1.5 py-0.5 rounded ml-1 tracking-wider uppercase font-bold">
            Bharat
          </span>
        </Link>

        {/* Navigation Links (Desktop) */}
        <nav className="hidden md:flex items-center space-x-6">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              `font-label-lg text-label-lg pb-1 transition-colors flex items-center gap-1.5 ${
                isActive
                  ? 'text-primary-container border-b-2 border-primary-container font-bold'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`
            }
          >
            <span className="material-symbols-outlined text-[18px]">search_check</span>
            {t.scanUrl}
          </NavLink>

          <NavLink
            to="/tracker"
            className={({ isActive }) =>
              `font-label-lg text-label-lg pb-1 transition-colors flex items-center gap-1.5 ${
                isActive
                  ? 'text-primary-container border-b-2 border-primary-container font-bold'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`
            }
          >
            <span className="material-symbols-outlined text-[18px]">track_changes</span>
            {t.incidentTracker}
          </NavLink>

          <NavLink
            to="/reports"
            className={({ isActive }) =>
              `font-label-lg text-label-lg pb-1 transition-colors flex items-center gap-1.5 ${
                isActive
                  ? 'text-primary-container border-b-2 border-primary-container font-bold'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`
            }
          >
            <span className="material-symbols-outlined text-[18px]">radar</span>
            {t.threatRadar}
          </NavLink>

          <NavLink
            to="/report-fraud"
            className={({ isActive }) =>
              `font-label-lg text-label-lg pb-1 transition-colors flex items-center gap-1.5 ${
                isActive
                  ? 'text-danger-red border-b-2 border-danger-red font-bold'
                  : 'text-on-surface-variant hover:text-danger-red'
              }`
            }
          >
            <span className="material-symbols-outlined text-[18px]">emergency_home</span>
            {t.reportFraud}
          </NavLink>

          <NavLink
            to="/verify"
            className={({ isActive }) =>
              `font-label-lg text-label-lg pb-1 transition-colors flex items-center gap-1.5 ${
                isActive
                  ? 'text-primary-container border-b-2 border-primary-container font-bold'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`
            }
          >
            <span className="material-symbols-outlined text-[18px]">verified</span>
            {t.verifyOnChain}
          </NavLink>
        </nav>

        {/* Trailing Action Cluster */}
        <div className="flex items-center gap-space-sm">
          {/* Multilingual Switcher Pill */}
          <div className="relative">
            <button
              onClick={() => setLangOpen(!langOpen)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-border-subtle bg-surface hover:bg-surface-container-low text-on-surface font-label-md text-label-md transition-colors"
              title="Change Language / भाषा चुनें"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px]">translate</span>
              <span className="font-semibold hidden sm:inline">
                {LANGUAGES.find((l) => l.code === language)?.nativeName ?? 'English'} / भाषा
              </span>
              <span className="material-symbols-outlined text-[14px]">arrow_drop_down</span>
            </button>

            {langOpen && (
              <div
                className="absolute right-0 mt-1 w-56 bg-surface-card border border-border-subtle rounded-xl shadow-lg p-2 z-50 animate-in fade-in"
                onClick={() => setLangOpen(false)}
              >
                <div className="text-[11px] font-bold text-outline px-2 py-1 uppercase tracking-wider">
                  Select Language / भाषा चुनें
                </div>
                {LANGUAGES.map((l) => (
                  <button
                    key={l.code}
                    onClick={() => setLanguage(l.code)}
                    type="button"
                    className={`w-full flex items-center justify-between px-2 py-1.5 rounded text-sm text-left transition-colors ${
                      language === l.code
                        ? 'text-primary font-bold bg-primary-fixed/30 hover:bg-primary-fixed/50'
                        : 'text-on-surface hover:bg-surface-container-low'
                    }`}
                  >
                    <span>{l.nativeName} ({l.name})</span>
                    {language === l.code && (
                      <span className="text-xs bg-primary text-white rounded px-1.5 py-0.5">
                        Active
                      </span>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Emergency Scam Report CTA */}
          <Link
            to="/report-fraud"
            className="hidden sm:inline-flex items-center gap-1.5 bg-danger-red hover:bg-red-600 text-on-error font-label-md text-label-md px-3.5 py-1.5 rounded-lg font-bold shadow-sm transition-all active:scale-95"
          >
            <span className="material-symbols-outlined text-[16px]">report</span>
            {t.emergencyReport}
          </Link>

          {/* Compact AuthBar */}
          <div className="hidden lg:block">
            <AuthBar />
          </div>

          {/* Mobile menu toggle */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            type="button"
            className="md:hidden p-2 rounded-lg text-on-surface-variant hover:bg-surface-container-low"
            aria-label="Toggle navigation menu"
          >
            <span className="material-symbols-outlined text-[24px]">
              {mobileMenuOpen ? 'close' : 'menu'}
            </span>
          </button>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-border-subtle bg-surface-card px-space-md py-3 space-y-2">
          <NavLink
            to="/"
            end
            onClick={() => setMobileMenuOpen(false)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold text-on-surface hover:bg-surface-container-low"
          >
            <span className="material-symbols-outlined text-[18px]">search_check</span>
            {t.scanUrl}
          </NavLink>
          <NavLink
            to="/tracker"
            onClick={() => setMobileMenuOpen(false)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold text-on-surface hover:bg-surface-container-low"
          >
            <span className="material-symbols-outlined text-[18px]">track_changes</span>
            {t.incidentTracker}
          </NavLink>
          <NavLink
            to="/reports"
            onClick={() => setMobileMenuOpen(false)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold text-on-surface hover:bg-surface-container-low"
          >
            <span className="material-symbols-outlined text-[18px]">radar</span>
            {t.threatRadar}
          </NavLink>
          <NavLink
            to="/report-fraud"
            onClick={() => setMobileMenuOpen(false)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-bold text-danger-red hover:bg-red-50"
          >
            <span className="material-symbols-outlined text-[18px]">emergency_home</span>
            {t.reportFraud}
          </NavLink>
          <NavLink
            to="/verify"
            onClick={() => setMobileMenuOpen(false)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold text-on-surface hover:bg-surface-container-low"
          >
            <span className="material-symbols-outlined text-[18px]">verified</span>
            {t.verifyOnChain}
          </NavLink>
          <div className="pt-2 border-t border-border-subtle">
            <AuthBar />
          </div>
        </div>
      )}
    </header>
  )
}
