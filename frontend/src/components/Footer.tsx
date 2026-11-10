import { Link } from 'react-router-dom'

export default function Footer() {
  return (
    <footer className="bg-helpline-navy border-t border-border-subtle text-surface-card mt-auto">
      <div className="w-full py-space-xl px-space-md md:px-margin max-w-[1200px] mx-auto flex flex-col gap-space-lg">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <span className="text-headline-sm font-headline-sm font-extrabold text-surface-card flex items-center gap-2">
              <span className="material-symbols-outlined text-[26px]">shield_lock</span>
              TrustLens
              <span className="text-[10px] font-label-sm bg-primary-fixed text-primary px-1.5 py-0.5 rounded tracking-wider uppercase font-bold ml-1">
                Bharat
              </span>
            </span>
            <p className="text-body-sm font-body-sm text-outline-variant mt-1">
              Empowering Indian citizens with proactive AI defense against modern cyber deception.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-outline-variant">Emergency Quick Dial:</span>
            <a
              className="px-3 py-1.5 rounded-full bg-safety-amber text-helpline-navy font-bold text-xs flex items-center gap-1 hover:bg-amber-400 transition-colors shadow-sm"
              href="tel:1930"
            >
              <span className="material-symbols-outlined text-[14px]">call</span> 1930 (Cyber)
            </a>
            <a
              className="px-3 py-1.5 rounded-full bg-surface-card/20 text-surface-card font-bold text-xs flex items-center gap-1 hover:bg-surface-card/30 transition-colors shadow-sm"
              href="tel:112"
            >
              <span className="material-symbols-outlined text-[14px]">emergency</span> 112 (Police)
            </a>
          </div>
        </div>

        {/* Links Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-3 text-body-sm font-body-sm pt-4 border-t border-surface-card/10">
          <a
            className="text-outline-variant hover:text-surface-card hover:underline text-body-sm font-body-sm transition-colors"
            href="https://cybercrime.gov.in"
            rel="noopener noreferrer"
            target="_blank"
          >
            National Cyber Crime Portal (1930)
          </a>
          <a
            className="text-outline-variant hover:text-surface-card hover:underline text-body-sm font-body-sm transition-colors"
            href="https://www.cert-in.org.in"
            rel="noopener noreferrer"
            target="_blank"
          >
            CERT-In Security Advisories
          </a>
          <Link
            className="text-outline-variant hover:text-surface-card hover:underline text-body-sm font-body-sm transition-colors"
            to="/tracker"
          >
            1930 Incident Tracker
          </Link>
          <Link
            className="text-outline-variant hover:text-surface-card hover:underline text-body-sm font-body-sm transition-colors"
            to="/reports"
          >
            Live Threat Radar
          </Link>
          <Link
            className="text-outline-variant hover:text-surface-card hover:underline text-body-sm font-body-sm transition-colors"
            to="/report-fraud"
          >
            Report Fraud &amp; Freeze
          </Link>
          <Link
            className="text-outline-variant hover:text-surface-card hover:underline text-body-sm font-body-sm transition-colors"
            to="/verify"
          >
            On-Chain Verification
          </Link>
          <a
            className="text-outline-variant hover:text-surface-card hover:underline text-body-sm font-body-sm transition-colors"
            href="#scanner"
          >
            Citizen Privacy Charter
          </a>
        </div>

        {/* Copyright and Mandate */}
        <div className="pt-4 border-t border-surface-card/10 flex flex-col md:flex-row items-center justify-between text-outline-variant text-body-sm font-body-sm gap-2">
          <p>© 2026 TrustLens India. In coordination with Citizen Financial Cyber Fraud Reporting System (1930) &amp; CERT-In guidelines.</p>
          <p className="text-xs">Digital Safety for Bharat • All Rights Reserved</p>
        </div>
      </div>
    </footer>
  )
}
