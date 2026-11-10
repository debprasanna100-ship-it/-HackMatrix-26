import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, analyzeMessage, analyzeUrl, listReports } from '../api/client'
import type { AnalysisReport, ReportListResponse } from '../api/types'
import { RiskBadge } from '../components/badges'
import { useLanguage } from '../context/useLanguage'

// ---- Classification → visual theme helper ----
// Maps all 5 backend verdicts to consistent colours/icons.
// "inconclusive" is treated the same as "suspicious" (amber warning) —
// it means checks FAILED, never that the site is safe.
type Classification = 'confirmed_malicious' | 'high_risk' | 'suspicious' | 'inconclusive' | 'low_risk' | string | undefined

function classTheme(c: Classification) {
  if (c === 'confirmed_malicious' || c === 'high_risk') {
    return {
      banner:  'border-l-danger-red bg-error-container/30',
      icon:    'bg-danger-red',
      symbol:  'gpp_bad',
      badge:   'bg-danger-red text-white',
      url:     'text-danger-red',
      advice:  'bg-red-50 border-red-200 text-red-900',
      adviceIcon: 'text-danger-red',
      adviceSymbol: 'block',
    } as const
  }
  if (c === 'suspicious' || c === 'inconclusive') {
    return {
      banner:  'border-l-safety-amber bg-amber-50/60',
      icon:    'bg-safety-amber',
      symbol:  'warning',
      badge:   'bg-safety-amber text-on-surface',
      url:     'text-amber-700',
      advice:  'bg-amber-50 border-amber-200 text-amber-900',
      adviceIcon: 'text-safety-amber',
      adviceSymbol: 'warning',
    } as const
  }
  // low_risk
  return {
    banner:  'border-l-secondary bg-emerald-50/60',
    icon:    'bg-secondary',
    symbol:  'verified_user',
    badge:   'bg-secondary text-white',
    url:     'text-secondary',
    advice:  'bg-emerald-50 border-emerald-200 text-emerald-900',
    adviceIcon: 'text-secondary',
    adviceSymbol: 'verified_user',
  } as const
}

function classLabel(c: Classification): string {
  if (c === 'confirmed_malicious') return 'CONFIRMED MALICIOUS'
  if (c === 'high_risk') return 'HIGH RISK DETECTED'
  if (c === 'suspicious') return 'SUSPICIOUS RISK DETECTED'
  if (c === 'inconclusive') return 'INCONCLUSIVE — INCOMPLETE CHECKS'
  return 'NO SIGNIFICANT INDICATORS'
}

// Sample demo datasets matching the Stitch design
const SAMPLE_SCANS: Record<string, Partial<AnalysisReport>> = {
  'http://sbi-instant-kyc-verification.top': {
    report_id: 'demo-sbi-kyc',
    raw_input: 'http://sbi-instant-kyc-verification.top',
    classification: 'confirmed_malicious',
    classification_rationale:
      'Impersonating official State Bank of India portal. Features an unauthorized credential harvester script targeting customer NetBanking usernames & OTPs.',
    created_at: new Date(Date.now() - 120000).toISOString(),
    scoring: {
      score: 95,
      high: 3,
      medium: 2,
      low: 1,
      authoritative_hits: 2,
      key_checks_failed: ['tls_validation', 'domain_age', 'cert_san'],
      key_checks_unavailable: [],
    },
    findings: [
      {
        id: 'FIND-PHISH-01',
        title: 'SBI Banking Look-alike credential harvester',
        severity: 'critical',
        category: 'intel',
        weight: 40,
        evidence: [
          'Domain registered 3 days ago via anonymous registrar',
          'Matches known SBI phishing pattern in CERT-In feeds',
        ],
        source: 'CERT-In Threat Feed',
        check_succeeded: true,
      },
      {
        id: 'FIND-TLS-02',
        title: 'Untrusted / Insecure SSL certificate',
        severity: 'high',
        category: 'tls',
        weight: 30,
        evidence: ['Subject Alternative Name does not match *.sbi or *.statebankofindia'],
        source: 'TLS Handshake Probe',
        check_succeeded: true,
      },
    ],
  },
  'http://mahavitran-bill-pay-urgent.xyz': {
    report_id: 'demo-electricity-bill',
    raw_input: 'http://mahavitran-bill-pay-urgent.xyz',
    classification: 'suspicious',
    classification_rationale:
      'Urgent SMS warning of immediate 9:30 PM power cutoff. Instructs user to call a private mobile number and download remote desktop software.',
    created_at: new Date(Date.now() - 360000).toISOString(),
    scoring: {
      score: 68,
      high: 1,
      medium: 3,
      low: 1,
      authoritative_hits: 1,
      key_checks_failed: ['domain_age'],
      key_checks_unavailable: [],
    },
    findings: [
      {
        id: 'FIND-DISCOM-01',
        title: 'High-urgency electricity cutoff social engineering pattern',
        severity: 'high',
        category: 'message',
        weight: 35,
        evidence: ['Urgent payment cutoff language with deadline under 2 hours'],
        source: 'Civic Threat Classifier',
        check_succeeded: true,
      },
    ],
  },
  'https://onlinesbi.sbi': {
    report_id: 'demo-onlinesbi',
    raw_input: 'https://onlinesbi.sbi',
    classification: 'low_risk',
    classification_rationale:
      'Official verified State Bank of India portal. Features Extended Validation (EV) certificate issued by DigiCert with authoritative banking DNS root.',
    created_at: new Date(Date.now() - 600000).toISOString(),
    scoring: {
      score: 0,
      high: 0,
      medium: 0,
      low: 0,
      authoritative_hits: 0,
      key_checks_failed: [],
      key_checks_unavailable: [],
    },
    findings: [],
  },
}

export default function SubmitPage() {
  const { t } = useLanguage()
  const [tab, setTab] = useState<'url' | 'message'>('url')
  const [url, setUrl] = useState('http://sbi-instant-kyc-verification.top')
  const [message, setMessage] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [activeResult, setActiveResult] = useState<Partial<AnalysisReport> | null>(
    SAMPLE_SCANS['http://sbi-instant-kyc-verification.top']
  )
  const [recent, setRecent] = useState<ReportListResponse | null>(null)

  useEffect(() => {
    listReports(6)
      .then(setRecent)
      .catch(() => {})
  }, [])

  // Honesty invariant: the demo samples carry a "demo-" report_id prefix.
  // Everything else in this card is a REAL backend report and must render
  // only backend-produced fields — never fabricated provenance or stats.
  const isSample = !activeResult?.report_id || activeResult.report_id.startsWith('demo-')
  const [scannedText, setScannedText] = useState(
    'Sample scenario — illustrative data, not a live scan'
  )

  // Pure formatter; "now" is passed in from event handlers (impure
  // Date.now() never runs during render).
  function scannedLabelFrom(createdAt: string | undefined, now: number): string {
    if (!createdAt) return 'Scanned just now'
    const secs = Math.max(0, (now - new Date(createdAt).getTime()) / 1000)
    if (secs < 60) return 'Scanned just now'
    if (secs < 3600) return `Scanned ${Math.floor(secs / 60)} min ago`
    if (secs < 86400) return `Scanned ${Math.floor(secs / 3600)} h ago`
    return `Scanned ${Math.floor(secs / 86400)} d ago`
  }

  async function handleAnalyze(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setAnalyzing(true)

    try {
      if (tab === 'url') {
        const report = await analyzeUrl(url.trim())
        setActiveResult(report)
        setScannedText(scannedLabelFrom(report.created_at, Date.now()))
      } else {
        const report = await analyzeMessage(message.trim())
        setActiveResult(report)
        setScannedText(scannedLabelFrom(report.created_at, Date.now()))
      }
    } catch (err) {
      // Never substitute a fabricated sample for a failed analysis — the
      // error surface must reflect reality (backend down, invalid input…).
      if (err instanceof ApiError) {
        setError(err)
      } else {
        setError(new ApiError('unknown', 'Analysis failed. Please check the target and try again.', 0))
      }
    } finally {
      setAnalyzing(false)
    }
  }

  function loadSample(sampleUrl: string) {
    setUrl(sampleUrl)
    setTab('url')
    if (SAMPLE_SCANS[sampleUrl]) {
      setActiveResult(SAMPLE_SCANS[sampleUrl])
      setScannedText('Sample scenario — illustrative data, not a live scan')
    }
  }

  return (
    <div className="w-full max-w-[1200px] mx-auto px-space-md md:px-margin py-space-xl flex flex-col gap-space-xl">
      {/* SECTION 3: HERO & OMNI-VERIFICATION SEARCH BAR */}
      <section className="flex flex-col items-center text-center max-w-4xl mx-auto w-full pt-4" id="scanner">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary-container/30 border border-secondary text-secondary font-label-md text-label-md mb-space-md">
          <span className="material-symbols-outlined text-[16px] material-symbols-fill">security</span>
          <span>{t.heroBadge}</span>
        </div>

        <h1 className="font-display text-display text-primary tracking-tight font-extrabold mb-space-sm">
          {t.heroTitle} <br className="hidden sm:inline" />
          <span className="text-primary-container">{t.heroTitleHighlight}</span>
        </h1>

        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl mb-space-xl leading-relaxed">
          {t.heroDesc}
        </p>

        {/* Mode Selector Tabs */}
        <div className="flex items-center gap-2 mb-space-sm bg-surface-container-low p-1.5 rounded-xl border border-border-subtle">
          <button
            type="button"
            onClick={() => setTab('url')}
            className={`px-4 py-1.5 rounded-lg font-label-md text-label-md font-bold transition-all flex items-center gap-1.5 ${
              tab === 'url'
                ? 'bg-surface-card text-primary shadow-sm'
                : 'text-on-surface-variant hover:text-on-surface'
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">link</span>
            Scan Link / Website
          </button>
          <button
            type="button"
            onClick={() => setTab('message')}
            className={`px-4 py-1.5 rounded-lg font-label-md text-label-md font-bold transition-all flex items-center gap-1.5 ${
              tab === 'message'
                ? 'bg-surface-card text-primary shadow-sm'
                : 'text-on-surface-variant hover:text-on-surface'
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">sms</span>
            Scan Message / SMS Text
          </button>
        </div>

        {/* Prominent Omni-Search URL Input */}
        <div className="w-full bg-surface-card border-2 border-border-subtle focus-within:border-primary-container rounded-2xl shadow-lg p-2.5 md:p-3 transition-all">
          <form className="flex flex-col md:flex-row items-center gap-2" onSubmit={handleAnalyze}>
            <div className="flex items-center flex-1 w-full px-3 gap-2">
              <span className="material-symbols-outlined text-outline text-[24px]">
                {tab === 'url' ? 'link' : 'chat'}
              </span>
              {tab === 'url' ? (
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder={t.placeholderUrl}
                  disabled={analyzing}
                  className="w-full border-none focus:ring-0 text-on-surface font-body-md text-body-md placeholder:text-outline-variant bg-transparent p-0 outline-hidden"
                />
              ) : (
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Paste the suspicious SMS, WhatsApp message, or email body here..."
                  rows={2}
                  disabled={analyzing}
                  className="w-full border-none focus:ring-0 text-on-surface font-body-sm text-body-sm placeholder:text-outline-variant bg-transparent p-0 outline-hidden resize-none"
                />
              )}

              {tab === 'url' && (
                <button
                  type="button"
                  onClick={() => {
                    if (navigator.clipboard) {
                      navigator.clipboard.readText().then((text) => setUrl(text))
                    }
                  }}
                  className="hidden sm:inline-flex items-center gap-1 text-xs font-label-md text-primary bg-primary-fixed/40 hover:bg-primary-fixed px-2.5 py-1 rounded transition-colors shrink-0"
                  title="Paste from clipboard"
                >
                  <span className="material-symbols-outlined text-[14px]">content_paste</span>
                  Paste
                </button>
              )}
            </div>

            <button
              type="submit"
              disabled={analyzing || (tab === 'url' ? url.trim().length < 3 : message.trim().length < 5)}
              className="w-full md:w-auto inline-flex items-center justify-center gap-2 bg-primary-container hover:bg-primary text-on-primary font-label-lg text-label-lg px-6 py-3.5 rounded-xl font-bold shadow-md transition-all active:scale-95 shrink-0 disabled:opacity-50"
            >
              <span className={`material-symbols-outlined text-[20px] ${analyzing ? 'animate-spin' : 'animate-spin-slow'}`}>
                {analyzing ? 'refresh' : 'radar'}
              </span>
              {analyzing ? t.analyzingBtn : t.analyzeBtn}
            </button>
          </form>
        </div>

        {error && (
          <div className="w-full mt-space-sm p-3 rounded-xl bg-red-50 text-danger-red border border-red-200 text-xs text-left flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px]">error</span>
              <span><strong>{error.code}:</strong> {error.message}</span>
            </div>
            <button onClick={() => setError(null)} className="text-outline hover:text-on-surface">
              <span className="material-symbols-outlined text-[16px]">close</span>
            </button>
          </div>
        )}

        {/* Quick Sample Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-2 mt-space-md">
          <span className="font-label-sm text-label-sm text-outline uppercase font-semibold">
            {t.sampleScans}
          </span>
          <button
            type="button"
            onClick={() => loadSample('http://sbi-instant-kyc-verification.top')}
            className="font-label-sm text-label-sm text-on-surface-variant bg-surface-container-low hover:bg-surface-container-high px-2.5 py-1 rounded-full border border-border-subtle transition-colors flex items-center gap-1 font-medium"
          >
            <span className="w-2 h-2 rounded-full bg-danger-red"></span>
            {t.sampleKyc}
          </button>
          <button
            type="button"
            onClick={() => loadSample('http://mahavitran-bill-pay-urgent.xyz')}
            className="font-label-sm text-label-sm text-on-surface-variant bg-surface-container-low hover:bg-surface-container-high px-2.5 py-1 rounded-full border border-border-subtle transition-colors flex items-center gap-1 font-medium"
          >
            <span className="w-2 h-2 rounded-full bg-safety-amber"></span>
            {t.sampleElectricity}
          </button>
          <button
            type="button"
            onClick={() => loadSample('https://onlinesbi.sbi')}
            className="font-label-sm text-label-sm text-on-surface-variant bg-surface-container-low hover:bg-surface-container-high px-2.5 py-1 rounded-full border border-border-subtle transition-colors flex items-center gap-1 font-medium"
          >
            <span className="w-2 h-2 rounded-full bg-secondary"></span>
            {t.sampleLegit}
          </button>
        </div>
      </section>

      {/* SECTION 4: REAL-TIME SCAN ASSESSMENT RESULT CARD (Interactive Layman Bento) */}
      {activeResult && (() => {
        const theme = classTheme(activeResult.classification)
        return (
        <section className="w-full bg-surface-card border border-border-subtle rounded-2xl shadow-sm overflow-hidden animate-in fade-in duration-300">
          {/* Status Header Banner with 6px semantic accent indicator */}
          <div
            className={`border-l-[6px] p-space-md sm:p-space-lg border-b border-border-subtle flex flex-col md:flex-row md:items-center justify-between gap-space-md ${theme.banner}`}
          >
            <div className="flex items-start sm:items-center gap-space-sm">
              <div className={`p-3 text-white rounded-xl shadow-sm shrink-0 ${theme.icon}`}>
                <span className="material-symbols-outlined text-[32px] material-symbols-fill">
                  {theme.symbol}
                </span>
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-label-md font-bold uppercase tracking-wider ${theme.badge}`}>
                    {classLabel(activeResult.classification)}
                  </span>
                  <span className="text-outline text-xs">
                    • {scannedText}
                  </span>
                </div>
                <h2 className="font-headline-sm text-headline-sm font-bold text-on-surface mt-1 break-all">
                  Analysis Result:{' '}
                  <span className={`font-mono font-medium ${theme.url}`}>
                    {activeResult.raw_input || activeResult.normalized?.url || url}
                  </span>
                </h2>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0 flex-wrap">
              {/* WhatsApp Sharing */}
              <a
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-label-md text-label-md font-bold shadow-sm transition-transform active:scale-95"
                href={`https://api.whatsapp.com/send?text=${encodeURIComponent(
                  activeResult.classification === 'low_risk'
                    ? `✅ TrustLens scan of ${
                        activeResult.raw_input || url
                      }: no significant indicators found in the completed checks (this is not proof of safety).`
                    : `⚠️ Warning: Do NOT open ${
                        activeResult.raw_input || url
                      }. It is flagged on TrustLens with verdict: ${activeResult.classification?.toUpperCase()}.`
                )}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span className="material-symbols-outlined text-[16px]">share</span>
                Share Alert on WhatsApp
              </a>

              {/* Report Domain CTA */}
              <Link
                to={`/report-fraud?url=${encodeURIComponent(activeResult.raw_input || url)}`}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-helpline-navy hover:bg-primary-container text-white font-label-md text-label-md font-bold shadow-sm transition-transform active:scale-95"
              >
                <span className="material-symbols-outlined text-[16px]">flag</span>
                Report Domain
              </Link>

              {activeResult.report_id && !activeResult.report_id.startsWith('demo-') && (
                <Link
                  to={`/reports/${activeResult.report_id}`}
                  className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-border-subtle bg-surface-card hover:bg-surface-container font-label-md text-label-md font-bold text-primary transition-colors"
                >
                  Full Forensic Dossier &rarr;
                </Link>
              )}
            </div>
          </div>

          {/* Citizen Advice Strip — classification-aware, never fabricated */}
          <div className={`border-b px-space-md py-3 flex items-center gap-space-sm font-label-lg text-label-lg ${theme.advice}`}>
            <span className={`material-symbols-outlined text-[20px] material-symbols-fill ${theme.adviceIcon}`}>
              {theme.adviceSymbol}
            </span>
            <span>
              {activeResult.classification === 'low_risk' ? (
                <>
                  <strong>NO SIGNIFICANT INDICATORS</strong> were found in the completed checks — this is
                  <strong> not proof of safety</strong>. Always verify the destination independently before
                  entering OTP, UPI PIN, or banking passwords.
                </>
              ) : activeResult.classification === 'inconclusive' ? (
                <>
                  <strong>INCONCLUSIVE</strong> — key checks could not complete (fetch failed or providers unavailable).
                  This is <strong>not a safe verdict</strong>. Treat this destination as untrusted.
                  If you already shared details or lost money, call <strong>1930</strong>{' '}
                  immediately (Golden Hour: 2 hours) to freeze fraud accounts.
                </>
              ) : (
                <>
                  <strong>DO NOT</strong> enter OTP, UPI PIN, Internet Banking Password, or ATM PIN on the
                  flagged destination. If you already shared details or lost money, call <strong>1930</strong>{' '}
                  immediately (Golden Hour: 2 hours) to freeze fraud accounts.
                </>
              )}
            </span>
          </div>

          {/* 4-Pillar Diagnostic Breakdown Grid (Layman Friendly Bento) */}
          <div className="p-space-md sm:p-space-lg grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-space-md">
            {/* Pillar 1: Threat Analysis */}
            <div className="bg-surface-canvas rounded-xl p-space-md border border-border-subtle flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="material-symbols-outlined text-danger-red text-[22px]">phishing</span>
                  <span
                    className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                      activeResult.classification === 'low_risk'
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'bg-red-100 text-danger-red'
                    }`}
                  >
                    {activeResult.classification === 'confirmed_malicious'
                      ? 'Phishing / Malware Confirmed'
                      : activeResult.classification === 'high_risk'
                      ? 'High Risk Indicators'
                      : activeResult.classification === 'suspicious'
                      ? 'Suspicious Indicators'
                      : activeResult.classification === 'inconclusive'
                      ? 'Inconclusive Checks'
                      : 'No Significant Indicators'}
                  </span>
                </div>
                <h3 className="font-title-md text-title-md font-bold text-on-surface">1. Threat Analysis</h3>
                <p className="font-label-sm text-label-sm text-outline mb-2">पहचान चोरी एवं धोखाधड़ी</p>
                <p className="text-on-surface-variant font-body-sm text-body-sm">
                  {activeResult.classification_rationale ||
                    'Deterministic engine rationale unavailable for this result.'}
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-xs">
                <span className="text-outline">Deterministic Score</span>
                <span
                  className={`font-bold ${
                    activeResult.classification === 'low_risk' ? 'text-secondary' : 'text-danger-red'
                  }`}
                >
                  {activeResult.scoring?.score ?? 0} pts
                  {activeResult.scoring?.authoritative_hits
                    ? ` • ${activeResult.scoring.authoritative_hits} authoritative`
                    : ''}
                </span>
              </div>
            </div>

            {/* Pillar 2: Web Security Assessment — real fetch data for real reports */}
            <div className="bg-surface-canvas rounded-xl p-space-md border border-border-subtle flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="material-symbols-outlined text-safety-amber text-[22px]">dns</span>
                  <span
                    className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                      isSample
                        ? 'text-safety-amber bg-amber-100'
                        : activeResult.fetch?.success
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'text-safety-amber bg-amber-100'
                    }`}
                  >
                    {isSample
                      ? activeResult.classification === 'low_risk'
                        ? 'Reputable Host'
                        : 'High Suspicion'
                      : activeResult.fetch?.success
                      ? 'Page Fetched'
                      : 'Fetch Not Completed'}
                  </span>
                </div>
                <h3 className="font-title-md text-title-md font-bold text-on-surface">2. Web Security</h3>
                <p className="font-label-sm text-label-sm text-outline mb-2">डोमेन एवं सर्वर सुरक्षा</p>
                <p className="text-on-surface-variant font-body-sm text-body-sm">
                  {isSample
                    ? activeResult.classification === 'low_risk'
                      ? 'Longstanding established domain with authorized DNS zone and verified ASN registry.'
                      : 'Domain registered merely 3 days ago via anonymous registrar. Hosted in an unverified offshore bulletproof server commonly linked to syndicated cyber gangs.'
                    : activeResult.fetch?.success
                    ? `SSRF-safe fetch completed (${activeResult.fetch.status_code ?? 'n/a'}${
                        activeResult.fetch.elapsed_ms ? `, ${activeResult.fetch.elapsed_ms} ms` : ''
                      }); redirects and content analysed passively. No scripts executed, nothing downloaded.`
                    : `The page could not be fetched (${activeResult.fetch?.error_kind || 'error'}): ${
                        activeResult.fetch?.error || 'the target was not contacted'
                      }. A verdict without a completed fetch is inconclusive by policy.`}
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-xs">
                <span className="text-outline">{isSample ? 'Domain Age' : 'Fetch Result'}</span>
                <span className={`font-bold ${isSample ? 'text-safety-amber' : activeResult.fetch?.success ? 'text-secondary' : 'text-safety-amber'}`}>
                  {isSample
                    ? activeResult.classification === 'low_risk'
                      ? '15+ Years (Verified)'
                      : '3 Days Old (High Risk)'
                    : activeResult.fetch?.success
                    ? `${activeResult.fetch.total_bytes ?? 0} bytes analysed`
                    : 'Not contacted'}
                </span>
              </div>
            </div>

            {/* Pillar 3: Certificate Validation — real TLS data for real reports */}
            <div className="bg-surface-canvas rounded-xl p-space-md border border-border-subtle flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`material-symbols-outlined text-[22px] ${
                      isSample
                        ? activeResult.classification === 'low_risk'
                          ? 'text-secondary'
                          : 'text-danger-red'
                        : activeResult.tls && !activeResult.tls.is_self_signed
                        ? 'text-secondary'
                        : 'text-safety-amber'
                    }`}
                  >
                    {isSample
                      ? activeResult.classification === 'low_risk'
                        ? 'lock'
                        : 'lock_open'
                      : activeResult.tls
                      ? activeResult.tls.is_self_signed
                        ? 'lock_open'
                        : 'lock'
                      : 'lock'}
                  </span>
                  <span
                    className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                      isSample
                        ? activeResult.classification === 'low_risk'
                          ? 'bg-emerald-100 text-secondary'
                          : 'bg-red-100 text-danger-red'
                        : activeResult.tls && !activeResult.tls.is_self_signed
                        ? 'bg-emerald-100 text-secondary'
                        : 'bg-amber-100 text-amber-800'
                    }`}
                  >
                    {isSample
                      ? activeResult.classification === 'low_risk'
                        ? 'Valid SSL'
                        : 'Insecure SSL'
                      : activeResult.tls
                      ? activeResult.tls.is_self_signed
                        ? 'Self-Signed Certificate'
                        : 'Certificate Presented'
                      : 'No Certificate Analysed'}
                  </span>
                </div>
                <h3 className="font-title-md text-title-md font-bold text-on-surface">3. Certificate Validity</h3>
                <p className="font-label-sm text-label-sm text-outline mb-2">सुरक्षा प्रमाणपत्र (SSL)</p>
                <p className="text-on-surface-variant font-body-sm text-body-sm">
                  {isSample
                    ? activeResult.classification === 'low_risk'
                      ? 'Subject Alternative Names match official corporate banking namespace. Verified CA chain.'
                      : 'Mismatched Subject Alternative Name. Insecure HTTP encryption prone to man-in-the-middle packet tampering. Lacks verified Extended Validation (EV) credentials.'
                    : activeResult.tls
                    ? `Issuer: ${activeResult.tls.issuer_common_name || 'n/a'}${
                        activeResult.tls.days_remaining != null
                          ? ` • ${activeResult.tls.days_remaining} days remaining`
                          : ''
                      }. A valid certificate is never proof of safety — look-alike domains can hold valid certificates.`
                    : 'No TLS certificate was analysed for this target (plain HTTP, blocked, or failed fetch).'}
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-xs">
                <span className="text-outline">Issuer Org</span>
                <span
                  className={`font-bold ${
                    isSample
                      ? 'text-danger-red'
                      : activeResult.tls && !activeResult.tls.is_self_signed
                      ? 'text-secondary'
                      : 'text-safety-amber'
                  }`}
                >
                  {isSample
                    ? activeResult.classification === 'low_risk'
                      ? 'DigiCert EV CA'
                      : 'Self-Signed / Untrusted'
                    : activeResult.tls
                    ? activeResult.tls.issuer_common_name || 'Unknown issuer'
                    : '—'}
                </span>
              </div>
            </div>

            {/* Pillar 4: Threat Intelligence — real intel summary for real reports */}
            <div className="bg-surface-canvas rounded-xl p-space-md border border-border-subtle flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="material-symbols-outlined text-primary-container text-[22px]">hub</span>
                  <span className="text-xs font-bold text-primary-container bg-primary-fixed px-2 py-0.5 rounded-full">
                    Threat Intel
                  </span>
                </div>
                <h3 className="font-title-md text-title-md font-bold text-on-surface">4. Threat Radar</h3>
                <p className="font-label-sm text-label-sm text-outline mb-2">नागरिक रिपोर्ट डेटाबेस</p>
                <p className="text-on-surface-variant font-body-sm text-body-sm">
                  {isSample
                    ? activeResult.classification === 'low_risk'
                      ? 'Zero consumer complaints registered across Indian states. Clean telemetric trust score.'
                      : '142 citizen complaints logged in Mumbai, Delhi, Bengaluru, and Pune within the last 24 hours. Automated dispatch triggered to 1930 Cyber Fraud registry.'
                    : `${activeResult.threat_intel?.total_findings ?? 0} intel finding(s); ${
                        activeResult.threat_intel?.authoritative_hits?.length ?? 0
                      } authoritative hit(s). ${
                        activeResult.threat_intel?.note ??
                        'Absence of intel hits is not proof of safety.'
                      }`}
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-xs">
                <span className="text-outline">Feed Status</span>
                <span
                  className={`font-bold ${
                    !isSample && (activeResult.threat_intel?.authoritative_hits?.length ?? 0) > 0
                      ? 'text-danger-red'
                      : 'text-secondary'
                  }`}
                >
                  {isSample
                    ? activeResult.classification === 'low_risk'
                      ? 'Clean Stream'
                      : 'Hot Wave Incident'
                    : activeResult.threat_intel?.authoritative_hits?.length
                    ? 'Authoritative Match'
                    : 'No Authoritative Match'}
                </span>
              </div>
            </div>
          </div>
        </section>
        )
      })()}

      {/* SECTION 6: LIVE THREAT RADAR & TRENDING SCAMS IN INDIA */}
      <section className="w-full" id="radar">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-space-md">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-danger-red"></span>
              <h3 className="font-headline-sm text-headline-sm font-bold text-on-surface">
                Trending Scam Patterns in India — Awareness
              </h3>
            </div>
            <p className="text-on-surface-variant font-body-sm text-body-sm">
              Illustrative scam patterns seen in the wild. Educational reference content — not live
              telemetry. Real scans are listed below and in Threat Radar &amp; Reports.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-secondary-container text-on-secondary-container">
              Awareness Content
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
          {/* Threat Card 1 */}
          <div className="bg-surface-card border border-border-subtle rounded-xl p-space-md shadow-sm border-l-4 border-l-danger-red hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between text-xs mb-2">
              <span className="font-bold text-danger-red bg-red-50 px-2 py-0.5 rounded">Banking / APK Lure</span>
              <span className="text-outline">Uttar Pradesh &amp; Bihar</span>
            </div>
            <h4 className="font-title-md text-title-md font-bold text-on-surface mb-1">
              "SBI-Yono-Rewards.apk"
            </h4>
            <p className="text-xs text-outline font-mono mb-2">sbi-reward-points-redeem.site</p>
            <p className="text-sm text-on-surface-variant mb-3">
              Malicious Trojan APK stealing OTP messages via SMS read permissions. Targeted at rural account holders.
            </p>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-border-subtle">
              <span className="text-danger-red font-bold flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">warning</span> Reported pattern
              </span>
              <span className="text-outline font-medium">Awareness example</span>
            </div>
          </div>

          {/* Threat Card 2 */}
          <div className="bg-surface-card border border-border-subtle rounded-xl p-space-md shadow-sm border-l-4 border-l-danger-red hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between text-xs mb-2">
              <span className="font-bold text-danger-red bg-red-50 px-2 py-0.5 rounded">Utility Extortion</span>
              <span className="text-outline">Maharashtra &amp; Gujarat</span>
            </div>
            <h4 className="font-title-md text-title-md font-bold text-on-surface mb-1">
              "Electricity Power Disconnection"
            </h4>
            <p className="text-xs text-outline font-mono mb-2">mahavitran-bill-update-online.in</p>
            <p className="text-sm text-on-surface-variant mb-3">
              Urgent SMS warning of immediate 9:30 PM power cutoff. Instructs user to call a private mobile number and download remote desktop software.
            </p>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-border-subtle">
              <span className="text-danger-red font-bold flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">warning</span> Reported pattern
              </span>
              <span className="text-outline font-medium">Awareness example</span>
            </div>
          </div>

          {/* Threat Card 3 */}
          <div className="bg-surface-card border border-border-subtle rounded-xl p-space-md shadow-sm border-l-4 border-l-safety-amber hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between text-xs mb-2">
              <span className="font-bold text-safety-amber bg-amber-50 px-2 py-0.5 rounded">Job / Telegram Task</span>
              <span className="text-outline">Karnataka &amp; Telangana</span>
            </div>
            <h4 className="font-title-md text-title-md font-bold text-on-surface mb-1">
              "Google Maps Review ₹5000/Day"
            </h4>
            <p className="text-xs text-outline font-mono mb-2">google-partner-tasks-india.biz</p>
            <p className="text-sm text-on-surface-variant mb-3">
              Prepaid task scam requesting initial ₹1,000 deposits to unlock earnings, escalating into large irreversible crypto/UPI transfers.
            </p>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-border-subtle">
              <span className="text-safety-amber font-bold flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">info</span> Reported pattern
              </span>
              <span className="text-outline font-medium">Awareness example</span>
            </div>
          </div>
        </div>

        {/* Live Stored Recent Reports from Backend */}
        {recent && recent.reports.length > 0 && (
          <div className="mt-space-lg bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg">
            <div className="flex items-center justify-between mb-space-sm">
              <h4 className="font-title-md text-title-md font-bold text-on-surface flex items-center gap-2">
                <span className="material-symbols-outlined text-[20px] text-primary">history</span>
                Recently Scanned Targets across India
              </h4>
              <Link to="/reports" className="font-label-md text-label-md font-bold text-primary hover:underline">
                View All Stored Reports ({recent.count}) &rarr;
              </Link>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {recent.reports.slice(0, 6).map((r) => (
                <Link
                  key={r.report_id}
                  to={`/reports/${r.report_id}`}
                  className="p-3 rounded-xl border border-border-subtle hover:border-primary-container bg-surface-canvas hover:bg-surface-card transition-all flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between mb-1">
                    <RiskBadge classification={r.classification} />
                    <span className="text-[11px] text-outline">
                      {new Date(r.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <span className="font-mono text-xs text-on-surface font-semibold truncate my-1">
                    {r.registrable_domain || r.normalized_url || r.report_id}
                  </span>
                  <span className="text-[11px] text-outline-variant">
                    {r.findings_count} security indicator(s) verified
                  </span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* SECTION 7: TRUST & CIVIC ASSURANCE BENTO */}
      <section className="w-full bg-surface-container-low border border-border-subtle rounded-2xl p-space-lg">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-space-lg items-center">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-surface-card rounded-xl text-primary shadow-sm border border-border-subtle shrink-0">
              <span className="material-symbols-outlined text-[24px] material-symbols-fill">verified_user</span>
            </div>
            <div>
              <h4 className="font-title-md text-title-md font-bold text-on-surface">Zero-Log Citizen Privacy</h4>
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                We never store your personal identifiers or submitted links without authorization. Analysis occurs in volatile encrypted memory.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-surface-card rounded-xl text-secondary shadow-sm border border-border-subtle shrink-0">
              <span className="material-symbols-outlined text-[24px] material-symbols-fill">policy</span>
            </div>
            <div>
              <h4 className="font-title-md text-title-md font-bold text-on-surface">CERT-In Aligned Telemetry</h4>
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                Operates under standard guidelines from Indian Computer Emergency Response Team and National Cyber Crime Guidelines.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-surface-card rounded-xl text-safety-amber shadow-sm border border-border-subtle shrink-0">
              <span className="material-symbols-outlined text-[24px] material-symbols-fill">support_agent</span>
            </div>
            <div>
              <h4 className="font-title-md text-title-md font-bold text-on-surface">Emergency Fast Response (1930)</h4>
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                Direct toll-free telephonic access to police cyber desks across all 28 states and 8 union territories.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
