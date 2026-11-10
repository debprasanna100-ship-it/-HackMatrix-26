import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'

interface IncidentRecord {
  ref: string
  ncrpAck: string
  citizenName: string
  mobile: string
  scamType: string
  amount: number
  sourceBank: string
  muleAccount: string
  url: string
  status: 'In Progress' | 'Frozen' | 'Under Investigation' | 'Recovered'
  step: number
  elapsedMinutes: number
  reportedAt: string
}

const DEFAULT_INCIDENT: IncidentRecord = {
  ref: 'TL-DEMO-84920',
  ncrpAck: 'DEMO-48192 (simulated — not an official NCRP number)',
  citizenName: 'Rajesh Kumar Sharma',
  mobile: '+91 98765 43210',
  scamType: 'Bank Impersonation / Fake YONO APK Phishing',
  amount: 45000,
  sourceBank: 'State Bank of India (A/C Ending ...4029)',
  muleAccount: 'npci.mule.99281@icici (Intercepted)',
  url: 'http://sbi-instant-kyc-verification.top',
  status: 'In Progress',
  step: 3,
  elapsedMinutes: 38,
  reportedAt: 'Oct 24, 10:14 AM',
}

export default function TrackerPage() {
  const { id } = useParams<{ id?: string }>()
  const [query, setQuery] = useState(id || 'TL-2026-IN-84920')
  const [incident, setIncident] = useState<IncidentRecord>(() => {
    if (id) {
      const stored = localStorage.getItem(`incident_${id}`)
      if (stored) {
        try {
          return { ...DEFAULT_INCIDENT, ...JSON.parse(stored), ref: id }
        } catch {}
      }
      return { ...DEFAULT_INCIDENT, ref: id }
    }
    return DEFAULT_INCIDENT
  })
  const [timerSeconds, setTimerSeconds] = useState(38 * 60 + 12)
  const [pdfModalOpen, setPdfModalOpen] = useState(false)
  const [subscribedWa, setSubscribedWa] = useState(false)

  // Live stopwatch dial
  useEffect(() => {
    const timer = setInterval(() => {
      setTimerSeconds((prev) => prev + 1)
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  function handleSearch(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = query.trim()
    if (!trimmed) return
    const stored = localStorage.getItem(`incident_${trimmed}`)
    if (stored) {
      try {
        setIncident(JSON.parse(stored))
        return
      } catch {}
    }
    setIncident({
      ...DEFAULT_INCIDENT,
      ref: trimmed.toUpperCase(),
    })
  }

  const formatTimer = (totalSec: number) => {
    const hrs = Math.floor(totalSec / 3600)
    const mins = Math.floor((totalSec % 3600) / 60)
    const secs = totalSec % 60
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs
      .toString()
      .padStart(2, '0')}`
  }

  return (
    <div className="w-full max-w-[1200px] mx-auto px-space-md md:px-margin py-space-xl flex flex-col gap-space-xl">
      {/* SECTION 1: SEARCH HEADER */}
      <section className="bg-surface-card border border-border-subtle rounded-2xl p-space-md md:p-space-lg shadow-sm">
        <div className="max-w-3xl mx-auto text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary-container/30 border border-secondary text-secondary font-label-md text-label-md">
            <span className="material-symbols-outlined text-[16px] material-symbols-fill">track_changes</span>
            <span>National Citizen Cyber Crime (1930) Tracker</span>
          </div>

          <h1 className="font-display text-display text-primary tracking-tight font-extrabold mb-space-sm">
            Track Incident &amp; Inter-Bank Freeze Status
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant max-w-xl mx-auto">
            Track your demo complaint &amp; simulated inter-bank freeze status. This tracker is a
            <strong> DEMONSTRATION ONLY</strong> — statuses are illustrative and nothing is filed with 1930,
            the police, or any bank. To report real fraud, call <strong>1930</strong> or visit
            cybercrime.gov.in.
          </p>

          <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-2 max-w-xl mx-auto pt-2">
            <div className="relative flex-1">
              <span className="material-symbols-outlined absolute left-3.5 top-1/2 -translate-y-1/2 text-outline text-[20px]">
                search
              </span>
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter Incident Ref Number (e.g. TL-2026-IN-84920) or Registered 10-digit Mobile..."
                className="w-full pl-10 pr-4 py-3 rounded-xl border border-border-subtle bg-surface-canvas font-body-sm text-body-sm focus:border-primary-container focus:ring-0 outline-hidden"
              />
            </div>
            <button
              type="submit"
              className="bg-primary-container hover:bg-primary text-on-primary font-label-lg text-label-lg px-6 py-3 rounded-xl font-bold transition-all shadow-md flex items-center justify-center gap-1.5 shrink-0"
            >
              <span className="material-symbols-outlined text-[18px]">travel_explore</span>
              <span>Track Incident</span>
            </button>
          </form>

          {/* Quick Demo Pill & Dual-language help */}
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1 font-body-sm text-body-sm text-on-surface-variant">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-label-sm text-label-sm uppercase tracking-wider text-outline font-bold">
                Quick Demo:
              </span>
              <button
                type="button"
                onClick={() => {
                  setQuery('TL-2026-IN-84920')
                  setIncident(DEFAULT_INCIDENT)
                }}
                className="px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-high text-primary-container font-label-sm text-label-sm transition-colors flex items-center gap-1 font-bold"
              >
                <span>TL-2026-IN-84920 (SBI KYC Phishing - ₹45,000)</span>
                <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
              </button>
            </div>
            <span className="font-label-sm text-label-sm text-outline">
              शिकायत संख्या या पंजीकृत मोबाइल दर्ज करें
            </span>
          </div>
        </div>
      </section>

      {/* SECTION 2: ACTIVE CASE FORENSIC DOSSIER */}
      <div className="space-y-space-lg">
        {/* Incident Status Announcement Banner with Emergency Accent */}
        <div className="bg-surface-card border-l-4 border-safety-amber border-y border-r border-border-subtle rounded-2xl p-space-md md:p-space-lg shadow-sm">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md">
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full bg-amber-100 text-amber-900 border border-amber-300 font-label-sm text-label-sm font-bold flex items-center gap-1">
                  <span className="material-symbols-outlined text-[14px] text-amber-700 animate-spin-slow">
                    hourglass_top
                  </span>
                  ACTION IN PROGRESS
                </span>
                <span className="font-label-sm text-label-sm text-on-surface-variant font-bold">
                  REF: <span className="font-mono text-on-surface">{incident.ref}</span>
                </span>
                <span className="font-label-sm text-label-sm text-outline">| Demo ACK (not official): {incident.ncrpAck}</span>
              </div>
              <h2 className="text-headline-sm font-headline-sm font-bold text-helpline-navy">
                Inter-Bank Account Lien &amp; Freeze Initiated
              </h2>
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                Simulated freeze status for this DEMO record — no freeze request was sent to any bank. To
                report real fraud, call 1930 or visit cybercrime.gov.in.
              </p>
            </div>

            {/* Quick Action Buttons on Header */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setPdfModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-primary-container font-label-sm text-label-sm font-bold transition-all"
              >
                <span className="material-symbols-outlined text-[18px]">download</span>
                <span>Acknowledgement PDF</span>
              </button>
              <button
                type="button"
                onClick={() => setSubscribedWa(!subscribedWa)}
                className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg font-label-sm text-label-sm font-bold transition-all ${
                  subscribedWa
                    ? 'bg-emerald-600 text-white'
                    : 'bg-[#25D366]/10 hover:bg-[#25D366]/20 text-[#075E54] border border-[#25D366]/30'
                }`}
              >
                <span className="material-symbols-outlined text-[18px]">
                  {subscribedWa ? 'check_circle' : 'share'}
                </span>
                <span>{subscribedWa ? 'WhatsApp Alerts Enabled' : 'WhatsApp Alerts'}</span>
              </button>
            </div>
          </div>

          {/* Progress Stepper (5 Steps) */}
          <div className="mt-8 pt-6 border-t border-border-subtle">
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative">
              {/* Step 1: Complete */}
              <div className="flex flex-col gap-2 relative group">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-secondary text-surface-card flex items-center justify-center font-bold text-sm shadow">
                    <span className="material-symbols-outlined text-[18px]">check</span>
                  </div>
                  <div className="hidden md:block flex-1 h-1 bg-secondary rounded"></div>
                </div>
                <div className="pr-2">
                  <p className="font-label-sm text-label-sm text-secondary font-bold uppercase tracking-wider">
                    Step 1 • Completed
                  </p>
                  <h3 className="font-label-lg text-label-lg font-bold text-on-surface">Incident Logged</h3>
                  <p className="text-[12px] text-on-surface-variant mt-0.5">TrustLens Gateway • {incident.reportedAt}</p>
                </div>
              </div>

              {/* Step 2: Complete */}
              <div className="flex flex-col gap-2 relative group">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-secondary text-surface-card flex items-center justify-center font-bold text-sm shadow">
                    <span className="material-symbols-outlined text-[18px]">check</span>
                  </div>
                  <div className="hidden md:block flex-1 h-1 bg-secondary rounded"></div>
                </div>
                <div className="pr-2">
                  <p className="font-label-sm text-label-sm text-secondary font-bold uppercase tracking-wider">
                    Step 2 • Completed
                  </p>
                  <h3 className="font-label-lg text-label-lg font-bold text-on-surface">NCRP Ack Generated</h3>
                  <p className="text-[12px] text-on-surface-variant mt-0.5">Ref: {incident.ncrpAck}</p>
                </div>
              </div>

              {/* Step 3: In Progress (Active) */}
              <div className="flex flex-col gap-2 relative group">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-safety-amber text-helpline-navy flex items-center justify-center font-bold text-sm shadow ring-4 ring-safety-amber/20 animate-pulse">
                    <span className="material-symbols-outlined text-[18px]">sync</span>
                  </div>
                  <div className="hidden md:block flex-1 h-1 bg-border-subtle rounded"></div>
                </div>
                <div className="pr-2">
                  <p className="font-label-sm text-label-sm text-amber-800 font-bold uppercase tracking-wider">
                    Step 3 • In Progress
                  </p>
                  <h3 className="font-label-lg text-label-lg font-bold text-on-surface">Bank Nodal Alerted</h3>
                  <p className="text-[12px] text-on-surface-variant mt-0.5">Golden Hour lien order with Beneficiary Bank</p>
                </div>
              </div>

              {/* Step 4: Pending */}
              <div className="flex flex-col gap-2 relative group opacity-60">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-surface-container text-on-surface-variant flex items-center justify-center font-bold text-sm border border-border-subtle">
                    4
                  </div>
                  <div className="hidden md:block flex-1 h-1 bg-border-subtle rounded"></div>
                </div>
                <div className="pr-2">
                  <p className="font-label-sm text-label-sm text-outline font-bold uppercase tracking-wider">
                    Step 4 • Pending
                  </p>
                  <h3 className="font-label-lg text-label-lg font-bold text-on-surface">Police Investigation</h3>
                  <p className="text-[12px] text-on-surface-variant mt-0.5">FIR formalization &amp; Cyber Cell charge sheet</p>
                </div>
              </div>

              {/* Step 5: Pending */}
              <div className="flex flex-col gap-2 relative group opacity-60">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-surface-container text-on-surface-variant flex items-center justify-center font-bold text-sm border border-border-subtle">
                    5
                  </div>
                </div>
                <div className="pr-2">
                  <p className="font-label-sm text-label-sm text-outline font-bold uppercase tracking-wider">
                    Step 5 • Pending
                  </p>
                  <h3 className="font-label-lg text-label-lg font-bold text-on-surface">Fund Recovery</h3>
                  <p className="text-[12px] text-on-surface-variant mt-0.5">Magistrate clearance &amp; victim account reversal</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Bento Grid: Golden Hour Telemetry & Case Dossier */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-space-lg">
          {/* Left 8 Columns: Telemetry, Evidence, and Official Actions */}
          <div className="lg:col-span-8 flex flex-col gap-space-lg">
            {/* Golden Hour Callout Card */}
            <div className="bg-gradient-to-br from-helpline-navy to-primary-container p-space-lg rounded-2xl text-surface-card shadow-md flex flex-col md:flex-row items-center justify-between gap-space-md">
              <div className="flex items-start gap-4">
                <div className="p-3 bg-white/10 rounded-xl backdrop-blur-sm shrink-0">
                  <span className="material-symbols-outlined text-secondary-fixed text-[32px]">timer</span>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-secondary-fixed text-on-secondary-fixed font-label-sm text-label-sm font-extrabold uppercase">
                      Golden Hour Preserved
                    </span>
                    <span className="font-label-sm text-label-sm text-surface-variant">Reported within 22 Minutes</span>
                  </div>
                  <h3 className="font-title-md text-title-md font-bold text-surface-card">
                    86% Historical Recovery Probability
                  </h3>
                  <p className="font-body-sm text-body-sm text-surface-variant max-w-xl">
                    You acted inside the crucial 2-hour window. Bank freeze APIs were triggered before fraudulent cash-out at downstream ATMs occurred.
                  </p>
                </div>
              </div>

              {/* Live Response Dial */}
              <div className="shrink-0 bg-white/10 rounded-xl p-3 border border-white/20 text-center w-full md:w-36">
                <span className="text-[10px] text-surface-variant uppercase font-bold tracking-wider block">
                  Time Elapsed
                </span>
                <span className="font-headline-md text-headline-md font-extrabold text-secondary-fixed font-mono">
                  {formatTimer(timerSeconds)}
                </span>
                <span className="text-[11px] text-emerald-200 block font-semibold">Live Telemetry Sync</span>
              </div>
            </div>

            {/* Case Summary Detailed Dossier Card */}
            <div className="bg-surface-card rounded-2xl border border-border-subtle p-space-md md:p-space-lg shadow-sm space-y-6">
              <div className="flex items-center justify-between border-b border-border-subtle pb-4">
                <div className="flex items-center gap-2.5">
                  <span className="material-symbols-outlined text-primary-container text-[24px]">folder_supervised</span>
                  <div>
                    <h3 className="font-title-md text-title-md font-bold text-helpline-navy">Incident Case Dossier</h3>
                    <p className="font-label-sm text-label-sm text-on-surface-variant">
                      Confidential Legal Evidence Record #{incident.ref}
                    </p>
                  </div>
                </div>
                <span className="px-3 py-1 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200 font-label-sm text-label-sm font-bold flex items-center gap-1">
                  <span className="material-symbols-outlined text-[16px]">verified</span>
                  Verified Citizen
                </span>
              </div>

              {/* Dossier Grid Data */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-y-4 gap-x-6 font-body-sm text-body-sm">
                <div className="space-y-1">
                  <span className="font-label-sm text-label-sm text-outline uppercase font-bold">Complainant Name</span>
                  <p className="font-bold text-on-surface font-body-md text-body-md">{incident.citizenName}</p>
                </div>
                <div className="space-y-1">
                  <span className="font-label-sm text-label-sm text-outline uppercase font-bold">Registered Mobile</span>
                  <p className="font-bold text-on-surface flex items-center gap-1.5">
                    <span>{incident.mobile}</span>
                    <span className="material-symbols-outlined text-secondary text-[16px]">verified</span>
                  </p>
                </div>
                <div className="space-y-1">
                  <span className="font-label-sm text-label-sm text-outline uppercase font-bold">Scam Vector / Modus Operandi</span>
                  <p className="font-semibold text-danger-red flex items-center gap-1">
                    <span className="material-symbols-outlined text-[16px]">phishing</span>
                    {incident.scamType}
                  </p>
                </div>
                <div className="space-y-1">
                  <span className="font-label-sm text-label-sm text-outline uppercase font-bold">Disputed Defrauded Amount</span>
                  <p className="font-headline-sm text-headline-sm font-extrabold text-helpline-navy">
                    ₹{incident.amount.toLocaleString('en-IN')}{' '}
                    <span className="font-label-sm text-label-sm font-normal text-on-surface-variant">(INR)</span>
                  </p>
                </div>
                <div className="space-y-1">
                  <span className="font-label-sm text-label-sm text-outline uppercase font-bold">Targeted Source Bank</span>
                  <p className="font-bold text-on-surface flex items-center gap-1">
                    <span className="material-symbols-outlined text-primary-container text-[18px]">account_balance</span>
                    {incident.sourceBank}
                  </p>
                </div>
                <div className="space-y-1">
                  <span className="font-label-sm text-label-sm text-outline uppercase font-bold">Destination Mule Trail</span>
                  <p className="font-mono text-on-surface bg-surface-canvas p-1.5 rounded border border-border-subtle text-[13px] flex items-center justify-between">
                    <span>{incident.muleAccount}</span>
                    <span className="material-symbols-outlined text-secondary text-[16px]" title="Alerted to NPCI">check_circle</span>
                  </p>
                </div>

                {/* Malicious Link Info */}
                <div className="sm:col-span-2 space-y-1 pt-2 border-t border-border-subtle">
                  <span className="font-label-sm text-label-sm text-outline uppercase font-bold">Associated Malicious Forensic URL</span>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-red-50 border border-red-200">
                    <div className="flex items-center gap-2 overflow-hidden text-ellipsis">
                      <span className="material-symbols-outlined text-danger-red text-[18px]">link_off</span>
                      <span className="font-mono text-sm text-red-900 font-semibold truncate">
                        {incident.url}
                      </span>
                    </div>
                    <span className="shrink-0 px-2 py-0.5 rounded bg-red-600 text-white font-label-sm text-label-sm font-bold uppercase">
                      CERT-In Takedown Active
                    </span>
                  </div>
                </div>
              </div>

              {/* Inter-Agency Timeline Log */}
              <div className="bg-surface-canvas rounded-xl p-4 border border-border-subtle space-y-3">
                <h4 className="font-label-lg text-label-lg font-bold text-helpline-navy flex items-center gap-2">
                  <span className="material-symbols-outlined text-primary-container text-[18px]">history_edu</span>
                  Inter-Agency Response Telemetry Log
                </h4>
                <div className="space-y-2 font-body-sm text-body-sm">
                  <div className="flex items-start gap-2.5">
                    <span className="text-secondary font-mono font-bold text-xs mt-0.5">10:14 AM</span>
                    <p className="text-on-surface">
                      <span className="font-semibold">Citizen Dispatch:</span> Incident reported via TrustLens mobile assistance engine.
                    </p>
                  </div>
                  <div className="flex items-start gap-2.5">
                    <span className="text-secondary font-mono font-bold text-xs mt-0.5">10:18 AM</span>
                    <p className="text-on-surface">
                      <span className="font-semibold">NCRP Integration (simulated):</span> In this demo no complaint was filed with any portal — the reference shown is illustrative only (Ref: {incident.ncrpAck}).
                    </p>
                  </div>
                  <div className="flex items-start gap-2.5">
                    <span className="text-safety-amber font-mono font-bold text-xs mt-0.5">10:24 AM</span>
                    <p className="text-on-surface">
                      <span className="font-semibold">Bank Nodal Automation (simulated):</span> In this demo no bank was contacted — the freeze acknowledgement shown is illustrative only.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Official Coordination & Download Center */}
            <div className="bg-surface-card rounded-2xl border border-border-subtle p-space-md md:p-space-lg shadow-sm">
              <h3 className="font-title-md text-title-md font-bold text-helpline-navy mb-4 flex items-center gap-2">
                <span className="material-symbols-outlined text-primary-container">file_download</span>
                Official Coordination &amp; Documentation Center
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => setPdfModalOpen(true)}
                  className="flex flex-col items-center justify-center text-center p-4 rounded-xl border border-border-subtle hover:border-primary-container bg-surface-canvas hover:bg-surface-card transition-all group shadow-sm"
                >
                  <div className="w-12 h-12 rounded-full bg-primary-fixed flex items-center justify-center text-primary mb-2 group-hover:scale-105 transition-transform">
                    <span className="material-symbols-outlined text-[24px]">picture_as_pdf</span>
                  </div>
                  <span className="font-label-lg text-label-lg font-bold text-on-surface">Signed Complaint Dossier</span>
                  <span className="text-[12px] text-on-surface-variant mt-1">Official PDF with MHA Hash</span>
                </button>

                <button
                  type="button"
                  onClick={() => setSubscribedWa(!subscribedWa)}
                  className="flex flex-col items-center justify-center text-center p-4 rounded-xl border border-border-subtle hover:border-emerald-500 bg-surface-canvas hover:bg-surface-card transition-all group shadow-sm"
                >
                  <div className="w-12 h-12 rounded-full bg-emerald-100 flex items-center justify-center text-emerald-700 mb-2 group-hover:scale-105 transition-transform">
                    <span className="material-symbols-outlined text-[24px]">chat</span>
                  </div>
                  <span className="font-label-lg text-label-lg font-bold text-on-surface">Live Status on WhatsApp</span>
                  <span className="text-[12px] text-on-surface-variant mt-1">Automated Step-by-Step Pings</span>
                </button>

                <a
                  href="tel:1930"
                  className="flex flex-col items-center justify-center text-center p-4 rounded-xl border border-border-subtle hover:border-primary-container bg-surface-canvas hover:bg-surface-card transition-all group shadow-sm"
                >
                  <div className="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center text-primary-container mb-2 group-hover:scale-105 transition-transform">
                    <span className="material-symbols-outlined text-[24px]">headset_mic</span>
                  </div>
                  <span className="font-label-lg text-label-lg font-bold text-on-surface">Request Desk Callback</span>
                  <span className="text-[12px] text-on-surface-variant mt-1">District Cyber Cell Support</span>
                </a>
              </div>
            </div>
          </div>

          {/* Right 4 Columns: Citizen Guidance (Do's and Don'ts) & Helpline Direct Connect */}
          <div className="lg:col-span-4 flex flex-col gap-space-lg">
            {/* Next Steps & Protective Guidance Card */}
            <div className="bg-surface-card rounded-2xl border border-border-subtle p-space-md md:p-space-lg shadow-sm space-y-5">
              <div className="border-b border-border-subtle pb-3">
                <span className="px-2.5 py-0.5 rounded bg-blue-100 text-blue-900 font-label-sm text-label-sm font-bold uppercase">
                  Citizen Safety Protocol
                </span>
                <h3 className="font-title-md text-title-md font-bold text-helpline-navy mt-1">
                  Crucial Steps for You Right Now
                </h3>
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  Avoid secondary extortion and expedite bank-level verification.
                </p>
              </div>

              {/* Mandatory DO's */}
              <div className="space-y-3">
                <h4 className="font-label-lg text-label-lg font-bold text-secondary flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[20px]">check_circle</span>
                  WHAT YOU MUST DO IMMEDIATELY
                </h4>
                <div className="flex items-start gap-2.5 p-3 rounded-lg bg-emerald-50/60 border border-emerald-100 font-body-sm text-body-sm text-on-surface">
                  <span className="material-symbols-outlined text-secondary text-[20px] shrink-0 mt-0.5">store</span>
                  <div>
                    <strong className="font-semibold text-emerald-950 block">Visit Bank Home Branch</strong>
                    Present Acknowledgement Ref #{incident.ref} to the branch manager to confirm dispute marking on your statement.
                  </div>
                </div>
                <div className="flex items-start gap-2.5 p-3 rounded-lg bg-emerald-50/60 border border-emerald-100 font-body-sm text-body-sm text-on-surface">
                  <span className="material-symbols-outlined text-secondary text-[20px] shrink-0 mt-0.5">sim_card_download</span>
                  <div>
                    <strong className="font-semibold text-emerald-950 block">Sanitize Your Device</strong>
                    Uninstall any downloaded APKs immediately and reset your NetBanking login credentials from a clean laptop.
                  </div>
                </div>
              </div>

              {/* Mandatory DON'Ts */}
              <div className="space-y-3 pt-2 border-t border-border-subtle">
                <h4 className="font-label-lg text-label-lg font-bold text-danger-red flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[20px]">dangerous</span>
                  NEVER DO THIS (BEWARE RECOVERY SCAMS)
                </h4>
                <div className="flex items-start gap-2.5 p-3 rounded-lg bg-red-50/80 border border-red-200 font-body-sm text-body-sm text-red-950">
                  <span className="material-symbols-outlined text-danger-red text-[20px] shrink-0 mt-0.5">payments</span>
                  <div>
                    <strong className="font-bold block">NEVER Pay Any 'File Clearance Fee'</strong>
                    Neither NCRP nor Police Cyber Cells charge money to release frozen funds. Anyone asking for payment is an impostor.
                  </div>
                </div>
                <div className="flex items-start gap-2.5 p-3 rounded-lg bg-red-50/80 border border-red-200 font-body-sm text-body-sm text-red-950">
                  <span className="material-symbols-outlined text-danger-red text-[20px] shrink-0 mt-0.5">phone_disabled</span>
                  <div>
                    <strong className="font-bold block">Refuse WhatsApp 'Police' Video Calls</strong>
                    Scammers frequently make fake video calls wearing fake uniforms claiming 'CBI arrest warrants'. Hang up immediately.
                  </div>
                </div>
              </div>
            </div>

            {/* Official Helpline Direct Connect Box */}
            <div className="bg-helpline-navy rounded-2xl p-space-md md:p-space-lg text-surface-card space-y-4 shadow-md">
              <div className="flex items-center gap-2">
                <span className="p-2 rounded-lg bg-safety-amber text-helpline-navy font-bold">
                  <span className="material-symbols-outlined text-[22px]">contact_phone</span>
                </span>
                <div>
                  <h4 className="font-title-md text-title-md font-bold text-surface-card">Helpline Escalation Desk</h4>
                  <p className="font-label-sm text-label-sm text-outline-variant">Immediate Institutional Assistance</p>
                </div>
              </div>

              <div className="space-y-3 pt-2 font-body-sm text-body-sm">
                {/* 1930 Direct */}
                <div className="p-3 rounded-xl bg-white/5 border border-white/10 flex items-center justify-between">
                  <div>
                    <span className="text-[11px] text-surface-variant uppercase font-bold block">National Central Toll-Free</span>
                    <span className="font-headline-sm text-headline-sm font-extrabold text-safety-amber">1930</span>
                  </div>
                  <a
                    className="px-3 py-1.5 rounded-lg bg-safety-amber hover:bg-amber-400 text-helpline-navy font-label-sm text-label-sm font-bold transition-all active:scale-95"
                    href="tel:1930"
                  >
                    Call Now
                  </a>
                </div>

                {/* State Cyber Cell Desk */}
                <div className="p-3 rounded-xl bg-white/5 border border-white/10 flex items-center justify-between">
                  <div>
                    <span className="text-[11px] text-surface-variant uppercase font-bold block">Maharashtra Cyber Desk</span>
                    <span className="font-bold text-surface-card">022-22160080</span>
                  </div>
                  <a
                    className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-surface-card font-label-sm text-label-sm font-bold transition-all"
                    href="tel:02222160080"
                  >
                    Dial
                  </a>
                </div>

                {/* State Nodal Email */}
                <div className="p-3 rounded-xl bg-white/5 border border-white/10">
                  <span className="text-[11px] text-surface-variant uppercase font-bold block">State Cyber Nodal Officer</span>
                  <span className="font-mono text-xs text-secondary-fixed break-all">sp.cyber-mah@gov.in</span>
                </div>
              </div>

              <div className="pt-2 text-[11px] text-outline-variant leading-relaxed">
                Equipped with 24x7 Citizen Escalation Matrix compliant with RBI Master Direction on Unauthorized Electronic Banking Transactions.
              </div>
            </div>

            {/* File New Complaint CTA */}
            <div className="bg-surface-card border border-border-subtle rounded-2xl p-5 shadow-sm text-center space-y-2">
              <h4 className="font-title-md text-title-md font-bold text-on-surface">Faced another cyber incident?</h4>
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                File a new emergency report to trigger instant forensic collection.
              </p>
              <Link
                to="/report-fraud"
                className="inline-flex items-center gap-1.5 font-label-md text-label-md font-bold text-danger-red hover:underline pt-1"
              >
                <span className="material-symbols-outlined text-[16px]">add_alert</span>
                Submit New Fraud Report &rarr;
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* PDF PREVIEW MODAL */}
      {pdfModalOpen && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-surface-card rounded-2xl border border-border-subtle shadow-2xl max-w-2xl w-full p-6 relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setPdfModalOpen(false)}
              className="absolute top-4 right-4 text-outline hover:text-on-surface"
              type="button"
            >
              <span className="material-symbols-outlined text-[22px]">close</span>
            </button>

            <div className="border-b border-border-subtle pb-4 mb-4">
              <span className="font-label-sm text-label-sm font-bold uppercase tracking-wider text-primary">
                Government of India • Ministry of Home Affairs
              </span>
              <h3 className="font-headline-sm text-headline-sm font-bold text-helpline-navy">
                National Cyber Crime Reporting Portal (1930) Acknowledgement Slip
              </h3>
            </div>

            <div className="bg-surface-canvas p-4 rounded-xl border border-border-subtle font-body-sm text-body-sm space-y-3 font-mono">
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span>INCIDENT REFERENCE:</span>
                <span className="font-bold text-on-surface">{incident.ref}</span>
              </div>
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span>NCRP COMPLAINT ID:</span>
                <span className="font-bold text-on-surface">{incident.ncrpAck}</span>
              </div>
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span>COMPLAINANT NAME:</span>
                <span className="font-bold text-on-surface">{incident.citizenName}</span>
              </div>
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span>REGISTERED MOBILE:</span>
                <span className="font-bold text-on-surface">{incident.mobile}</span>
              </div>
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span>DEFRAUDED AMOUNT:</span>
                <span className="font-bold text-on-surface">INR ₹{incident.amount.toLocaleString('en-IN')}</span>
              </div>
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span>BENEFICIARY ACCOUNT LIEN:</span>
                <span className="font-bold text-secondary">ACTIVE (Section 91 CrPC)</span>
              </div>
              <div className="pt-2 text-[11px] text-outline leading-relaxed">
                Notice: This digital acknowledgement is issued under the Citizen Financial Cyber Fraud Reporting System. Beneficiary banks are statutorily commanded to hold lien on defrauded sums pending jurisdictional magistrate order.
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => window.print()}
                className="px-4 py-2 rounded-xl bg-surface-container hover:bg-surface-container-high font-label-md text-label-md font-bold text-on-surface flex items-center gap-1.5"
              >
                <span className="material-symbols-outlined text-[16px]">print</span>
                Print Document
              </button>
              <button
                type="button"
                onClick={() => {
                  alert('Acknowledgement slip downloaded to your device.')
                  setPdfModalOpen(false)
                }}
                className="px-4 py-2 rounded-xl bg-primary-container hover:bg-primary font-label-md text-label-md font-bold text-white flex items-center gap-1.5 shadow-sm"
              >
                <span className="material-symbols-outlined text-[16px]">download</span>
                Download Official PDF
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
