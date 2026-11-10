import type { Classification, Severity } from '../api/types'

export function RiskBadge({ classification }: { classification: Classification }) {
  switch (classification) {
    case 'confirmed_malicious':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-red-100 text-danger-red border border-red-200">
          <span className="material-symbols-outlined material-symbols-fill text-[14px]">gpp_bad</span>
          Confirmed Threat
        </span>
      )
    case 'high_risk':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-red-100 text-danger-red border border-red-200">
          <span className="material-symbols-outlined text-[14px]">warning</span>
          High Risk
        </span>
      )
    case 'suspicious':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-100 text-amber-900 border border-amber-200">
          <span className="material-symbols-outlined text-[14px]">report_problem</span>
          Suspicious
        </span>
      )
    case 'low_risk':
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-100 text-emerald-800 border border-emerald-200">
          <span className="material-symbols-outlined material-symbols-fill text-[14px]">verified</span>
          Verified Safe
        </span>
      )
    case 'inconclusive':
    default:
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-surface-container text-on-surface-variant border border-border-subtle">
          <span className="material-symbols-outlined text-[14px]">help</span>
          Inconclusive
        </span>
      )
  }
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  switch (severity) {
    case 'critical':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-red-100 text-danger-red">
          Critical
        </span>
      )
    case 'high':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-orange-100 text-orange-800">
          High
        </span>
      )
    case 'medium':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-amber-100 text-amber-800">
          Medium
        </span>
      )
    case 'low':
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-blue-100 text-blue-800">
          Low
        </span>
      )
    case 'info':
    default:
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-slate-100 text-slate-700">
          Info
        </span>
      )
  }
}

export function CheckStatus({ succeeded }: { succeeded: boolean }) {
  return succeeded ? (
    <span className="inline-flex items-center gap-1 text-[11px] text-secondary font-semibold">
      <span className="material-symbols-outlined text-[14px]">check_circle</span>
      Verified
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-[11px] text-outline font-semibold">
      <span className="material-symbols-outlined text-[14px]">cancel</span>
      Skipped / Inconclusive
    </span>
  )
}

export function RiskHint({ classification }: { classification: Classification }) {
  switch (classification) {
    case 'confirmed_malicious':
      return (
        <div className="bg-red-50 border border-red-200 rounded-xl p-3 flex items-start gap-2.5 text-red-900 text-xs sm:text-sm">
          <span className="material-symbols-outlined material-symbols-fill text-danger-red text-[20px] shrink-0">
            block
          </span>
          <div>
            <strong>CONFIRMED BY THREAT FEEDS:</strong> An authoritative threat-intelligence source has
            matched this target. Do NOT enter OTP, UPI PIN, Internet Banking Password, or ATM PIN. If you
            already shared details or lost money, call <strong>1930</strong> immediately (Golden Hour:
            2 hours) to freeze fraud accounts.
          </div>
        </div>
      )
    case 'high_risk':
      return (
        <div className="bg-red-50 border border-red-200 rounded-xl p-3 flex items-start gap-2.5 text-red-900 text-xs sm:text-sm">
          <span className="material-symbols-outlined material-symbols-fill text-danger-red text-[20px] shrink-0">
            block
          </span>
          <div>
            <strong>STRONG RISK INDICATORS:</strong> Do NOT enter OTP, UPI PIN, Internet Banking Password,
            or ATM PIN on this destination, and do not download or install anything it offers. If you
            already shared details, call <strong>1930</strong> immediately.
          </div>
        </div>
      )
    case 'suspicious':
      return (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-3 flex items-start gap-2.5 text-amber-900 text-xs sm:text-sm">
          <span className="material-symbols-outlined text-safety-amber text-[20px] shrink-0">
            warning
          </span>
          <div>
            <strong>VERIFY INDEPENDENTLY:</strong> Indicators of concern were found. Verify the destination
            through the organisation's official channels before acting — never authorize UPI auto-debits or
            install remote-access apps at a link's urging.
          </div>
        </div>
      )
    case 'low_risk':
      return (
        <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 flex items-start gap-2.5 text-emerald-900 text-xs sm:text-sm">
          <span className="material-symbols-outlined material-symbols-fill text-secondary text-[20px] shrink-0">
            verified
          </span>
          <div>
            <strong>NO SIGNIFICANT INDICATORS</strong> were found in the completed checks — this is
            <strong> not proof of safety</strong>. Legitimate appearance can be imitated; always verify the
            destination independently before entering credentials or payments.
          </div>
        </div>
      )
    case 'inconclusive':
      return (
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 flex items-start gap-2.5 text-slate-800 text-xs sm:text-sm">
          <span className="material-symbols-outlined text-outline text-[20px] shrink-0">
            help
          </span>
          <div>
            <strong>INCONCLUSIVE:</strong> A required check (page fetch or threat-feed availability) did not
            complete, so no verdict can be issued. Inconclusive means <strong>unknown, not safe</strong> —
            treat the destination with the same caution as before.
          </div>
        </div>
      )
    default:
      return null
  }
}
