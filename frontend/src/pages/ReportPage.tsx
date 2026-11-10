import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  commitReport,
  correlateReport,
  deleteReport,
  getReport,
  verifyIdentifier,
  type ApiError,
} from '../api/client'
import type {
  AnalysisReport,
  ChainCommitment,
  CorrelationResult,
  Finding,
  VerifyResult,
} from '../api/types'
import { CheckStatus, RiskBadge, RiskHint, SeverityBadge } from '../components/badges'

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <details className="border border-border-subtle rounded-xl p-space-md bg-surface-canvas hover:bg-surface-card transition-colors group">
      <summary className="flex items-center justify-between cursor-pointer list-none">
        <div className="flex items-center gap-2.5">
          <SeverityBadge severity={finding.severity} />
          <span className="font-title-md text-title-md font-bold text-on-surface">{finding.title}</span>
        </div>
        <div className="flex items-center gap-3">
          <code className="text-[11px] text-outline font-mono">{finding.id}</code>
          <CheckStatus succeeded={finding.check_succeeded} />
          <span className="material-symbols-outlined text-outline text-[16px] group-open:rotate-180 transition-transform">
            expand_more
          </span>
        </div>
      </summary>
      <div className="mt-3 pt-3 border-t border-border-subtle font-body-sm text-body-sm space-y-2">
        <div className="flex items-center justify-between text-outline">
          <span>Source: <strong className="text-on-surface">{finding.source}</strong></span>
          <span>Category: <strong className="text-on-surface">{finding.category}</strong></span>
          <span>Weight: <strong className="text-on-surface">{finding.weight}</strong></span>
        </div>
        {finding.evidence && finding.evidence.length > 0 && (
          <div>
            <span className="font-bold text-on-surface block mb-1">Evidence Trail:</span>
            <ul className="list-disc list-inside space-y-1 text-on-surface-variant font-mono text-[11px] bg-surface-container-low p-2.5 rounded-lg">
              {finding.evidence.map((e, idx) => (
                <li key={idx} className="break-all">{e}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </details>
  )
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [committing, setCommitting] = useState(false)
  const [commitment, setCommitment] = useState<ChainCommitment | null>(null)
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null)

  const [correlating, setCorrelating] = useState(false)
  const [correlation, setCorrelation] = useState<CorrelationResult | null>(null)

  useEffect(() => {
    if (!id) return
    let cancelled = false

    getReport(id)
      .then((rep) => {
        if (cancelled) return
        setReport(rep)
        verifyIdentifier(rep.report_id)
          .then((v) => {
            if (!cancelled) setVerifyResult(v)
          })
          .catch(() => {})
      })
      .catch((err) => {
        if (!cancelled) {
          setError((err as ApiError).message || 'Failed to load report.')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [id])

  async function handleCommit() {
    if (!report) return
    setCommitting(true)
    try {
      const comm = await commitReport(report.report_id)
      setCommitment(comm)
      const freshVerify = await verifyIdentifier(report.report_id)
      setVerifyResult(freshVerify)
    } catch (err) {
      alert(`Commitment failed: ${(err as ApiError).message}`)
    } finally {
      setCommitting(false)
    }
  }

  async function handleCorrelate() {
    if (!report) return
    setCorrelating(true)
    try {
      const res = await correlateReport(report.report_id)
      setCorrelation(res)
    } catch (err) {
      alert(`Correlation failed: ${(err as ApiError).message}`)
    } finally {
      setCorrelating(false)
    }
  }

  async function handleDelete() {
    if (!report) return
    if (!confirm('Permanently delete this report?')) return
    try {
      await deleteReport(report.report_id)
      navigate('/reports')
    } catch (err) {
      alert(`Delete failed: ${(err as ApiError).message}`)
    }
  }

  if (loading) {
    return (
      <div className="w-full max-w-[1200px] mx-auto px-space-md py-16 text-center flex flex-col items-center gap-3">
        <span className="material-symbols-outlined text-[36px] text-primary animate-spin">refresh</span>
        <p className="font-title-md text-title-md font-bold text-on-surface">Compiling Forensic Evidence Dossier...</p>
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className="w-full max-w-[1200px] mx-auto px-space-md py-16 text-center space-y-4">
        <div className="inline-flex p-3 rounded-full bg-red-100 text-danger-red">
          <span className="material-symbols-outlined text-[32px]">error</span>
        </div>
        <h2 className="font-headline-sm text-headline-sm font-bold text-on-surface">Report Not Found or Unreachable</h2>
        <p className="font-body-sm text-body-sm text-outline max-w-md mx-auto">{error || 'Could not find the requested report.'}</p>
        <Link
          to="/"
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-primary-container text-on-primary font-label-md text-label-md font-bold rounded-xl"
        >
          &larr; Back to Scanner
        </Link>
      </div>
    )
  }

  const isPhish = report.classification === 'confirmed_malicious' || report.classification === 'high_risk'
  const isSuspicious = report.classification === 'suspicious'

  return (
    <div className="w-full max-w-[1200px] mx-auto px-space-md md:px-margin py-space-xl flex flex-col gap-space-xl">
      {/* Dossier Header Banner */}
      <section className="bg-surface-card border border-border-subtle rounded-2xl shadow-sm overflow-hidden">
        <div
          className={`border-l-[6px] p-space-md sm:p-space-lg border-b border-border-subtle flex flex-col lg:flex-row lg:items-center justify-between gap-space-md ${
            isPhish
              ? 'border-l-danger-red bg-error-container/30'
              : isSuspicious
              ? 'border-l-safety-amber bg-amber-50/70'
              : 'border-l-secondary bg-emerald-50/70'
          }`}
        >
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <RiskBadge classification={report.classification} />
              <span className="font-label-sm text-label-sm text-outline font-mono">
                REF: {report.report_id}
              </span>
              <span className="font-label-sm text-label-sm text-outline">
                • {new Date(report.created_at).toLocaleString()}
              </span>
            </div>

            <h1 className="font-headline-sm text-headline-sm font-extrabold text-helpline-navy break-all mt-1">
              Target: <span className="font-mono">{report.normalized?.url || report.raw_input}</span>
            </h1>

            <p className="font-body-sm text-body-sm text-on-surface-variant max-w-3xl leading-relaxed">
              {report.classification_rationale}
            </p>
          </div>

          {/* Quick Action cluster */}
          <div className="flex items-center gap-2 flex-wrap">
            <a
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-label-md text-label-md font-bold transition-all shadow-sm active:scale-95"
              href={`https://api.whatsapp.com/send?text=${encodeURIComponent(
                `⚠️ Warning: Check this link before opening: ${
                  report.normalized?.url || report.raw_input
                }. Verdict on TrustLens: ${report.classification.toUpperCase()}.`
              )}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              <span className="material-symbols-outlined text-[16px]">share</span>
              WhatsApp Alert
            </a>

            <Link
              to={`/report-fraud?url=${encodeURIComponent(report.normalized?.url || report.raw_input)}`}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-helpline-navy hover:bg-primary-container text-white font-label-md text-label-md font-bold transition-all shadow-sm active:scale-95"
            >
              <span className="material-symbols-outlined text-[16px]">flag</span>
              1930 Cyber Cell
            </Link>

            <button
              type="button"
              onClick={handleCommit}
              disabled={committing || verifyResult?.on_chain?.exists || !!commitment}
              className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-lg font-label-md text-label-md font-bold transition-all border ${
                verifyResult?.on_chain?.exists || commitment
                  ? 'bg-emerald-50 text-secondary border-emerald-300'
                  : 'bg-surface-canvas hover:bg-surface-card text-on-surface border-border-subtle'
              }`}
            >
              <span className="material-symbols-outlined text-[16px]">
                {verifyResult?.on_chain?.exists || commitment ? 'verified' : 'token'}
              </span>
              {verifyResult?.on_chain?.exists || commitment
                ? 'Committed On-Chain'
                : committing
                ? 'Committing...'
                : 'Commit to Chain'}
            </button>

            <button
              type="button"
              onClick={handleCorrelate}
              disabled={correlating}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-canvas hover:bg-surface-card text-on-surface border border-border-subtle font-label-md text-label-md font-bold transition-all"
            >
              <span className="material-symbols-outlined text-[16px]">hub</span>
              {correlating ? 'Correlating...' : 'Correlate'}
            </button>

            <button
              type="button"
              onClick={handleDelete}
              className="p-2 rounded-lg text-outline hover:text-danger-red hover:bg-red-50 transition-colors"
              title="Delete report"
            >
              <span className="material-symbols-outlined text-[18px]">delete</span>
            </button>
          </div>
        </div>

        {/* Citizen Guidance Strip */}
        <div className="p-space-md border-b border-border-subtle">
          <RiskHint classification={report.classification} />
        </div>

        {/* Scoring & Telemetry Highlights Bento */}
        <div className="p-space-md sm:p-space-lg grid grid-cols-2 sm:grid-cols-4 gap-space-md bg-surface-canvas font-body-sm text-body-sm">
          <div className="p-3 bg-surface-card rounded-xl border border-border-subtle">
            <span className="text-outline uppercase font-label-sm text-label-sm font-bold block">Threat Score</span>
            <span className={`font-headline-md text-headline-md font-extrabold ${isPhish ? 'text-danger-red' : 'text-secondary'}`}>
              {report.scoring?.score ?? 0} pts
            </span>
          </div>

          <div className="p-3 bg-surface-card rounded-xl border border-border-subtle">
            <span className="text-outline uppercase font-label-sm text-label-sm font-bold block">Critical / High Hits</span>
            <span className="font-headline-md text-headline-md font-extrabold text-on-surface">
              {(report.scoring?.high ?? 0)}
            </span>
          </div>

          <div className="p-3 bg-surface-card rounded-xl border border-border-subtle">
            <span className="text-outline uppercase font-label-sm text-label-sm font-bold block">Authoritative Feeds</span>
            <span className="font-headline-md text-headline-md font-extrabold text-primary-container">
              {report.scoring?.authoritative_hits ?? 0}
            </span>
          </div>

          <div className="p-3 bg-surface-card rounded-xl border border-border-subtle">
            <span className="text-outline uppercase font-label-sm text-label-sm font-bold block">Checks Completed</span>
            <span className="font-headline-md text-headline-md font-extrabold text-on-surface">
              {report.coverage?.completed ?? 0} / {report.coverage?.attempted ?? 0}
            </span>
          </div>
        </div>
      </section>

      {/* AI Explanation & Recommendations */}
      {report.explanation && (
        <section className="bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-border-subtle pb-3">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-[22px] material-symbols-fill">smart_toy</span>
              <h3 className="font-title-md text-title-md font-bold text-helpline-navy">
                AI Threat Intelligence Synthesis
              </h3>
            </div>
            <span className="font-label-sm text-label-sm text-outline font-mono">
              Model: {report.explanation.model || report.explanation.generated_by}
            </span>
          </div>

          <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
            {report.explanation.summary}
          </p>

          {report.explanation.claims && report.explanation.claims.length > 0 && (
            <div className="space-y-2 pt-2">
              <span className="font-label-sm text-label-sm font-bold text-on-surface uppercase tracking-wider block">
                Evidence-Backed Claims:
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {report.explanation.claims.map((c, i) => (
                  <div key={i} className="p-3 rounded-xl bg-surface-canvas border border-border-subtle font-body-sm text-body-sm">
                    <p className="font-semibold text-on-surface">{c.claim}</p>
                    <span className="text-[10px] text-outline mt-1 block font-mono">
                      Associated findings: {c.finding_ids.join(', ')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.explanation.recommended_actions && report.explanation.recommended_actions.length > 0 && (
            <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 font-body-sm text-body-sm text-amber-900 space-y-1.5">
              <span className="font-bold flex items-center gap-1.5 font-label-md text-label-md">
                <span className="material-symbols-outlined text-[18px]">verified</span>
                Recommended Citizen Actions:
              </span>
              <ul className="list-disc list-inside space-y-1">
                {report.explanation.recommended_actions.map((act, idx) => (
                  <li key={idx}>{act}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {/* Correlation Section */}
      {correlation && (
        <section className="bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg shadow-sm space-y-4">
          <div className="flex items-center gap-2 border-b border-border-subtle pb-3">
            <span className="material-symbols-outlined text-primary-container text-[22px]">hub</span>
            <h3 className="font-title-md text-title-md font-bold text-helpline-navy">
              Syndicated Cyber Campaign Correlation
            </h3>
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {correlation.summary || correlation.note || 'Cross-incident indicator matching complete.'}
          </p>

          {correlation.shared_indicators && correlation.shared_indicators.length > 0 && (
            <div className="space-y-2">
              <span className="font-label-sm text-label-sm font-bold text-on-surface uppercase tracking-wider block">
                Shared Indicators Across Incidents:
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {correlation.shared_indicators.map((ind, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl bg-surface-canvas border border-border-subtle flex items-center justify-between font-body-sm text-body-sm"
                  >
                    <div>
                      <span className="font-mono font-bold text-primary">{ind.value}</span>
                      <p className="text-[11px] text-outline mt-0.5">
                        Kind: {ind.kind} • {ind.prior_count} prior occurrence(s)
                      </p>
                    </div>
                    <span className="font-bold text-danger-red bg-red-50 px-2 py-0.5 rounded text-[11px]">
                      {ind.prior_classifications?.join(', ') || 'Correlated'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {correlation.similar_reports && correlation.similar_reports.length > 0 && (
            <div className="space-y-2 pt-2">
              <span className="font-label-sm text-label-sm font-bold text-on-surface uppercase tracking-wider block">
                Similar Campaign Incidents:
              </span>
              <div className="space-y-2">
                {correlation.similar_reports.map((sim) => (
                  <div
                    key={sim.report_id}
                    className="p-3 rounded-xl bg-surface-canvas border border-border-subtle flex items-center justify-between font-body-sm text-body-sm"
                  >
                    <Link
                      to={`/reports/${sim.report_id}`}
                      className="font-mono font-bold text-primary hover:underline truncate max-w-md"
                    >
                      Report #{sim.report_id}
                    </Link>
                    <span className="font-bold text-primary-container bg-primary-fixed/40 px-2 py-0.5 rounded text-[11px]">
                      {Math.round(sim.text_similarity * 100)}% Similarity
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Detailed Security Findings */}
      <section className="bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-border-subtle pb-3">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-[22px]">checklist</span>
            <h3 className="font-title-md text-title-md font-bold text-helpline-navy">
              Forensic Findings &amp; Heuristic Checks ({report.findings.length})
            </h3>
          </div>
        </div>

        {report.findings.length === 0 ? (
          <p className="font-body-sm text-body-sm text-outline py-4">
            No adverse security findings detected on this target.
          </p>
        ) : (
          <div className="space-y-2.5">
            {report.findings.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </div>
        )}
      </section>

      {/* Network Fetch & TLS Certificate Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-space-lg">
        {/* Network & Redirect Chain */}
        <div className="bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg shadow-sm space-y-4">
          <div className="flex items-center gap-2 border-b border-border-subtle pb-3">
            <span className="material-symbols-outlined text-primary text-[20px]">route</span>
            <h3 className="font-title-md text-title-md font-bold text-helpline-navy">Network Hops &amp; Redirect Chain</h3>
          </div>

          {report.redirect_chain && report.redirect_chain.length > 0 ? (
            <div className="space-y-2 font-body-sm text-body-sm">
              {report.redirect_chain.map((hop, i) => (
                <div key={i} className="p-2.5 bg-surface-canvas rounded-xl border border-border-subtle font-mono text-[11px] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-primary font-bold">Hop #{i + 1}</span>
                    <span className="bg-surface-container px-2 py-0.5 rounded text-[10px]">
                      HTTP {hop.status || 'N/A'}
                    </span>
                  </div>
                  <p className="truncate text-on-surface">{hop.url}</p>
                  <p className="text-outline text-[10px]">
                    IP: {hop.peer_ip || 'Hidden / CDN'} • Elapsed: {hop.elapsed_ms}ms
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p className="font-body-sm text-body-sm text-outline">No HTTP redirect hops recorded.</p>
          )}
        </div>

        {/* TLS/SSL Certificate */}
        <div className="bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg shadow-sm space-y-4">
          <div className="flex items-center gap-2 border-b border-border-subtle pb-3">
            <span className="material-symbols-outlined text-primary text-[20px]">lock</span>
            <h3 className="font-title-md text-title-md font-bold text-helpline-navy">SSL / TLS Certificate Inspector</h3>
          </div>

          {report.tls ? (
            <div className="space-y-2.5 font-body-sm text-body-sm">
              <div className="flex justify-between py-1 border-b border-border-subtle">
                <span className="text-outline">Issuer Org:</span>
                <span className="font-bold text-on-surface">{report.tls.issuer || 'Untrusted'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border-subtle">
                <span className="text-outline">Common Name:</span>
                <span className="font-mono text-on-surface">{report.tls.issuer_common_name || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border-subtle">
                <span className="text-outline">Self-Signed:</span>
                <span className={report.tls.is_self_signed ? 'text-danger-red font-bold' : 'text-secondary font-bold'}>
                  {report.tls.is_self_signed ? 'YES (UNSAFE)' : 'NO'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-border-subtle">
                <span className="text-outline">Days Remaining:</span>
                <span className="font-bold text-on-surface">{report.tls.days_remaining ?? 'Unknown'}</span>
              </div>
              <div className="py-1">
                <span className="text-outline block mb-1">Subject Alternative Names (SAN):</span>
                <div className="flex flex-wrap gap-1">
                  {report.tls.san_dns?.slice(0, 5).map((san, i) => (
                    <span key={i} className="px-1.5 py-0.5 rounded bg-surface-canvas border border-border-subtle font-mono text-[10px]">
                      {san}
                    </span>
                  ))}
                  {(report.tls.san_dns?.length ?? 0) > 5 && (
                    <span className="text-[10px] text-outline">+{report.tls.san_dns.length - 5} more</span>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <p className="font-body-sm text-body-sm text-outline">TLS handshake details unavailable or target uses insecure HTTP.</p>
          )}
        </div>
      </div>

      {/* Cryptographic Integrity & Blockchain Commitment Section */}
      <section className="bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-border-subtle pb-3">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-secondary text-[22px] material-symbols-fill">verified</span>
            <h3 className="font-title-md text-title-md font-bold text-helpline-navy">
              Tamper-Evident Cryptographic Integrity &amp; On-Chain Ledger
            </h3>
          </div>
          <Link
            to="/verify"
            className="font-label-sm text-label-sm font-bold text-primary hover:underline"
          >
            Open Verification Portal &rarr;
          </Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
          <div className="p-3 bg-surface-canvas rounded-xl border border-border-subtle space-y-1">
            <span className="text-outline uppercase font-label-sm text-label-sm font-bold block">
              Canonical JSON SHA-256 Hash
            </span>
            <p className="text-on-surface break-all">
              {report.integrity?.canonical_json_sha256 || 'Hash computing...'}
            </p>
          </div>

          <div className="p-3 bg-surface-canvas rounded-xl border border-border-subtle space-y-1">
            <span className="text-outline uppercase font-label-sm text-label-sm font-bold block">
              Smart Contract Proof Status
            </span>
            {verifyResult?.commitment ? (
              <div>
                <span className="text-secondary font-bold flex items-center gap-1">
                  <span className="material-symbols-outlined text-[16px]">check_circle</span>
                  Committed to Block #{verifyResult.commitment.block_number}
                </span>
                <span className="text-[10px] text-outline block truncate mt-0.5">
                  Tx: {verifyResult.commitment.tx_hash}
                </span>
              </div>
            ) : verifyResult?.on_chain?.exists ? (
              <div>
                <span className="text-secondary font-bold flex items-center gap-1">
                  <span className="material-symbols-outlined text-[16px]">check_circle</span>
                  Verified On-Chain in ThreatRegistry
                </span>
                {verifyResult.on_chain.reporter && (
                  <span className="text-[10px] text-outline block truncate mt-0.5">
                    Reporter: {verifyResult.on_chain.reporter}
                  </span>
                )}
              </div>
            ) : commitment ? (
              <div>
                <span className="text-secondary font-bold flex items-center gap-1">
                  <span className="material-symbols-outlined text-[16px]">check_circle</span>
                  Freshly Committed! (Tx: {commitment.tx_hash.slice(0, 14)}...)
                </span>
              </div>
            ) : (
              <span className="text-outline">
                Not yet committed on-chain. Click "Commit to Chain" above to anchor immutable evidence.
              </span>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
