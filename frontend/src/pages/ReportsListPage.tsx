import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { listReports, deleteReport, type ApiError } from '../api/client'
import type { Classification, ReportListItem, ReportListResponse } from '../api/types'
import { RiskBadge } from '../components/badges'

export default function ReportsListPage() {
  const [data, setData] = useState<ReportListResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filterClass, setFilterClass] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [deletingId, setDeletingId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    listReports(100)
      .then((d) => {
        if (!cancelled) setData(d)
      })
      .catch(() => {
        if (!cancelled) setError('Could not load reports. Make sure the backend server is running.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  async function handleDelete(reportId: string, e: React.MouseEvent) {
    e.preventDefault()
    e.stopPropagation()
    if (!confirm(`Are you sure you want to delete report ${reportId}?`)) return
    setDeletingId(reportId)
    try {
      await deleteReport(reportId)
      setData((prev) =>
        prev
          ? {
              count: prev.count - 1,
              reports: prev.reports.filter((r) => r.report_id !== reportId),
            }
          : prev
      )
    } catch (err) {
      alert(`Could not delete report: ${(err as ApiError).message}`)
    } finally {
      setDeletingId(null)
    }
  }

  const reports = data?.reports || []
  const filtered = reports.filter((r: ReportListItem) => {
    if (filterClass !== 'all' && r.classification !== filterClass) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      const domain = (r.registrable_domain || '').toLowerCase()
      const url = (r.normalized_url || '').toLowerCase()
      const id = (r.report_id || '').toLowerCase()
      return domain.includes(q) || url.includes(q) || id.includes(q)
    }
    return true
  })

  return (
    <div className="w-full max-w-[1200px] mx-auto px-space-md md:px-margin py-space-xl flex flex-col gap-space-lg">
      {/* Header */}
      <div className="bg-surface-card border border-border-subtle rounded-2xl p-space-md md:p-space-lg shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary-container/30 border border-secondary text-secondary font-label-md text-label-md mb-2">
              <span className="material-symbols-outlined text-[16px] material-symbols-fill">folder_supervised</span>
              <span>National Citizen Cyber Defense Archive</span>
            </div>
            <h1 className="font-headline-lg text-headline-lg font-extrabold text-primary tracking-tight">
              Stored Evidence Reports &amp; Threat Telemetry
            </h1>
            <p className="font-body-md text-body-md text-on-surface-variant mt-1 max-w-2xl leading-relaxed">
              Every analyzed URL and message is recorded with complete cryptographic integrity, forensic findings, and correlation status.
            </p>
          </div>
          <Link
            to="/"
            className="inline-flex items-center justify-center gap-1.5 bg-primary-container hover:bg-primary text-on-primary font-label-lg text-label-lg px-5 py-2.5 rounded-xl transition-all shadow-md self-start md:self-auto font-bold active:scale-95"
          >
            <span className="material-symbols-outlined text-[18px]">add_link</span>
            Scan New Target
          </Link>
        </div>

        {/* Filter and Search Bar */}
        <div className="mt-space-md pt-space-md border-t border-border-subtle flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="font-label-sm text-label-sm font-bold text-outline uppercase mr-1">Filter:</span>
            {[
              { id: 'all', label: 'All' },
              { id: 'confirmed_malicious', label: 'Confirmed Threat' },
              { id: 'high_risk', label: 'High Risk' },
              { id: 'suspicious', label: 'Suspicious' },
              { id: 'low_risk', label: 'Verified Safe' },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setFilterClass(f.id)}
                type="button"
                className={`px-3 py-1.5 rounded-lg font-label-md text-label-md font-bold transition-colors ${
                  filterClass === f.id
                    ? 'bg-primary-container text-white'
                    : 'bg-surface-container-low text-on-surface hover:bg-surface-container'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          <div className="relative min-w-[240px]">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-[18px]">
              search
            </span>
            <input
              type="text"
              placeholder="Filter by domain or URL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 rounded-xl border border-border-subtle bg-surface-canvas font-body-sm text-body-sm focus:border-primary-container focus:ring-0 outline-hidden"
            />
          </div>
        </div>
      </div>

      {/* Reports Table / Card List */}
      <div className="bg-surface-card border border-border-subtle rounded-2xl p-space-md shadow-sm overflow-hidden">
        {loading && (
          <div className="py-12 text-center text-on-surface-variant flex flex-col items-center gap-2">
            <span className="material-symbols-outlined text-[32px] text-primary animate-spin">refresh</span>
            <span className="font-title-md text-title-md font-semibold">Loading stored evidence reports...</span>
          </div>
        )}

        {error && (
          <div className="p-4 rounded-xl bg-red-50 text-danger-red border border-red-200 text-xs">
            {error}
          </div>
        )}

        {!loading && filtered.length === 0 && (
          <div className="py-12 text-center text-on-surface-variant flex flex-col items-center gap-2">
            <span className="material-symbols-outlined text-[36px] text-outline">search_off</span>
            <p className="font-title-md text-title-md font-bold text-on-surface">No reports match your selection</p>
            <p className="font-body-sm text-body-sm text-outline">Try clearing the search query or scan a new website.</p>
          </div>
        )}

        {!loading && filtered.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-body-sm text-body-sm">
              <thead>
                <tr className="border-b border-border-subtle text-outline font-label-sm text-label-sm uppercase tracking-wider">
                  <th className="py-3 px-3">Verdict</th>
                  <th className="py-3 px-3">Analyzed Target / Domain</th>
                  <th className="py-3 px-3">Type</th>
                  <th className="py-3 px-3">Findings</th>
                  <th className="py-3 px-3">Scanned Time</th>
                  <th className="py-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {filtered.map((r) => (
                  <tr key={r.report_id} className="hover:bg-surface-canvas transition-colors group">
                    <td className="py-3 px-3 shrink-0">
                      <RiskBadge classification={r.classification as Classification} />
                    </td>
                    <td className="py-3 px-3 max-w-xs sm:max-w-md truncate">
                      <Link
                        to={`/reports/${r.report_id}`}
                        className="font-mono text-xs font-bold text-primary hover:underline block truncate"
                      >
                        {r.registrable_domain || r.normalized_url || r.report_id}
                      </Link>
                      {r.normalized_url && r.registrable_domain && (
                        <span className="text-[11px] text-outline truncate block font-mono">
                          {r.normalized_url}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 uppercase text-[11px] font-bold text-outline">
                      {r.input_type}
                    </td>
                    <td className="py-3 px-3 text-xs font-semibold text-on-surface">
                      {r.findings_count} item(s)
                    </td>
                    <td className="py-3 px-3 text-xs text-outline whitespace-nowrap">
                      {new Date(r.created_at).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          to={`/reports/${r.report_id}`}
                          className="px-2.5 py-1 rounded-lg bg-surface-container hover:bg-surface-container-high text-primary font-label-sm text-label-sm font-bold"
                        >
                          View
                        </Link>
                        <button
                          type="button"
                          onClick={(e) => handleDelete(r.report_id, e)}
                          disabled={deletingId === r.report_id}
                          className="p-1 text-outline hover:text-danger-red transition-colors"
                          title="Delete report"
                        >
                          <span className="material-symbols-outlined text-[16px]">delete</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
