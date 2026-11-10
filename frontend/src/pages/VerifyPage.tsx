import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, verifyIdentifier, verifyReportJson } from '../api/client'
import type { SuppliedVerifyResult, VerifyResult } from '../api/types'

type VerifyMode = 'identifier' | 'json'

export default function VerifyPage() {
  const [mode, setMode] = useState<VerifyMode>('identifier')
  const [identifier, setIdentifier] = useState('')
  const [reportJson, setReportJson] = useState('')
  const [expectedHash, setExpectedHash] = useState('')
  const [result, setResult] = useState<VerifyResult | SuppliedVerifyResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setResult(null)
    setLoading(true)
    try {
      if (mode === 'identifier') {
        setResult(await verifyIdentifier(identifier))
      } else {
        setResult(await verifyReportJson(reportJson, expectedHash))
      }
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err
          : new ApiError('unknown', 'Verification request failed. Please try again.', 0)
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="w-full max-w-[1200px] mx-auto px-space-md md:px-margin py-space-xl flex flex-col gap-space-xl">
      {/* Hero Header */}
      <section className="bg-surface-card border border-border-subtle rounded-2xl p-space-md md:p-space-lg shadow-sm text-center max-w-3xl mx-auto w-full space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary-container/30 border border-secondary text-secondary font-label-md text-label-md">
          <span className="material-symbols-outlined text-[16px] material-symbols-fill">verified</span>
          <span>Cryptographic Proof &amp; On-Chain Integrity</span>
        </div>

        <h1 className="font-headline-lg text-headline-lg font-extrabold text-primary tracking-tight">
          Verify Evidence Integrity &amp; Blockchain Seal
        </h1>

        <p className="font-body-md text-body-md text-on-surface-variant max-w-xl mx-auto leading-relaxed">
          The canonical hash is recomputed and matched against the ThreatRegistry commitment. "The hash exists on-chain" and "these contents produce that hash" are verified as independent mathematical facts.
        </p>

        {/* Mode Selector */}
        <div className="flex items-center justify-center gap-2 pt-2">
          <button
            type="button"
            onClick={() => {
              setMode('identifier')
              setResult(null)
              setError(null)
            }}
            className={`px-4 py-2 rounded-xl font-label-md text-label-md font-bold transition-all ${
              mode === 'identifier'
                ? 'bg-primary-container text-white shadow-sm'
                : 'bg-surface-container-low text-on-surface hover:bg-surface-container'
            }`}
          >
            By Report ID or On-Chain Hash
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('json')
              setResult(null)
              setError(null)
            }}
            className={`px-4 py-2 rounded-xl font-label-md text-label-md font-bold transition-all ${
              mode === 'json'
                ? 'bg-primary-container text-white shadow-sm'
                : 'bg-surface-container-low text-on-surface hover:bg-surface-container'
            }`}
          >
            By Uploaded JSON Dossier
          </button>
        </div>
      </section>

      {/* Main Verification Form */}
      <section className="max-w-3xl mx-auto w-full bg-surface-card border border-border-subtle rounded-2xl p-space-md sm:p-space-lg shadow-sm">
        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === 'identifier' ? (
            <div>
              <label className="block font-label-md text-label-md font-bold text-on-surface mb-1.5">
                Report ID or 64-character SHA-256 Digest
              </label>
              <input
                type="text"
                required
                placeholder="e.g. e82d30f157ca48a4a203aeed51d8f6ba or 0xab12...(64 hex)"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                maxLength={80}
                className="w-full bg-surface-canvas border border-border-subtle rounded-xl px-3.5 py-3 font-mono font-body-sm text-body-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
              />
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block font-label-md text-label-md font-bold text-on-surface mb-1.5">
                  Report JSON (exported from a report page)
                </label>
                <textarea
                  rows={6}
                  required
                  placeholder='{"schema_version": "1.0", "report_id": "...", ...}'
                  value={reportJson}
                  onChange={(e) => setReportJson(e.target.value)}
                  className="w-full bg-surface-canvas border border-border-subtle rounded-xl px-3.5 py-2.5 font-mono font-body-sm text-body-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                ></textarea>
              </div>
              <div>
                <label className="block font-label-md text-label-md font-bold text-on-surface mb-1.5">
                  Optional Expected SHA-256 Hash
                </label>
                <input
                  type="text"
                  placeholder="Leave empty to use the hash embedded in the report itself"
                  value={expectedHash}
                  onChange={(e) => setExpectedHash(e.target.value)}
                  className="w-full bg-surface-canvas border border-border-subtle rounded-xl px-3.5 py-2.5 font-mono font-body-sm text-body-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                />
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-xl bg-red-50 text-danger-red border border-red-200 text-xs">
              <strong>{error.code}:</strong> {error.message}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || (mode === 'identifier' ? !identifier.trim() : !reportJson.trim())}
            className="w-full inline-flex items-center justify-center gap-2 bg-primary-container hover:bg-primary text-white font-label-lg text-label-lg font-bold py-3.5 px-6 rounded-xl transition-all shadow-md active:scale-95 disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[18px]">
              {loading ? 'sync' : 'fingerprint'}
            </span>
            {loading ? 'Verifying Cryptographic Ledger...' : 'Verify Cryptographic Proof'}
          </button>
        </form>

        {/* Case A: Supplied Report JSON verification result */}
        {result && result.mode === 'supplied_report' && (
          <div className="mt-8 pt-6 border-t border-border-subtle space-y-4 animate-in fade-in duration-300">
            <h3 className="font-title-md text-title-md font-bold text-helpline-navy">Supplied Report Verification</h3>

            <div className="bg-surface-canvas p-4 rounded-xl border border-border-subtle font-body-sm text-body-sm space-y-2.5 font-mono">
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span className="text-outline">RECOMPUTED HASH:</span>
                <span className="font-bold text-on-surface break-all">{result.recomputed_hash}</span>
              </div>

              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span className="text-outline">INTEGRITY FIELD MATCH:</span>
                <span>
                  {result.integrity_match === null ? (
                    <span className="text-outline">— (No integrity metadata)</span>
                  ) : result.integrity_match ? (
                    <span className="text-secondary font-bold">YES — Contents unchanged</span>
                  ) : (
                    <span className="text-danger-red font-bold">TAMPERED — Contents altered</span>
                  )}
                </span>
              </div>

              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span className="text-outline">EXPECTED HASH MATCH:</span>
                <span>
                  {result.hash_match === null ? (
                    <span className="text-outline">— (No expected hash supplied)</span>
                  ) : result.hash_match ? (
                    <span className="text-secondary font-bold">YES — Matches expected hash</span>
                  ) : (
                    <span className="text-danger-red font-bold">NO — Different hash generated</span>
                  )}
                </span>
              </div>

              {result.on_chain && (
                <div className={`p-3 rounded-lg border ${result.on_chain.exists ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-surface-container border-border-subtle text-outline'}`}>
                  <p className="font-bold">
                    {result.on_chain.exists
                      ? '✅ The recomputed hash exists on-chain in ThreatRegistry.'
                      : '❌ The recomputed hash is not committed on-chain.'}
                  </p>
                  {result.on_chain.exists && (
                    <div className="mt-2 space-y-1 text-[11px]">
                      <div>Reporter: <code>{result.on_chain.reporter}</code></div>
                      <div>Category: {result.on_chain.category}</div>
                      <div>Status: {result.on_chain.status}</div>
                    </div>
                  )}
                </div>
              )}

              {result.note && <p className="text-[11px] text-outline pt-1">{result.note}</p>}
            </div>
          </div>
        )}

        {/* Case B: Identifier / Stored Report verification result */}
        {result && result.mode !== 'supplied_report' && (
          <div className="mt-8 pt-6 border-t border-border-subtle space-y-4 animate-in fade-in duration-300">
            <h3 className="font-title-md text-title-md font-bold text-helpline-navy">Stored Report Verification</h3>

            <div className="bg-surface-canvas p-4 rounded-xl border border-border-subtle font-body-sm text-body-sm space-y-2.5 font-mono">
              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span className="text-outline">VERIFICATION MODE:</span>
                <span className="font-bold text-on-surface">
                  {result.mode === 'hash' ? 'Raw On-Chain Hash' : 'Stored Report (Hash Recomputed)'}
                </span>
              </div>

              <div className="flex justify-between border-b border-border-subtle pb-2">
                <span className="text-outline">REPORT HASH:</span>
                <span className="font-bold text-on-surface break-all">{result.report_hash ?? '—'}</span>
              </div>

              {result.mode === 'report_id' && (
                <div className="flex justify-between border-b border-border-subtle pb-2">
                  <span className="text-outline">INTEGRITY CHECK:</span>
                  <span>
                    {result.integrity_match === null ? (
                      <span className="text-outline">—</span>
                    ) : result.integrity_match ? (
                      <span className="text-secondary font-bold">YES — Stored report matches recorded hash</span>
                    ) : (
                      <span className="text-danger-red font-bold">TAMPERED — Stored report does not match hash</span>
                    )}
                  </span>
                </div>
              )}

              {result.on_chain && (
                <div className={`p-3 rounded-lg border ${result.on_chain.exists ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-surface-container border-border-subtle text-outline'}`}>
                  <p className="font-bold">
                    {result.on_chain.exists
                      ? '✅ Found on-chain — this exact report hash is committed in ThreatRegistry.'
                      : '❌ Not found on-chain — no commitment exists for this hash.'}
                  </p>
                  {result.on_chain.exists && (
                    <div className="mt-2 space-y-1 text-[11px]">
                      <div>Reporter: <code>{result.on_chain.reporter}</code></div>
                      <div>Category: {result.on_chain.category}</div>
                      <div>Status: {result.on_chain.status}</div>
                    </div>
                  )}
                </div>
              )}

              {result.commitment && (
                <div className="p-3 bg-surface-card rounded-lg border border-border-subtle space-y-1 text-[11px]">
                  <div>Commitment Tx: <code className="break-all">{result.commitment.tx_hash}</code></div>
                  <div>Contract: <code>{result.commitment.contract_address}</code></div>
                  <div>Block: {result.commitment.block_number} (Chain ID: {result.commitment.chain_id})</div>
                </div>
              )}

              {result.note && <p className="text-[11px] text-outline pt-1">{result.note}</p>}
            </div>

            {result.mode === 'report_id' && (
              <div className="text-center pt-2">
                <Link
                  to={`/reports/${result.identifier}`}
                  className="font-label-md text-label-md font-bold text-primary hover:underline"
                >
                  Open Full Evidence Dossier &rarr;
                </Link>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
