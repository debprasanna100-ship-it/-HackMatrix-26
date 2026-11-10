export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type Classification =
  | 'low_risk'
  | 'suspicious'
  | 'high_risk'
  | 'confirmed_malicious'
  | 'inconclusive'

export type FindingCategory =
  | 'normalization'
  | 'domain'
  | 'fetch'
  | 'tls'
  | 'intel'
  | 'headers'
  | 'message'
  | 'correlation'
  | 'dns'
  | 'system'

export interface Finding {
  id: string
  title: string
  severity: Severity
  category: FindingCategory
  weight: number
  evidence: string[]
  source: string
  check_succeeded: boolean
}

export interface NormalizedTarget {
  url: string
  scheme: string
  host: string
  original_host: string
  unicode_host: string | null
  port: number | null
  path: string
  query: string
  is_ip_literal: boolean
  ip: string | null
  registrable_domain: string | null
  suffix: string | null
  subdomain: string | null
  notes: string[]
}

export interface FetchHop {
  url: string
  status: number | null
  ok: boolean
  location: string | null
  content_type: string | null
  server: string | null
  resolved_ips: string[]
  peer_ip: string | null
  elapsed_ms: number
  bytes_read: number
  note: string | null
}

export interface FetchSummary {
  final_url: string | null
  status_code: number | null
  success: boolean
  ok: boolean
  error_kind: string
  error: string | null
  content_type: string | null
  title: string | null
  total_bytes: number
  elapsed_ms: number
}

export interface Coverage {
  attempted: number
  completed: number
  completed_checks: string[]
  unavailable_checks: string[]
  failed_checks: string[]
}

export interface IntegrityInfo {
  algorithm: string
  canonical_json_sha256: string
  note: string
}

export interface TlsSummary {
  hostname: string
  san_dns: string[]
  issuer: string
  issuer_common_name: string
  issuer_ca: boolean
  public_key_type: string
  public_key_size: number | null
  signature_algorithm: string
  days_remaining: number | null
  is_self_signed: boolean
  chain_length: number
  chain: string[]
  cert_sha256: string
  errors: string[]
  note: string
}

export interface ThreatIntelSummary {
  checks_performed: string[]
  providers: Record<string, string>
  authoritative_hits: string[]
  total_findings: number
  note: string
}

export interface CtHistorySummary {
  domain: string
  records_found: number
  most_recent: string | null
  error: string | null
  note: string
}

export interface ScoringSummary {
  score: number
  high: number
  medium: number
  low: number
  authoritative_hits: number
  key_checks_failed: string[]
  key_checks_unavailable: string[]
}

export interface ExplanationClaim {
  claim: string
  finding_ids: string[]
}

export interface ExplanationResult {
  summary: string
  claims: ExplanationClaim[]
  caveats: string[]
  recommended_actions: string[]
  generated_by: 'llm' | 'rule-based-fallback'
  model: string | null
  stripped_claims: number
  fallback_reason: string | null
}

export interface AnalysisReport {
  schema_version: string
  report_id: string
  created_at: string
  input_type: 'url' | 'message'
  raw_input: string
  normalized: NormalizedTarget | null
  classification: Classification
  classification_rationale: string
  findings: Finding[]
  redirect_chain: FetchHop[]
  fetch: FetchSummary | null
  tls: TlsSummary | null
  threat_intel: ThreatIntelSummary
  ct_history: CtHistorySummary
  scoring: ScoringSummary
  explanation: ExplanationResult | null
  coverage: Coverage
  recommended_actions: string[]
  limitations: string[]
  integrity: IntegrityInfo | null
  extras: Record<string, unknown>
}

export interface ReportListItem {
  report_id: string
  created_at: string
  input_type: string
  normalized_url: string | null
  registrable_domain: string | null
  classification: Classification
  findings_count: number
}

export interface ReportListResponse {
  count: number
  reports: ReportListItem[]
}

export interface ChainCommitment {
  report_id: string
  report_hash: string
  tx_hash: string
  contract_address: string
  chain_id: number
  block_number: number
  gas_used: number
  committed_at: string
}

export interface OnChainInfo {
  exists: boolean
  reporter?: string
  submitted_at?: number
  category?: string
  status?: string
  revision_count?: number
}

export interface VerifyResult {
  identifier: string
  chain_enabled: boolean
  mode: 'hash' | 'report_id' | null
  report_hash: string | null
  integrity_match: boolean | null
  on_chain: OnChainInfo | null
  commitment: ChainCommitment | null
  note: string
}

/** Result of POST /api/v1/verify/report (supplied report JSON verification). */
export interface SuppliedVerifyResult {
  mode: 'supplied_report'
  chain_enabled: boolean
  recomputed_hash: string
  integrity_match: boolean | null
  hash_match: boolean | null
  on_chain: OnChainInfo | null
  note: string
}

export interface CorrelationMatch {
  kind: string
  value: string
  prior_count: number
  report_ids: string[]
  prior_classifications: string[]
}

export interface CorrelationResult {
  report_id: string
  shared_indicators: CorrelationMatch[]
  similar_reports: { report_id: string; text_similarity: number }[]
  prior: Record<string, unknown>
  summary: string
  note: string
}
