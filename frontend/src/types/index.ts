export interface User {
  id: number; username: string; display_name: string; role: string; permissions: string[];
  is_active: boolean; created_at: string; last_login_at: string | null; locked: boolean;
}
export interface Meta { app_name: string; tagline: string; version: string; demo_mode: boolean; active_checks_enabled: boolean }

export interface InvestigationSummary {
  id: string; reference: string; title: string; status: string; priority: string; severity: string;
  source_system: string | null; restricted: boolean; pipeline_status: string; risk_score: number | null;
  risk_level: string | null; confidence_score: number | null; confidence_level: string | null; is_synthetic: boolean;
  created_at: string; updated_at: string; owner: string | null; assignees: string[]; event_count: number;
  src_ip: string | null; target: string | null;
}
export interface SiemEvent {
  id: number; source_system: string; original_id: string; ingest_method: string; received_at: string;
  event_time: string | null; title: string; event_type: string; severity: string; severity_raw: string | null;
  src_ip: string | null; dst_ip: string | null; src_port: number | null; dst_port: number | null; protocol: string | null;
  hostname: string | null; attempt_count: number | null; context: Record<string, unknown>; raw_sha256: string;
  is_synthetic: boolean; raw?: Record<string, unknown>;
}
export interface IndicatorLink { id: number; type: string; value: string; scope: string; note: string | null; role: string; extracted_from: string }
export interface Findings {
  network?: { registered_org?: string; network_name?: string; cidr?: string; rir?: string; registration_country?: string; asn?: number; as_name?: string; isp?: string; bgp_prefix?: string };
  geo?: { country?: string; country_code?: string; region?: string; city?: string; latitude?: number; longitude?: number; accuracy_radius_km?: number; precision_note?: string };
  reputation?: { verdict: string; score?: number; raw_score?: string; detections?: number; total_engines?: number; report_count?: number; categories?: string[]; last_reported_at?: string; explanation?: string };
  resolutions?: { type: string; value: string; first_seen?: string; last_seen?: string; temporality: string }[];
  certificates?: { subject_cn?: string; issuer?: string; sans?: string[]; not_before?: string; not_after?: string; reference_url?: string }[];
  related?: { type: string; value: string; relation: string; first_seen?: string; last_seen?: string }[];
  campaigns?: { name: string; reference?: string; source_statement?: string }[];
  services?: { ports: number[]; hostnames: string[]; tags: string[]; vulns: string[]; cpes: string[] };
  tags?: string[]; notes?: string[];
}
export interface EnrichmentResult {
  id: number; evidence_id: string; indicator: string; indicator_type: string; source: string; source_display: string;
  category: string | null; upstream_group: string | null; reliability: number | null; status: string; queried_at: string;
  data_updated_at: string | null; duration_ms: number | null; findings: Findings; reference_url: string | null;
  source_confidence: string | null; error_message: string | null; raw_sha256: string | null; is_synthetic: boolean;
  raw?: unknown; run_number: number; superseded_at: string | null;
}
export interface Relation {
  id: number; from_kind: string; from_value: string; to_kind: string; to_value: string; relation_type: string;
  source: string; observed_at: string | null; temporality: string; confidence: number; evidence_id: string | null; is_synthetic: boolean;
}
export interface RiskFactor { key: string; label: string; value: number | null; weight: number; contribution: number | null; status: string; rationale: string }
export interface Scoring {
  risk_score: number | null; risk_level: string; confidence_score: number; confidence_level: string;
  risk_factors: RiskFactor[]; confidence_factors: { label: string; value: number; weight: number; rationale: string }[];
  confidence_penalties: { label: string; points: number }[]; notes: string[]; summary: string; effective_independent_sources: number;
}
export interface Correlation {
  facts: { statement: string; category: string; evidence_ids: string[]; source: string; is_synthetic: boolean }[];
  agreements: { indicator: string; dimension: string; description: string }[];
  contradictions: { indicator: string; dimension: string; description: string; evidence_ids: string[] }[];
  stale: { source: string; indicator: string; message: string }[];
  missing: string[]; collection_errors: { source: string; indicator: string; status: string; message: string }[]; notes: string[];
}
export interface AIOutput {
  executive_summary: string; initial_event: string;
  observed_indicators: { indicator: string; type: string; note: string }[];
  osint_results: { source: string; summary: string; evidence_ids: string[] }[];
  established_facts: { statement: string; evidence_ids: string[] }[];
  hypotheses: { statement: string; rationale: string; evidence_ids: string[]; how_to_verify: string }[];
  contradictions: { description: string; evidence_ids: string[] }[];
  missing_information: string[]; alternative_hypotheses: { statement: string; rationale: string }[];
  mitre_attack: { technique_id: string; name: string; justification: string; evidence_ids: string[] }[];
  estimated_risk: { level: string; rationale: string }; confidence: { level: string; rationale: string };
  recommended_actions: { action: string; priority: string; requires_human_validation: boolean }[];
  references: { evidence_id: string; source: string; url: string | null }[]; limitations: string[];
  threat_actor_attribution: { actor: string; evidence_ids: string[]; confidence: string; alternatives: string[] }[];
}
export interface Analysis {
  id: number; provider: string; model: string | null; status: string; created_at: string; output: AIOutput | null;
  validation_issues: string[]; injection_flags: { path: string; pattern: string; excerpt: string }[];
  input_sha256: string; data_sent_externally: boolean; error_message: string | null;
}
export interface Note { id: number; kind: string; content: string; created_at: string; author: string }
export interface Report { id: number; investigation_id: string; kind: string; format: string; file_name: string; sha256: string; size_bytes: number; created_at: string; investigation_reference?: string; investigation_title?: string; is_synthetic?: boolean }
export interface TimelineItem { ts: string | null; kind: string; provenance: string; label: string; detail: string; is_synthetic: boolean }
export interface InvestigationDetail extends InvestigationSummary {
  events: SiemEvent[]; indicators: IndicatorLink[]; results: EnrichmentResult[]; relations: Relation[];
  correlation: Correlation; scoring: Scoring; analysis: Analysis | null;
  analyses: { id: number; provider: string; status: string; created_at: string }[];
  notes: Note[]; reports: Report[]; timeline: TimelineItem[]; enrichment_runs: number; superseded_results: number;
}
export interface Connector {
  id: number; kind: string; provider: string; name: string; enabled: boolean; settings: Record<string, unknown>;
  secrets: Record<string, string>; poll_interval_seconds: number; last_status: string; last_error: string | null;
  last_success_at: string | null; last_run_at: string | null; state: string; display_name?: string; category?: string;
  description?: string; requires_api_key?: boolean; secret_fields?: string[]; settings_schema?: Record<string, string>;
  terms_url?: string | null; reliability?: number; upstream_group?: string; maturity?: string; supported_types?: string[];
}
export interface MapPoint {
  indicator: string; source: string; latitude: number; longitude: number; accuracy_radius_km: number | null; country: string | null;
  city: string | null; region: string | null; precision_note: string | null; queried_at: string; is_synthetic: boolean;
  investigation_id: string; investigation_reference: string | null; risk_level: string | null; event_times: string[]; targets: string[];
}
export interface Task { id: number; type: string; payload: Record<string, unknown>; status: string; attempts: number; max_attempts: number; next_run_at: string; last_error: string | null; result: unknown; created_at: string; finished_at: string | null }
