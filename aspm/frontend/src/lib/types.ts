// Espelha backend/app/schemas/api.py — quando o backend mudar, atualize aqui.
// Datetimes vêm como ISO strings, UUIDs como strings.

export type FindingStatus =
  | "open"
  | "triaged"
  | "false_positive"
  | "fixed"
  | "accepted_risk";

export type ScanStatus = "queued" | "running" | "done" | "failed";

export type SeverityRaw = string | null;

export type BreakingRisk = "low" | "medium" | "high";

export interface AssetOut {
  id: string;
  repo_url: string;
  name: string;
  default_branch: string | null;
  languages: Record<string, unknown> | null;
  frameworks: Record<string, unknown> | null;
  criticality: number | null;
  criticality_source: string | null;
  internet_facing: boolean | null;
  handles_pii: boolean | null;
  has_auth: boolean | null;
  ai_rationale: string | null;
  owner: string | null;
  created_at: string;
  open_findings: number;
  max_risk_score: number | null;
}

export interface CreateAssetRequest {
  repo_url: string;
}

export interface ScanOut {
  id: string;
  asset_id: string;
  commit_sha: string | null;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  tool_stats: Record<string, unknown> | null;
  error: string | null;
}

export interface ScanAIUsage {
  scan_id: string;
  ai_calls: number;
  input_tokens: number;
  output_tokens: number;
}

export interface FindingOut {
  id: string;
  asset_id: string;
  scan_id: string;
  source_tool: string;
  category: string;
  rule_id: string | null;
  title: string;
  description: string | null;
  severity_raw: SeverityRaw;
  cwe: string[] | null;
  cve: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  snippet: string | null;
  package_name: string | null;
  package_version: string | null;
  fixed_version: string | null;
  // Campos DAST (populados so quando category='dast')
  url?: string | null;
  http_method?: string | null;
  parameter?: string | null;
  evidence?: string | null;
  solution?: string | null;
  dast_scan_id?: string | null;
  dast_monitor_id?: string | null;
  fingerprint: string;
  cluster_id: string | null;
  status: FindingStatus;
  first_seen: string;
  last_seen: string;
  risk_score: number | null;
  ai_rationale: string | null;
}

export interface UpdateFindingStatusRequest {
  status: FindingStatus;
}

export interface RemediationOut {
  id: string;
  finding_id: string;
  patch_diff: string | null;
  explanation: string | null;
  breaking_risk: BreakingRisk | null;
  test_suggestion: string | null;
  applied: boolean;
  model: string | null;
  created_at: string;
}

export interface UpdateRemediationRequest {
  applied: boolean;
}

export interface ClusterOut {
  id: string;
  asset_id: string;
  root_cause: string;
  confidence: number | null;
  source: string;
  created_at: string;
  findings_count: number;
  max_risk_score: number | null;
  categories: string[];
  tools: string[];
}

export interface FindingFilters {
  asset_id?: string;
  scan_id?: string;
  category?: string;
  status?: FindingStatus;
  min_score?: number;
  limit?: number;
}

// ---------- Policies (Fase 6) ----------

export type PolicyAction = "fail" | "warn";

export interface RuleCondition {
  category_in?: string[] | null;
  severity_in?: string[] | null;
  min_risk_score?: number | null;
  cwe_any?: string[] | null;
  cve_present?: boolean | null;
  package_name_in?: string[] | null;
  rule_id_in?: string[] | null;
  tool_in?: string[] | null;
  exclude_status?: string[];
}

export interface PolicyRule {
  id: string;
  description?: string | null;
  action: PolicyAction;
  when: RuleCondition;
}

export interface Policy {
  name: string;
  description?: string | null;
  rules: PolicyRule[];
}

export interface PolicyViolation {
  rule_id: string;
  action: PolicyAction;
  finding_id: string;
  finding_title: string;
  file_path: string | null;
  severity: string | null;
  risk_score: number | null;
  category: string;
  tool: string;
}

export interface PolicyEvaluation {
  policy_name: string;
  asset_id: string;
  scan_id: string | null;
  passed: boolean;
  findings_considered: number;
  fail_count: number;
  warn_count: number;
  violations: PolicyViolation[];
  rule_hits: Record<string, number>;
}

// ---------- DAST ----------

export type DastProfileName = "passive" | "baseline" | "active" | "full";

export type DastScanStatus =
  | "pending"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface DastProfileOut {
  name: DastProfileName;
  description: string;
  requires_authorization: boolean;
  default_timeout_s: number;
  max_timeout_s: number;
}

export interface DastScanOut {
  id: string;
  asset_id: string;
  target_url: string;
  profile: DastProfileName;
  status: DastScanStatus;
  requested_by: string | null;
  authorized: boolean;
  options: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
  duration_s: number | null;
  zap_version: string | null;
  metrics: Record<string, unknown> | null;
  findings_count: number;
  error: string | null;
  created_at: string;
}

export interface CreateDastScanRequest {
  asset_id: string;
  target_url: string;
  profile: DastProfileName;
  authorized?: boolean;
  requested_by?: string | null;
  options?: Record<string, unknown> | null;
}

export type DastMonitorStatus = "starting" | "running" | "stopped" | "failed";

export interface DastMonitorOut {
  id: string;
  asset_id: string;
  target_url: string;
  status: DastMonitorStatus;
  zap_port: number | null;
  poll_interval_s: number;
  started_at: string | null;
  stopped_at: string | null;
  last_poll_at: string | null;
  next_poll_at: string | null;
  alerts_total: number;
  polls_total: number;
  last_error: string | null;
  options: Record<string, unknown> | null;
  created_at: string;
}

export interface CreateDastMonitorRequest {
  asset_id: string;
  target_url: string;
  poll_interval_s?: number;
  options?: Record<string, unknown> | null;
}
