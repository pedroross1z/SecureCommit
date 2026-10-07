-- ASPM MVP: schema inicial
-- Todas as tabelas do spec (assets, scans, findings, ai_analysis, remediations, ai_cache)

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Pilar 1: Descoberta
CREATE TABLE IF NOT EXISTS assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_url TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  default_branch TEXT,
  languages JSONB,
  frameworks JSONB,
  criticality SMALLINT,
  criticality_source TEXT,
  internet_facing BOOLEAN,
  handles_pii BOOLEAN,
  has_auth BOOLEAN,
  ai_rationale TEXT,
  owner TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
  commit_sha TEXT,
  status TEXT NOT NULL,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  tool_stats JSONB,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_asset_id ON scans(asset_id);

-- Pilar 2: Coleta normalizada
CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  source_tool TEXT NOT NULL,
  category TEXT NOT NULL,
  rule_id TEXT,
  title TEXT NOT NULL,
  description TEXT,
  severity_raw TEXT,
  cwe TEXT[],
  cve TEXT,
  file_path TEXT,
  line_start INT,
  line_end INT,
  snippet TEXT,
  package_name TEXT,
  package_version TEXT,
  fixed_version TEXT,
  fingerprint TEXT NOT NULL,
  cluster_id UUID,
  status TEXT DEFAULT 'open',
  first_seen TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_asset_fingerprint ON findings (asset_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cluster_id ON findings(cluster_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Pilar 3 e 4: enriquecimento por IA
CREATE TABLE IF NOT EXISTS ai_analysis (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
  reachability TEXT,
  exploitability SMALLINT,
  business_impact SMALLINT,
  risk_score SMALLINT,
  is_likely_false_positive BOOLEAN,
  confidence NUMERIC(3,2),
  rationale TEXT NOT NULL,
  model TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  input_tokens INT,
  output_tokens INT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_analysis_finding_id ON ai_analysis(finding_id);

-- Pilar 5: Remediação
CREATE TABLE IF NOT EXISTS remediations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
  patch_diff TEXT,
  explanation TEXT,
  breaking_risk TEXT,
  test_suggestion TEXT,
  applied BOOLEAN DEFAULT false,
  model TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remediations_finding_id ON remediations(finding_id);

-- Cache de IA por fingerprint (economia de custo)
CREATE TABLE IF NOT EXISTS ai_cache (
  cache_key TEXT PRIMARY KEY,
  response JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
