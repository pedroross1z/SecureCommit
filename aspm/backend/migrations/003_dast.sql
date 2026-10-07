-- Fase DAST: execucoes OWASP ZAP + colunas opcionais em findings
-- Idempotente; nao destrutivo.

CREATE TABLE IF NOT EXISTS dast_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  profile TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  requested_by TEXT,
  authorized BOOLEAN DEFAULT false,
  options JSONB,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  duration_s INT,
  zap_version TEXT,
  metrics JSONB,
  findings_count INT DEFAULT 0,
  report_path TEXT,
  error TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dast_scans_asset_id ON dast_scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_dast_scans_status ON dast_scans(status);

-- Campos opcionais para findings DAST. Nullable para preservar findings existentes.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS url TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS http_method TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS parameter TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS solution TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dast_scan_id UUID;
CREATE INDEX IF NOT EXISTS idx_findings_dast_scan_id ON findings(dast_scan_id);
