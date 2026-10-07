-- Fase DAST contínuo: monitores com ZAP daemon + polling
-- Idempotente, não destrutivo.

CREATE TABLE IF NOT EXISTS dast_monitors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'starting',
  zap_container TEXT,
  zap_port INT,
  zap_api_key TEXT,
  poll_interval_s INT DEFAULT 60,
  started_at TIMESTAMPTZ,
  stopped_at TIMESTAMPTZ,
  last_poll_at TIMESTAMPTZ,
  next_poll_at TIMESTAMPTZ,
  alerts_total INT DEFAULT 0,
  polls_total INT DEFAULT 0,
  last_error TEXT,
  options JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dast_monitors_asset_id ON dast_monitors(asset_id);
CREATE INDEX IF NOT EXISTS idx_dast_monitors_status ON dast_monitors(status);

-- Rastreio de origem do finding por monitor (quando criado em polling contínuo)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dast_monitor_id UUID;
CREATE INDEX IF NOT EXISTS idx_findings_dast_monitor_id ON findings(dast_monitor_id);
