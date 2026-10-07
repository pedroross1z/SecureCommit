-- Fase 2: Correlação — clusters de findings por raiz comum
CREATE TABLE IF NOT EXISTS clusters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
  root_cause TEXT NOT NULL,
  confidence NUMERIC(3,2),
  source TEXT DEFAULT 'ai',
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_clusters_asset_id ON clusters(asset_id);
