import type { FindingFilters } from "./types";

export const qk = {
  assets: ["assets"] as const,
  asset: (id: string) => ["assets", id] as const,
  scan: (id: string) => ["scans", id] as const,
  scanAIUsage: (id: string) => ["scans", id, "ai-usage"] as const,
  findings: (filters: FindingFilters) => ["findings", filters] as const,
  finding: (id: string) => ["findings", id] as const,
  remediations: (findingId: string) =>
    ["findings", findingId, "remediations"] as const,
  clusters: (assetId?: string) => ["clusters", assetId ?? null] as const,
  cluster: (id: string) => ["clusters", id] as const,
  policies: ["policies"] as const,
  policy: (name: string) => ["policies", name] as const,
  policyEvaluation: (name: string, assetId: string, scanId?: string | null) =>
    ["policies", name, "evaluate", assetId, scanId ?? null] as const,
  // DAST
  dastProfiles: ["dast", "profiles"] as const,
  dastScans: (assetId?: string) => ["dast", "scans", assetId ?? null] as const,
  dastScan: (id: string) => ["dast", "scan", id] as const,
  dastScanFindings: (id: string) => ["dast", "scan", id, "findings"] as const,
  dastMonitors: (assetId?: string) =>
    ["dast", "monitors", assetId ?? null] as const,
  dastMonitor: (id: string) => ["dast", "monitor", id] as const,
  dastMonitorFindings: (id: string) => ["dast", "monitor", id, "findings"] as const,
};

export const STALE_LIST = 15_000;
export const STALE_DETAIL = 5_000;
export const SCAN_POLL_MS = 3_000;
