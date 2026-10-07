import type {
  AssetOut,
  ClusterOut,
  CreateAssetRequest,
  CreateDastMonitorRequest,
  CreateDastScanRequest,
  DastMonitorOut,
  DastProfileOut,
  DastScanOut,
  FindingFilters,
  FindingOut,
  Policy,
  PolicyEvaluation,
  RemediationOut,
  ScanAIUsage,
  ScanOut,
  UpdateFindingStatusRequest,
  UpdateRemediationRequest,
} from "./types";

const BASE =
  (import.meta.env.VITE_API_URL as string | undefined) ?? "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let body: unknown = {};
    try {
      body = await res.json();
    } catch {
      // corpo nao-JSON
    }
    const detail =
      body && typeof body === "object" && "detail" in body
        ? (body as { detail: unknown }).detail
        : res.statusText;
    throw new ApiError(res.status, String(detail ?? res.statusText), body);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ---------- Assets ----------

export const listAssets = () => apiFetch<AssetOut[]>("/assets");
export const getAsset = (id: string) => apiFetch<AssetOut>(`/assets/${id}`);
export const createAsset = (body: CreateAssetRequest) =>
  apiFetch<AssetOut>("/assets", { method: "POST", body: JSON.stringify(body) });
export const startScan = (assetId: string) =>
  apiFetch<ScanOut>(`/assets/${assetId}/scan`, { method: "POST" });

// ---------- Scans ----------

export const getScan = (id: string) => apiFetch<ScanOut>(`/scans/${id}`);
export const getScanAIUsage = (id: string) =>
  apiFetch<ScanAIUsage>(`/scans/${id}/ai-usage`);

// ---------- Findings ----------

export const listFindings = (filters: FindingFilters = {}) => {
  const qs = new URLSearchParams();
  if (filters.asset_id) qs.set("asset_id", filters.asset_id);
  if (filters.scan_id) qs.set("scan_id", filters.scan_id);
  if (filters.category) qs.set("category", filters.category);
  if (filters.status) qs.set("status", filters.status);
  if (filters.min_score != null) qs.set("min_score", String(filters.min_score));
  if (filters.limit != null) qs.set("limit", String(filters.limit));
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch<FindingOut[]>(`/findings${suffix}`);
};

export const getFinding = (id: string) => apiFetch<FindingOut>(`/findings/${id}`);

export const updateFindingStatus = (id: string, body: UpdateFindingStatusRequest) =>
  apiFetch<FindingOut>(`/findings/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });

export const analyzeFinding = (id: string) =>
  apiFetch<FindingOut>(`/findings/${id}/analyze`, { method: "POST" });

export const remediateFinding = (id: string) =>
  apiFetch<RemediationOut>(`/findings/${id}/remediate`, { method: "POST" });

export const listRemediations = (findingId: string) =>
  apiFetch<RemediationOut[]>(`/findings/${findingId}/remediations`);

// ---------- Remediations ----------

export const getRemediation = (id: string) =>
  apiFetch<RemediationOut>(`/remediations/${id}`);

export const updateRemediation = (id: string, body: UpdateRemediationRequest) =>
  apiFetch<RemediationOut>(`/remediations/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });

// ---------- Clusters ----------

export const listClusters = (assetId?: string) => {
  const qs = new URLSearchParams();
  if (assetId) qs.set("asset_id", assetId);
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch<ClusterOut[]>(`/clusters${suffix}`);
};

export const getCluster = (id: string) => apiFetch<ClusterOut>(`/clusters/${id}`);

export const getClusterFindings = (id: string) =>
  apiFetch<FindingOut[]>(`/clusters/${id}/findings`);

// ---------- Policies (Fase 6) ----------

export const listPolicies = () => apiFetch<Policy[]>("/policies");

export const getPolicy = (name: string) => apiFetch<Policy>(`/policies/${name}`);

export const evaluatePolicy = (
  name: string,
  assetId: string,
  scanId?: string,
) => {
  const qs = new URLSearchParams({ asset_id: assetId });
  if (scanId) qs.set("scan_id", scanId);
  return apiFetch<PolicyEvaluation>(
    `/policies/${name}/evaluate?${qs.toString()}`,
    { method: "POST" },
  );
};

// ---------- DAST ----------

export const listDastProfiles = () =>
  apiFetch<DastProfileOut[]>("/api/dast/profiles");

export const createDastScan = (body: CreateDastScanRequest) =>
  apiFetch<DastScanOut>("/api/dast/scans", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const listDastScans = (assetId?: string, limit = 50) => {
  const qs = new URLSearchParams();
  if (assetId) qs.set("asset_id", assetId);
  qs.set("limit", String(limit));
  return apiFetch<DastScanOut[]>(`/api/dast/scans?${qs.toString()}`);
};

export const getDastScan = (id: string) =>
  apiFetch<DastScanOut>(`/api/dast/scans/${id}`);

export const cancelDastScan = (id: string) =>
  apiFetch<DastScanOut>(`/api/dast/scans/${id}/cancel`, { method: "POST" });

export const getDastScanFindings = (id: string) =>
  apiFetch<FindingOut[]>(`/api/dast/scans/${id}/findings`);

// ---------- DAST monitors (contínuos) ----------

export const createDastMonitor = (body: CreateDastMonitorRequest) =>
  apiFetch<DastMonitorOut>("/api/dast/monitors", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const listDastMonitors = (assetId?: string) => {
  const qs = new URLSearchParams();
  if (assetId) qs.set("asset_id", assetId);
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch<DastMonitorOut[]>(`/api/dast/monitors${suffix}`);
};

export const getDastMonitor = (id: string) =>
  apiFetch<DastMonitorOut>(`/api/dast/monitors/${id}`);

export const stopDastMonitor = (id: string) =>
  apiFetch<DastMonitorOut>(`/api/dast/monitors/${id}/stop`, { method: "POST" });

export const respiderDastMonitor = (id: string) =>
  apiFetch<DastMonitorOut>(`/api/dast/monitors/${id}/respider`, { method: "POST" });

export const getDastMonitorFindings = (id: string) =>
  apiFetch<FindingOut[]>(`/api/dast/monitors/${id}/findings`);
