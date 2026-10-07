import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { getAsset, listClusters, startScan } from "../lib/api";
import { STALE_DETAIL, qk } from "../lib/queries";
import AssetContextCard from "../components/AssetContextCard";
import FindingsTable from "../components/FindingsTable";
import RiskScoreChip from "../components/RiskScoreChip";
import Spinner from "../components/Spinner";
import DastScansList from "../components/DastScansList";
import DastMonitorCard from "../components/DastMonitorCard";
import StartDastScanModal from "../components/StartDastScanModal";

type Tab = "findings" | "clusters" | "dast";

export default function AssetDetailPage() {
  const { assetId } = useParams<{ assetId: string }>();
  const [params, setParams] = useSearchParams();
  const activeTab = (params.get("tab") as Tab | null) ?? "findings";
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [dastModalOpen, setDastModalOpen] = useState(false);

  const assetQuery = useQuery({
    queryKey: qk.asset(assetId ?? ""),
    queryFn: () => getAsset(assetId!),
    enabled: Boolean(assetId),
    staleTime: STALE_DETAIL,
  });

  const clustersQuery = useQuery({
    queryKey: qk.clusters(assetId),
    queryFn: () => listClusters(assetId),
    enabled: Boolean(assetId) && activeTab === "clusters",
    staleTime: STALE_DETAIL,
  });

  const scanMutation = useMutation({
    mutationFn: () => startScan(assetId!),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: qk.asset(assetId!) });
      navigate(`/scans/${scan.id}`);
    },
  });

  if (!assetId) return null;
  if (assetQuery.isPending) {
    return (
      <div className="flex items-center gap-2 text-slate-500">
        <Spinner /> Carregando asset...
      </div>
    );
  }
  if (assetQuery.isError || !assetQuery.data) {
    return (
      <div className="text-red-700 text-sm">
        Falha ao carregar asset: {String(assetQuery.error)}
      </div>
    );
  }

  const asset = assetQuery.data;
  const tabButton = (id: Tab, label: string) => (
    <button
      onClick={() => setParams({ tab: id })}
      className={`px-3 py-1.5 text-sm font-medium border-b-2 -mb-px ${
        activeTab === id
          ? "border-cyan-700 text-cyan-800"
          : "border-transparent text-slate-500 hover:text-slate-700"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <Link to="/" className="text-sm text-cyan-700 hover:underline">
          ← Voltar
        </Link>
        <button
          onClick={() => scanMutation.mutate()}
          disabled={scanMutation.isPending}
          className="inline-flex items-center gap-2 rounded-md bg-cyan-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-800 disabled:opacity-50"
        >
          {scanMutation.isPending && <Spinner className="h-3 w-3" />}
          Rodar novo scan
        </button>
      </div>

      <AssetContextCard asset={asset} />

      <div className="border-b border-slate-200 flex gap-2">
        {tabButton("findings", "Findings")}
        {tabButton("clusters", "Clusters")}
        {tabButton("dast", "DAST")}
      </div>

      {activeTab === "findings" && <FindingsTable assetId={asset.id} />}

      {activeTab === "dast" && (
        <div className="space-y-6">
          <DastMonitorCard assetId={asset.id} />

          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-800">
                  Scans one-shot (snapshot)
                </h3>
                <p className="text-xs text-slate-600">
                  Execucoes pontuais do OWASP ZAP (baseline/active) — util para
                  CI/CD ou validacao especifica.
                </p>
              </div>
              <button
                onClick={() => setDastModalOpen(true)}
                className="inline-flex items-center gap-2 rounded-md bg-cyan-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-800"
              >
                + Novo scan DAST
              </button>
            </div>
            <DastScansList assetId={asset.id} />
          </div>

          <StartDastScanModal
            open={dastModalOpen}
            onClose={() => setDastModalOpen(false)}
            assetId={asset.id}
            defaultUrl={asset.repo_url?.startsWith("http") ? asset.repo_url : null}
          />
        </div>
      )}

      {activeTab === "clusters" && (
        <div>
          {clustersQuery.isPending && (
            <div className="flex items-center gap-2 text-slate-500">
              <Spinner /> Carregando clusters...
            </div>
          )}
          {clustersQuery.data && clustersQuery.data.length === 0 && (
            <div className="text-sm text-slate-500 italic py-6">
              Nenhum cluster ainda. Rode um scan para gerar.
            </div>
          )}
          {clustersQuery.data && clustersQuery.data.length > 0 && (
            <div className="overflow-x-auto border border-slate-200 rounded-lg bg-white">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 text-left text-slate-500 text-xs uppercase">
                  <tr>
                    <th className="px-3 py-2">Causa raiz</th>
                    <th className="px-3 py-2">Origem</th>
                    <th className="px-3 py-2">Findings</th>
                    <th className="px-3 py-2">Max risk</th>
                    <th className="px-3 py-2">Categorias</th>
                    <th className="px-3 py-2">Tools</th>
                    <th className="px-3 py-2">Confianca</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {clustersQuery.data.map((c) => {
                    const sourceClass =
                      c.source === "correlator-cwe"
                        ? "bg-cyan-100 text-cyan-800"
                        : c.source === "manual"
                          ? "bg-slate-200 text-slate-700"
                          : "bg-violet-100 text-violet-800";
                    const sourceLabel =
                      c.source === "correlator-cwe"
                        ? "DAST↔SAST"
                        : c.source === "manual"
                          ? "manual"
                          : "ia";
                    return (
                      <tr key={c.id} className="hover:bg-slate-50">
                        <td className="px-3 py-2 text-slate-800">{c.root_cause}</td>
                        <td className="px-3 py-2">
                          <span
                            className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${sourceClass}`}
                          >
                            {sourceLabel}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-slate-600">{c.findings_count}</td>
                        <td className="px-3 py-2">
                          <RiskScoreChip value={c.max_risk_score} />
                        </td>
                        <td className="px-3 py-2 text-slate-600">
                          {c.categories.join(", ") || "-"}
                        </td>
                        <td className="px-3 py-2 text-slate-600">
                          {c.tools.join(", ") || "-"}
                        </td>
                        <td className="px-3 py-2 text-slate-600">
                          {c.confidence != null ? c.confidence.toFixed(2) : "-"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
