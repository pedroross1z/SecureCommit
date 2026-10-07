import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { listAssets, startScan } from "../lib/api";
import { STALE_LIST, qk } from "../lib/queries";
import { criticalityLabel, formatDate } from "../lib/format";
import RiskScoreChip from "../components/RiskScoreChip";
import AddAssetModal from "../components/AddAssetModal";
import Spinner from "../components/Spinner";

export default function AssetsListPage() {
  const [modalOpen, setModalOpen] = useState(false);
  const qc = useQueryClient();
  const navigate = useNavigate();

  const assetsQuery = useQuery({
    queryKey: qk.assets,
    queryFn: listAssets,
    staleTime: STALE_LIST,
  });

  const scanMutation = useMutation({
    mutationFn: (assetId: string) => startScan(assetId),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: qk.assets });
      navigate(`/scans/${scan.id}`);
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Assets</h1>
        <button
          onClick={() => setModalOpen(true)}
          className="inline-flex items-center gap-2 rounded-md bg-cyan-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-800"
        >
          + Adicionar asset
        </button>
      </div>

      {assetsQuery.isPending && (
        <div className="flex items-center gap-2 text-slate-500">
          <Spinner /> Carregando...
        </div>
      )}

      {assetsQuery.isError && (
        <div className="text-red-700 text-sm">
          Falha ao carregar assets: {String(assetsQuery.error)}
        </div>
      )}

      {assetsQuery.data && assetsQuery.data.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-300 bg-white p-8 text-center text-slate-500">
          Nenhum asset cadastrado. Clique em "Adicionar asset" para comecar.
        </div>
      )}

      {assetsQuery.data && assetsQuery.data.length > 0 && (
        <div className="overflow-x-auto border border-slate-200 rounded-lg bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-3 py-2">Nome</th>
                <th className="px-3 py-2">Criticidade</th>
                <th className="px-3 py-2">Findings abertos</th>
                <th className="px-3 py-2">Max risk</th>
                <th className="px-3 py-2">Adicionado</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {assetsQuery.data.map((a) => (
                <tr key={a.id} className="hover:bg-slate-50">
                  <td className="px-3 py-2">
                    <Link
                      to={`/assets/${a.id}`}
                      className="font-medium text-cyan-700 hover:underline"
                    >
                      {a.name}
                    </Link>
                    <div className="text-xs text-slate-500 truncate max-w-xs">
                      {a.repo_url}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-slate-600">
                    {criticalityLabel(a.criticality)}
                  </td>
                  <td className="px-3 py-2 text-slate-600">{a.open_findings}</td>
                  <td className="px-3 py-2">
                    <RiskScoreChip value={a.max_risk_score} />
                  </td>
                  <td className="px-3 py-2 text-slate-500">
                    {formatDate(a.created_at)}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => scanMutation.mutate(a.id)}
                      disabled={
                        scanMutation.isPending && scanMutation.variables === a.id
                      }
                      className="inline-flex items-center gap-2 rounded border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    >
                      {scanMutation.isPending &&
                        scanMutation.variables === a.id && (
                          <Spinner className="h-3 w-3" />
                        )}
                      Rodar scan
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <AddAssetModal open={modalOpen} onClose={() => setModalOpen(false)} />
    </div>
  );
}
