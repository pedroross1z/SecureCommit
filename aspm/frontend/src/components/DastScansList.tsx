import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { listDastScans } from "../lib/api";
import { STALE_LIST, qk } from "../lib/queries";
import DastStatusPill from "./DastStatusPill";
import Spinner from "./Spinner";
import { formatDate } from "../lib/format";

export default function DastScansList({ assetId }: { assetId: string }) {
  const query = useQuery({
    queryKey: qk.dastScans(assetId),
    queryFn: () => listDastScans(assetId),
    staleTime: STALE_LIST,
    refetchInterval: (q) => {
      const scans = q.state.data ?? [];
      const hasActive = scans.some(
        (s) => s.status === "pending" || s.status === "queued" || s.status === "running",
      );
      return hasActive ? 3_000 : false;
    },
  });

  if (query.isPending) {
    return (
      <div className="flex items-center gap-2 text-slate-500">
        <Spinner /> Carregando execucoes DAST...
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="text-sm text-red-700">
        Falha ao carregar scans DAST: {String(query.error)}
      </div>
    );
  }

  const scans = query.data ?? [];
  if (scans.length === 0) {
    return (
      <div className="text-sm text-slate-500 italic py-6">
        Nenhum scan DAST ainda. Clique em &quot;Novo scan DAST&quot; para
        comecar.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto border border-slate-200 rounded-lg bg-white">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 text-left text-slate-500 text-xs uppercase">
          <tr>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Alvo</th>
            <th className="px-3 py-2">Perfil</th>
            <th className="px-3 py-2">Iniciado</th>
            <th className="px-3 py-2">Duracao</th>
            <th className="px-3 py-2">Findings</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200">
          {scans.map((s) => (
            <tr key={s.id} className="hover:bg-slate-50">
              <td className="px-3 py-2">
                <DastStatusPill status={s.status} />
              </td>
              <td className="px-3 py-2">
                <Link
                  to={`/dast/scans/${s.id}`}
                  className="font-mono text-xs text-cyan-700 hover:underline break-all"
                >
                  {s.target_url}
                </Link>
              </td>
              <td className="px-3 py-2 text-slate-600">{s.profile}</td>
              <td className="px-3 py-2 text-slate-500">
                {formatDate(s.started_at ?? s.created_at)}
              </td>
              <td className="px-3 py-2 text-slate-600">
                {s.duration_s != null ? `${s.duration_s}s` : "-"}
              </td>
              <td className="px-3 py-2 text-slate-700 font-semibold">
                {s.findings_count}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
