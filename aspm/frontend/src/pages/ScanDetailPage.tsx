import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { getScanAIUsage } from "../lib/api";
import { qk } from "../lib/queries";
import { useScanStatus } from "../hooks/useScanStatus";
import ScanStatusPill from "../components/ScanStatusPill";
import Spinner from "../components/Spinner";
import { formatDate } from "../lib/format";

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const scanQuery = useScanStatus(scanId);

  const isTerminal =
    scanQuery.data?.status === "done" || scanQuery.data?.status === "failed";

  const usageQuery = useQuery({
    queryKey: qk.scanAIUsage(scanId ?? ""),
    queryFn: () => getScanAIUsage(scanId!),
    enabled: Boolean(scanId) && isTerminal,
  });

  if (!scanId) return null;
  if (scanQuery.isPending) {
    return (
      <div className="flex items-center gap-2 text-slate-500">
        <Spinner /> Carregando scan...
      </div>
    );
  }
  if (scanQuery.isError || !scanQuery.data) {
    return (
      <div className="text-red-700 text-sm">
        Falha ao carregar scan: {String(scanQuery.error)}
      </div>
    );
  }
  const scan = scanQuery.data;

  return (
    <div className="space-y-6">
      <div>
        <Link
          to={`/assets/${scan.asset_id}`}
          className="text-sm text-cyan-700 hover:underline"
        >
          ← Voltar para asset
        </Link>
      </div>

      <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <div className="flex items-center gap-3">
          <ScanStatusPill status={scan.status} />
          {scan.commit_sha && (
            <span className="text-xs text-slate-500 font-mono">
              {scan.commit_sha.slice(0, 12)}
            </span>
          )}
        </div>
        <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-2 text-sm">
          <div>
            <dt className="text-slate-500 text-xs uppercase">Iniciado</dt>
            <dd>{formatDate(scan.started_at)}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Finalizado</dt>
            <dd>{formatDate(scan.finished_at)}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Scan ID</dt>
            <dd className="font-mono text-xs">{scan.id}</dd>
          </div>
        </dl>
        {scan.status === "failed" && scan.error && (
          <div className="border-t border-slate-200 pt-3 text-sm text-red-700">
            <div className="text-xs uppercase text-red-500 mb-1">Erro</div>
            <pre className="whitespace-pre-wrap">{scan.error}</pre>
          </div>
        )}
      </section>

      {scan.tool_stats && (
        <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-2">
          <h2 className="text-base font-semibold">Estatisticas por ferramenta</h2>
          <pre className="bg-slate-900 text-slate-100 rounded p-3 text-xs overflow-x-auto">
            {JSON.stringify(scan.tool_stats, null, 2)}
          </pre>
        </section>
      )}

      {isTerminal && (
        <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-2">
          <h2 className="text-base font-semibold">Uso de IA</h2>
          {usageQuery.isPending && (
            <div className="flex items-center gap-2 text-slate-500">
              <Spinner /> Carregando...
            </div>
          )}
          {usageQuery.data && (
            <dl className="grid grid-cols-3 gap-4 text-sm">
              <div>
                <dt className="text-slate-500 text-xs uppercase">Chamadas</dt>
                <dd className="text-lg font-semibold">
                  {usageQuery.data.ai_calls}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500 text-xs uppercase">Tokens in</dt>
                <dd className="text-lg font-semibold">
                  {usageQuery.data.input_tokens.toLocaleString("pt-BR")}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500 text-xs uppercase">Tokens out</dt>
                <dd className="text-lg font-semibold">
                  {usageQuery.data.output_tokens.toLocaleString("pt-BR")}
                </dd>
              </div>
            </dl>
          )}
        </section>
      )}

      {isTerminal && (
        <div>
          <Link
            to={`/assets/${scan.asset_id}?tab=findings`}
            className="text-sm text-cyan-700 hover:underline"
          >
            Ver findings do asset →
          </Link>
        </div>
      )}
    </div>
  );
}
