import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { cancelDastScan } from "../lib/api";
import { qk } from "../lib/queries";
import { useDastScanStatus } from "../hooks/useDastScanStatus";
import DastStatusPill from "../components/DastStatusPill";
import DastFindingsTable from "../components/DastFindingsTable";
import Spinner from "../components/Spinner";
import { formatDate } from "../lib/format";
import type { DastScanOut } from "../lib/types";

function Metrics({ scan }: { scan: DastScanOut }) {
  const m = (scan.metrics ?? {}) as {
    alerts?: number;
    unique_urls?: number;
    by_severity?: Record<string, number>;
    new?: number;
    updated?: number;
    executor_rc?: number;
  };
  const bySev = m.by_severity ?? {};
  return (
    <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-3 text-sm">
      <div>
        <dt className="text-slate-500 text-xs uppercase">Alertas</dt>
        <dd className="text-lg font-semibold">{m.alerts ?? "-"}</dd>
      </div>
      <div>
        <dt className="text-slate-500 text-xs uppercase">URLs unicas</dt>
        <dd className="text-lg font-semibold">{m.unique_urls ?? "-"}</dd>
      </div>
      <div>
        <dt className="text-slate-500 text-xs uppercase">Novos findings</dt>
        <dd className="text-lg font-semibold">{m.new ?? 0}</dd>
      </div>
      <div>
        <dt className="text-slate-500 text-xs uppercase">Atualizados</dt>
        <dd className="text-lg font-semibold">{m.updated ?? 0}</dd>
      </div>
      <div className="col-span-2 md:col-span-4">
        <dt className="text-slate-500 text-xs uppercase mb-1">
          Distribuicao por severidade
        </dt>
        <dd className="flex flex-wrap gap-3 text-xs">
          {["high", "medium", "low", "info"].map((s) => (
            <span
              key={s}
              className={`rounded px-2 py-0.5 ${
                s === "high"
                  ? "bg-red-100 text-red-800"
                  : s === "medium"
                    ? "bg-amber-100 text-amber-900"
                    : s === "low"
                      ? "bg-cyan-100 text-cyan-800"
                      : "bg-slate-100 text-slate-700"
              }`}
            >
              {s}: {bySev[s] ?? 0}
            </span>
          ))}
        </dd>
      </div>
    </dl>
  );
}

export default function DastScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const query = useDastScanStatus(scanId);
  const qc = useQueryClient();

  const cancelMutation = useMutation({
    mutationFn: () => cancelDastScan(scanId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.dastScan(scanId!) });
    },
  });

  if (!scanId) return null;
  if (query.isPending) {
    return (
      <div className="flex items-center gap-2 text-slate-500">
        <Spinner /> Carregando scan DAST...
      </div>
    );
  }
  if (query.isError || !query.data) {
    return (
      <div className="text-red-700 text-sm">
        Falha ao carregar scan DAST: {String(query.error)}
      </div>
    );
  }

  const scan = query.data;
  const active =
    scan.status === "pending" ||
    scan.status === "queued" ||
    scan.status === "running";
  const isTerminal =
    scan.status === "completed" ||
    scan.status === "failed" ||
    scan.status === "cancelled";

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <Link
          to={`/assets/${scan.asset_id}?tab=dast`}
          className="text-sm text-cyan-700 hover:underline"
        >
          ← Voltar para asset
        </Link>
        {active && (
          <button
            onClick={() => cancelMutation.mutate()}
            disabled={cancelMutation.isPending}
            className="inline-flex items-center gap-2 rounded border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            {cancelMutation.isPending && <Spinner className="h-3 w-3" />}
            Cancelar scan
          </button>
        )}
      </div>

      <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <DastStatusPill status={scan.status} />
          <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
            {scan.profile}
          </span>
          {scan.authorized && scan.profile !== "passive" && scan.profile !== "baseline" && (
            <span className="rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">
              autorizado
            </span>
          )}
          {scan.zap_version && (
            <span className="text-xs text-slate-500 font-mono">
              ZAP {scan.zap_version}
            </span>
          )}
        </div>

        <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-2 text-sm">
          <div className="md:col-span-3">
            <dt className="text-slate-500 text-xs uppercase">URL alvo</dt>
            <dd className="font-mono text-xs break-all">{scan.target_url}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Iniciado</dt>
            <dd>{formatDate(scan.started_at)}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Finalizado</dt>
            <dd>{formatDate(scan.finished_at)}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Duracao</dt>
            <dd>{scan.duration_s != null ? `${scan.duration_s}s` : "-"}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Findings</dt>
            <dd className="font-semibold">{scan.findings_count}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Solicitado por</dt>
            <dd>{scan.requested_by ?? "-"}</dd>
          </div>
          <div className="md:col-span-3">
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

        {active && (
          <div className="border-t border-slate-200 pt-3 text-xs text-slate-500">
            Scan em andamento — atualizando a cada 3s.
          </div>
        )}
      </section>

      {scan.metrics && (
        <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <h2 className="text-base font-semibold">Metricas</h2>
          <Metrics scan={scan} />
        </section>
      )}

      {isTerminal && (
        <section className="space-y-3">
          <h2 className="text-base font-semibold">Findings</h2>
          <DastFindingsTable scanId={scanId} />
        </section>
      )}
    </div>
  );
}
