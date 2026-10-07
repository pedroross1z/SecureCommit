import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import {
  analyzeFinding,
  ApiError,
  getFinding,
  listRemediations,
  remediateFinding,
  updateFindingStatus,
  updateRemediation,
} from "../lib/api";
import { STALE_DETAIL, qk } from "../lib/queries";
import type {
  BreakingRisk,
  FindingOut,
  FindingStatus,
  RemediationOut,
} from "../lib/types";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge, { STATUS_LABELS } from "../components/StatusBadge";
import RiskScoreChip from "../components/RiskScoreChip";
import DiffViewer from "../components/DiffViewer";
import Spinner from "../components/Spinner";
import { formatDate } from "../lib/format";

const STATUS_OPTIONS: FindingStatus[] = [
  "open",
  "triaged",
  "false_positive",
  "fixed",
  "accepted_risk",
];

const RISK_LABEL: Record<BreakingRisk, string> = {
  low: "Baixo",
  medium: "Medio",
  high: "Alto",
};

const RISK_CLASS: Record<BreakingRisk, string> = {
  low: "bg-emerald-100 text-emerald-800",
  medium: "bg-amber-100 text-amber-800",
  high: "bg-red-100 text-red-800",
};

function humanizeApiError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 409) {
      return "Workdir do asset foi limpo. Rode um novo scan primeiro.";
    }
    if (e.status === 502) {
      return "Servico de IA indisponivel.";
    }
    return `Falha (${e.status}): ${e.message}`;
  }
  return "Falha desconhecida.";
}

export default function FindingDetailPage() {
  const { findingId } = useParams<{ findingId: string }>();
  const qc = useQueryClient();

  const findingQuery = useQuery({
    queryKey: qk.finding(findingId ?? ""),
    queryFn: () => getFinding(findingId!),
    enabled: Boolean(findingId),
    staleTime: STALE_DETAIL,
  });

  const remediationsQuery = useQuery({
    queryKey: qk.remediations(findingId ?? ""),
    queryFn: () => listRemediations(findingId!),
    enabled: Boolean(findingId),
    staleTime: STALE_DETAIL,
  });

  const analyzeMutation = useMutation({
    mutationFn: () => analyzeFinding(findingId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.finding(findingId!) });
    },
  });

  const remediateMutation = useMutation({
    mutationFn: () => remediateFinding(findingId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.remediations(findingId!) });
    },
  });

  const statusMutation = useMutation({
    mutationFn: (newStatus: FindingStatus) =>
      updateFindingStatus(findingId!, { status: newStatus }),
    onMutate: async (newStatus) => {
      await qc.cancelQueries({ queryKey: qk.finding(findingId!) });
      const prev = qc.getQueryData<FindingOut>(qk.finding(findingId!));
      if (prev) {
        qc.setQueryData<FindingOut>(qk.finding(findingId!), {
          ...prev,
          status: newStatus,
        });
      }
      return { prev };
    },
    onError: (_e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(qk.finding(findingId!), ctx.prev);
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: qk.finding(findingId!) });
    },
  });

  const applyMutation = useMutation({
    mutationFn: ({ id, applied }: { id: string; applied: boolean }) =>
      updateRemediation(id, { applied }),
    onMutate: async ({ id, applied }) => {
      await qc.cancelQueries({ queryKey: qk.remediations(findingId!) });
      const prev = qc.getQueryData<RemediationOut[]>(qk.remediations(findingId!));
      if (prev) {
        qc.setQueryData<RemediationOut[]>(
          qk.remediations(findingId!),
          prev.map((r) => (r.id === id ? { ...r, applied } : r)),
        );
      }
      return { prev };
    },
    onError: (_e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(qk.remediations(findingId!), ctx.prev);
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: qk.remediations(findingId!) });
    },
  });

  if (!findingId) return null;
  if (findingQuery.isPending) {
    return (
      <div className="flex items-center gap-2 text-slate-500">
        <Spinner /> Carregando finding...
      </div>
    );
  }
  if (findingQuery.isError || !findingQuery.data) {
    return (
      <div className="text-red-700 text-sm">
        Falha ao carregar: {String(findingQuery.error)}
      </div>
    );
  }
  const f = findingQuery.data;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <Link
          to={`/assets/${f.asset_id}`}
          className="text-sm text-cyan-700 hover:underline"
        >
          ← Voltar para asset
        </Link>
      </div>

      <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={f.severity_raw} />
          <StatusBadge status={f.status} />
          <RiskScoreChip value={f.risk_score} />
        </div>
        <h1 className="text-xl font-semibold">{f.title}</h1>
        {f.description && (
          <p className="text-slate-700 whitespace-pre-wrap">{f.description}</p>
        )}
        <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-2 text-sm border-t border-slate-200 pt-3">
          <div>
            <dt className="text-slate-500 text-xs uppercase">Tool</dt>
            <dd>{f.source_tool}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Categoria</dt>
            <dd>{f.category}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Regra</dt>
            <dd>{f.rule_id ?? "-"}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Arquivo</dt>
            <dd className="break-all">
              {f.file_path ?? "-"}
              {f.line_start ? `:${f.line_start}` : ""}
              {f.line_end && f.line_end !== f.line_start ? `-${f.line_end}` : ""}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">CVE</dt>
            <dd>{f.cve ?? "-"}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">CWE</dt>
            <dd>{f.cwe && f.cwe.length ? f.cwe.join(", ") : "-"}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Pacote</dt>
            <dd>
              {f.package_name
                ? `${f.package_name}@${f.package_version ?? "?"}`
                : "-"}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Versao com fix</dt>
            <dd>{f.fixed_version ?? "-"}</dd>
          </div>
          <div>
            <dt className="text-slate-500 text-xs uppercase">Visto por ultimo</dt>
            <dd>{formatDate(f.last_seen)}</dd>
          </div>
        </dl>
        {f.category === "dast" && (f.url || f.http_method || f.parameter) && (
          <div className="border-t border-slate-200 pt-3 space-y-2">
            <div className="text-xs uppercase text-slate-500">Dados HTTP</div>
            <dl className="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-2 text-sm">
              {f.url && (
                <div className="md:col-span-3">
                  <dt className="text-slate-500 text-xs">URL</dt>
                  <dd className="font-mono text-xs break-all">{f.url}</dd>
                </div>
              )}
              <div>
                <dt className="text-slate-500 text-xs">Metodo</dt>
                <dd className="font-mono text-xs">{f.http_method ?? "-"}</dd>
              </div>
              <div>
                <dt className="text-slate-500 text-xs">Parametro</dt>
                <dd className="font-mono text-xs">{f.parameter ?? "-"}</dd>
              </div>
              {f.dast_scan_id && (
                <div>
                  <dt className="text-slate-500 text-xs">Scan DAST</dt>
                  <dd>
                    <Link
                      to={`/dast/scans/${f.dast_scan_id}`}
                      className="text-cyan-700 hover:underline text-xs font-mono"
                    >
                      {String(f.dast_scan_id).slice(0, 8)}
                    </Link>
                  </dd>
                </div>
              )}
            </dl>
            {f.evidence && (
              <div>
                <div className="text-xs uppercase text-slate-500 mb-1">
                  Evidencia
                </div>
                <pre className="bg-slate-900 text-slate-100 rounded p-3 text-xs overflow-x-auto whitespace-pre-wrap">
                  {f.evidence}
                </pre>
              </div>
            )}
            {f.solution && (
              <div>
                <div className="text-xs uppercase text-slate-500 mb-1">
                  Solucao sugerida pelo ZAP
                </div>
                <p className="text-sm text-slate-700 whitespace-pre-wrap">
                  {f.solution}
                </p>
              </div>
            )}
          </div>
        )}

        {f.snippet && (
          <div className="border-t border-slate-200 pt-3">
            <div className="text-xs uppercase text-slate-500 mb-1">Snippet</div>
            <pre className="bg-slate-900 text-slate-100 rounded p-3 text-xs overflow-x-auto">
              {f.snippet}
            </pre>
          </div>
        )}
        {f.ai_rationale && (
          <div className="border-t border-slate-200 pt-3">
            <div className="text-xs uppercase text-slate-500 mb-1">
              Analise da IA
            </div>
            <p className="text-sm text-slate-700 whitespace-pre-wrap">
              {f.ai_rationale}
            </p>
          </div>
        )}
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <h2 className="text-base font-semibold">Acoes</h2>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => analyzeMutation.mutate()}
            disabled={analyzeMutation.isPending}
            className="inline-flex items-center gap-2 rounded-md bg-slate-800 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-900 disabled:opacity-50"
          >
            {analyzeMutation.isPending && <Spinner className="h-3 w-3" />}
            Aprofundar
          </button>
          <button
            onClick={() => remediateMutation.mutate()}
            disabled={remediateMutation.isPending}
            className="inline-flex items-center gap-2 rounded-md bg-cyan-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-800 disabled:opacity-50"
          >
            {remediateMutation.isPending && <Spinner className="h-3 w-3" />}
            Gerar patch
          </button>
          <label className="text-sm inline-flex items-center gap-2">
            <span className="text-slate-500">Status</span>
            <select
              value={f.status}
              onChange={(e) =>
                statusMutation.mutate(e.target.value as FindingStatus)
              }
              disabled={statusMutation.isPending}
              className="rounded border border-slate-300 px-2 py-1 text-sm"
            >
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
        </div>
        {analyzeMutation.isPending && (
          <div className="text-xs text-slate-500">
            Analisando... isso pode levar ate 30s.
          </div>
        )}
        {analyzeMutation.isError && (
          <div className="text-sm text-red-700">
            {humanizeApiError(analyzeMutation.error)}
          </div>
        )}
        {remediateMutation.isPending && (
          <div className="text-xs text-slate-500">
            Gerando patch... isso pode levar ate 60s.
          </div>
        )}
        {remediateMutation.isError && (
          <div className="text-sm text-red-700">
            {humanizeApiError(remediateMutation.error)}
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-base font-semibold">Remediacoes</h2>
        {remediationsQuery.isPending && (
          <div className="flex items-center gap-2 text-slate-500">
            <Spinner /> Carregando...
          </div>
        )}
        {remediationsQuery.data && remediationsQuery.data.length === 0 && (
          <div className="text-sm text-slate-500 italic">
            Nenhum patch gerado ainda.
          </div>
        )}
        {remediationsQuery.data?.map((r) => (
          <div
            key={r.id}
            className="bg-white border border-slate-200 rounded-lg p-4 space-y-3"
          >
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                {r.breaking_risk && (
                  <span
                    className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${RISK_CLASS[r.breaking_risk]}`}
                  >
                    Risco de quebra: {RISK_LABEL[r.breaking_risk]}
                  </span>
                )}
                <span className="text-xs text-slate-500">
                  {formatDate(r.created_at)}
                  {r.model ? ` · ${r.model}` : ""}
                </span>
              </div>
              <label className="inline-flex items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={r.applied}
                  onChange={(e) =>
                    applyMutation.mutate({ id: r.id, applied: e.target.checked })
                  }
                />
                Aplicado
              </label>
            </div>
            {r.explanation && (
              <p className="text-sm text-slate-700 whitespace-pre-wrap">
                {r.explanation}
              </p>
            )}
            <DiffViewer diff={r.patch_diff} />
            {r.test_suggestion && (
              <div className="text-sm">
                <span className="text-xs uppercase text-slate-500">Teste</span>
                <p className="text-slate-700">{r.test_suggestion}</p>
              </div>
            )}
          </div>
        ))}
      </section>
    </div>
  );
}
