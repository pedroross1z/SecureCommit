import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getDastScanFindings } from "../lib/api";
import { STALE_LIST, qk } from "../lib/queries";
import SeverityBadge from "./SeverityBadge";
import RiskScoreChip from "./RiskScoreChip";
import StatusBadge, { STATUS_LABELS } from "./StatusBadge";
import Spinner from "./Spinner";
import type { FindingStatus } from "../lib/types";

const SEVERITY_OPTIONS: { value: string; label: string }[] = [
  { value: "", label: "todas" },
  { value: "high", label: "alta" },
  { value: "medium", label: "media" },
  { value: "low", label: "baixa" },
  { value: "info", label: "info" },
];

const STATUS_OPTIONS: (FindingStatus | "")[] = [
  "",
  "open",
  "triaged",
  "false_positive",
  "fixed",
  "accepted_risk",
];

export default function DastFindingsTable({ scanId }: { scanId: string }) {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  const query = useQuery({
    queryKey: qk.dastScanFindings(scanId),
    queryFn: () => getDastScanFindings(scanId),
    staleTime: STALE_LIST,
  });

  const items = useMemo(() => {
    const rows = query.data ?? [];
    return rows.filter((f) => {
      if (severity && String(f.severity_raw ?? "").toLowerCase() !== severity) {
        return false;
      }
      if (status && f.status !== status) return false;
      return true;
    });
  }, [query.data, severity, status]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="text-slate-500 block">Severidade</span>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="mt-1 rounded border border-slate-300 px-2 py-1 text-sm"
          >
            {SEVERITY_OPTIONS.map((o) => (
              <option key={o.value || "all"} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="text-slate-500 block">Status</span>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="mt-1 rounded border border-slate-300 px-2 py-1 text-sm"
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s || "all"} value={s}>
                {s ? STATUS_LABELS[s as FindingStatus] : "todos"}
              </option>
            ))}
          </select>
        </label>
        {query.isFetching && <Spinner className="h-4 w-4 text-slate-500" />}
      </div>

      {query.isError && (
        <div className="text-sm text-red-700">
          Falha ao carregar findings: {String(query.error)}
        </div>
      )}

      {!query.isError && items.length === 0 && !query.isPending && (
        <div className="text-sm text-slate-500 italic py-6">
          Nenhum finding DAST ainda para este scan.
        </div>
      )}

      {items.length > 0 && (
        <div className="overflow-x-auto border border-slate-200 rounded-lg bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-3 py-2">Sev</th>
                <th className="px-3 py-2">Alerta</th>
                <th className="px-3 py-2">URL</th>
                <th className="px-3 py-2">Metodo</th>
                <th className="px-3 py-2">Parametro</th>
                <th className="px-3 py-2">CWE</th>
                <th className="px-3 py-2">Risk</th>
                <th className="px-3 py-2">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {items.map((f) => (
                <tr key={f.id} className="hover:bg-slate-50">
                  <td className="px-3 py-2">
                    <SeverityBadge severity={f.severity_raw} />
                  </td>
                  <td className="px-3 py-2">
                    <Link
                      to={`/findings/${f.id}`}
                      className="font-medium text-cyan-700 hover:underline"
                    >
                      {f.title}
                    </Link>
                    {f.rule_id && (
                      <div className="text-xs text-slate-500">{f.rule_id}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-slate-600 max-w-xs truncate font-mono text-xs">
                    {f.url ?? f.file_path ?? "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-600 text-xs">
                    {f.http_method ?? "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-600 text-xs">
                    {f.parameter ?? "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-600 text-xs">
                    {f.cwe?.join(", ") || "-"}
                  </td>
                  <td className="px-3 py-2">
                    <RiskScoreChip value={f.risk_score} />
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge status={f.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
