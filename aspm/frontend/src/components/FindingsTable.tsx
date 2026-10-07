import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { listFindings } from "../lib/api";
import { STALE_LIST, qk } from "../lib/queries";
import type { FindingFilters, FindingStatus, SeverityRaw } from "../lib/types";
import SeverityBadge from "./SeverityBadge";
import StatusBadge, { STATUS_LABELS } from "./StatusBadge";
import RiskScoreChip from "./RiskScoreChip";
import Spinner from "./Spinner";

const SEVERITY_CATEGORY_OPTIONS: { value: SeverityRaw; label: string }[] = [
  { value: null, label: "todas" },
  { value: "critical", label: "critica" },
  { value: "high", label: "alta" },
  { value: "medium", label: "media" },
  { value: "low", label: "baixa" },
];

const STATUS_OPTIONS: (FindingStatus | "")[] = [
  "",
  "open",
  "triaged",
  "false_positive",
  "fixed",
  "accepted_risk",
];

function useDebounced<T>(value: T, delay = 400): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

export default function FindingsTable({
  assetId,
  scanId,
  clusterId,
}: {
  assetId?: string;
  scanId?: string;
  clusterId?: string;
}) {
  const [severity, setSeverity] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [minScoreInput, setMinScoreInput] = useState<string>("");
  const minScoreDebounced = useDebounced(minScoreInput);

  const filters: FindingFilters = useMemo(() => {
    const f: FindingFilters = {};
    if (assetId) f.asset_id = assetId;
    if (scanId) f.scan_id = scanId;
    if (status) f.status = status as FindingStatus;
    const n = Number(minScoreDebounced);
    if (minScoreDebounced && !Number.isNaN(n)) f.min_score = n;
    return f;
  }, [assetId, scanId, status, minScoreDebounced]);

  const query = useQuery({
    queryKey: [...qk.findings(filters), clusterId ?? null],
    queryFn: () => listFindings(filters),
    staleTime: STALE_LIST,
  });

  const items = useMemo(() => {
    const rows = query.data ?? [];
    if (!severity) return rows;
    return rows.filter((f) => {
      const s = String(f.severity_raw ?? "").toLowerCase();
      if (severity === "critical") return s === "critical" || s === "crit";
      if (severity === "high") return s === "high" || s === "error";
      if (severity === "medium") return s === "medium" || s === "warning" || s === "moderate";
      if (severity === "low") return s === "low" || s === "note";
      return true;
    });
  }, [query.data, severity]);

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
            {SEVERITY_CATEGORY_OPTIONS.map((o) => (
              <option key={o.value ?? "all"} value={o.value ?? ""}>
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
        <label className="text-sm">
          <span className="text-slate-500 block">Risk score minimo</span>
          <input
            type="number"
            min={0}
            max={100}
            value={minScoreInput}
            onChange={(e) => setMinScoreInput(e.target.value)}
            className="mt-1 w-24 rounded border border-slate-300 px-2 py-1 text-sm"
            placeholder="0-100"
          />
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
          Nenhum finding encontrado para os filtros atuais.
        </div>
      )}

      {items.length > 0 && (
        <div className="overflow-x-auto border border-slate-200 rounded-lg bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-3 py-2">Sev</th>
                <th className="px-3 py-2">Titulo</th>
                <th className="px-3 py-2">Tool</th>
                <th className="px-3 py-2">Cat</th>
                <th className="px-3 py-2">Arquivo</th>
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
                  <td className="px-3 py-2 text-slate-600">{f.source_tool}</td>
                  <td className="px-3 py-2 text-slate-600">{f.category}</td>
                  <td className="px-3 py-2 text-slate-600 max-w-xs truncate">
                    {f.file_path ?? "-"}
                    {f.line_start ? `:${f.line_start}` : ""}
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
