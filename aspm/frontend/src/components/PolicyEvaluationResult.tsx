import { Link } from "react-router-dom";
import type { PolicyEvaluation, PolicyViolation } from "../lib/types";
import RiskScoreChip from "./RiskScoreChip";

function VerdictBadge({ passed }: { passed: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${
        passed ? "bg-emerald-600 text-white" : "bg-rose-600 text-white"
      }`}
    >
      {passed ? "PASS" : "FAIL"}
    </span>
  );
}

function ActionPill({ action }: { action: PolicyViolation["action"] }) {
  const cls =
    action === "fail"
      ? "bg-rose-100 text-rose-800 border-rose-200"
      : "bg-amber-100 text-amber-800 border-amber-200";
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}
    >
      {action}
    </span>
  );
}

export default function PolicyEvaluationResult({
  evaluation,
}: {
  evaluation: PolicyEvaluation;
}) {
  const hits = Object.entries(evaluation.rule_hits);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
        <div className="flex items-center gap-2">
          <span className="text-slate-500">Resultado:</span>
          <VerdictBadge passed={evaluation.passed} />
        </div>
        <div>
          <span className="text-slate-500">Policy:</span>{" "}
          <span className="font-medium">{evaluation.policy_name}</span>
        </div>
        <div>
          <span className="text-slate-500">Findings avaliados:</span>{" "}
          <span className="font-medium">{evaluation.findings_considered}</span>
        </div>
        <div>
          <span className="text-slate-500">Fail / Warn:</span>{" "}
          <span className="font-medium text-rose-700">
            {evaluation.fail_count}
          </span>{" "}
          /{" "}
          <span className="font-medium text-amber-700">
            {evaluation.warn_count}
          </span>
        </div>
        {evaluation.scan_id && (
          <div>
            <span className="text-slate-500">Scan:</span>{" "}
            <Link
              to={`/scans/${evaluation.scan_id}`}
              className="text-cyan-700 hover:underline font-mono text-xs"
            >
              {evaluation.scan_id.slice(0, 8)}
            </Link>
          </div>
        )}
      </div>

      {hits.length > 0 && (
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
            Rule hits
          </div>
          <div className="flex flex-wrap gap-2">
            {hits.map(([ruleId, n]) => (
              <span
                key={ruleId}
                className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs ${
                  n > 0
                    ? "border-slate-300 bg-white text-slate-800"
                    : "border-slate-200 bg-slate-50 text-slate-400"
                }`}
              >
                <code className="font-mono">{ruleId}</code>
                <span className="font-semibold">{n}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {evaluation.violations.length === 0 ? (
        <div className="rounded border border-dashed border-slate-300 bg-white px-4 py-6 text-center text-sm text-slate-500">
          Nenhuma violacao.
        </div>
      ) : (
        <div className="overflow-x-auto border border-slate-200 rounded-lg bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-3 py-2">Acao</th>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">Finding</th>
                <th className="px-3 py-2">Tool / Categoria</th>
                <th className="px-3 py-2">Arquivo</th>
                <th className="px-3 py-2">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {evaluation.violations.map((v) => (
                <tr key={`${v.rule_id}:${v.finding_id}`} className="hover:bg-slate-50">
                  <td className="px-3 py-2">
                    <ActionPill action={v.action} />
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-700">
                    {v.rule_id}
                  </td>
                  <td className="px-3 py-2">
                    <Link
                      to={`/findings/${v.finding_id}`}
                      className="text-cyan-700 hover:underline"
                    >
                      {v.finding_title.length > 90
                        ? v.finding_title.slice(0, 87) + "..."
                        : v.finding_title}
                    </Link>
                  </td>
                  <td className="px-3 py-2 text-slate-600 text-xs">
                    {v.tool} / {v.category}
                  </td>
                  <td className="px-3 py-2 text-slate-500 text-xs font-mono">
                    {v.file_path ?? "-"}
                  </td>
                  <td className="px-3 py-2">
                    <RiskScoreChip value={v.risk_score} />
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
