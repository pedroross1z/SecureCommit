import type { AssetOut } from "../lib/types";
import { criticalityLabel, formatDate } from "../lib/format";

function Yn({ value }: { value: boolean | null | undefined }) {
  if (value == null) return <span className="text-slate-400">?</span>;
  return (
    <span className={value ? "text-emerald-700" : "text-slate-500"}>
      {value ? "sim" : "nao"}
    </span>
  );
}

export default function AssetContextCard({ asset }: { asset: AssetOut }) {
  const langs = asset.languages
    ? Object.keys(asset.languages).join(", ")
    : "-";
  const frameworks = asset.frameworks
    ? Object.keys(asset.frameworks).join(", ") || "-"
    : "-";
  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">{asset.name}</h1>
          <a
            href={asset.repo_url}
            target="_blank"
            rel="noreferrer"
            className="text-sm text-cyan-700 hover:underline break-all"
          >
            {asset.repo_url}
          </a>
        </div>
        <div className="text-sm text-slate-500">
          criado em {formatDate(asset.created_at)}
        </div>
      </div>
      <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-3 text-sm">
        <div>
          <dt className="text-slate-500 text-xs uppercase">Criticidade</dt>
          <dd className="font-medium">{criticalityLabel(asset.criticality)}</dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">Origem criticidade</dt>
          <dd>{asset.criticality_source ?? "-"}</dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">Branch</dt>
          <dd>{asset.default_branch ?? "-"}</dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">Dono</dt>
          <dd>{asset.owner ?? "-"}</dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">Linguagens</dt>
          <dd>{langs}</dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">Frameworks</dt>
          <dd>{frameworks}</dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">Internet-facing</dt>
          <dd>
            <Yn value={asset.internet_facing} />
          </dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">PII</dt>
          <dd>
            <Yn value={asset.handles_pii} />
          </dd>
        </div>
        <div>
          <dt className="text-slate-500 text-xs uppercase">Tem auth</dt>
          <dd>
            <Yn value={asset.has_auth} />
          </dd>
        </div>
      </dl>
      {asset.ai_rationale && (
        <div className="border-t border-slate-200 pt-3">
          <div className="text-xs uppercase text-slate-500 mb-1">
            Racional da IA (discovery)
          </div>
          <p className="text-sm text-slate-700 whitespace-pre-wrap">
            {asset.ai_rationale}
          </p>
        </div>
      )}
    </section>
  );
}
