import { riskScoreColor } from "../lib/format";

export default function RiskScoreChip({
  value,
}: {
  value: number | null | undefined;
}) {
  if (value == null) {
    return <span className="text-slate-400 text-sm">-</span>;
  }
  const { bg, text } = riskScoreColor(value);
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${bg} ${text}`}
    >
      {value}/100
    </span>
  );
}
