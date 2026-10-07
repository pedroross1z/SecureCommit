import { severityToLevel } from "../lib/format";

const CLASSES: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-white",
  low: "bg-severity-low text-white",
  info: "bg-severity-info text-white",
  unknown: "bg-severity-unknown text-white",
};

const LABEL: Record<string, string> = {
  critical: "Critica",
  high: "Alta",
  medium: "Media",
  low: "Baixa",
  info: "Info",
  unknown: "?",
};

export default function SeverityBadge({
  severity,
}: {
  severity: string | null | undefined;
}) {
  const level = severityToLevel(severity);
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${CLASSES[level]}`}
    >
      {LABEL[level]}
    </span>
  );
}
