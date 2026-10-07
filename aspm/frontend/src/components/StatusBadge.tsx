import type { FindingStatus } from "../lib/types";

const CLASSES: Record<FindingStatus, string> = {
  open: "bg-status-open text-white",
  triaged: "bg-status-triaged text-white",
  false_positive: "bg-status-false_positive text-white",
  fixed: "bg-status-fixed text-white",
  accepted_risk: "bg-status-accepted_risk text-white",
};

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Aberto",
  triaged: "Triado",
  false_positive: "Falso positivo",
  fixed: "Corrigido",
  accepted_risk: "Risco aceito",
};

export default function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${CLASSES[status]}`}
    >
      {STATUS_LABELS[status]}
    </span>
  );
}
