import Spinner from "./Spinner";
import type { DastScanStatus } from "../lib/types";

const CLASSES: Record<DastScanStatus, string> = {
  pending: "bg-slate-200 text-slate-700",
  queued: "bg-slate-200 text-slate-700",
  running: "bg-cyan-100 text-cyan-800",
  completed: "bg-emerald-100 text-emerald-800",
  failed: "bg-red-100 text-red-800",
  cancelled: "bg-amber-100 text-amber-800",
};

const LABELS: Record<DastScanStatus, string> = {
  pending: "Pendente",
  queued: "Na fila",
  running: "Rodando",
  completed: "Concluido",
  failed: "Falhou",
  cancelled: "Cancelado",
};

export default function DastStatusPill({ status }: { status: DastScanStatus }) {
  const active = status === "pending" || status === "queued" || status === "running";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs font-medium ${CLASSES[status]}`}
    >
      {active && <Spinner className="h-3 w-3" />}
      {LABELS[status]}
    </span>
  );
}
