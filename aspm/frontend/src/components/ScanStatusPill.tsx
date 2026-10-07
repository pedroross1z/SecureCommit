import Spinner from "./Spinner";
import type { ScanStatus } from "../lib/types";

const CLASSES: Record<ScanStatus, string> = {
  queued: "bg-slate-200 text-slate-700",
  running: "bg-cyan-100 text-cyan-800",
  done: "bg-emerald-100 text-emerald-800",
  failed: "bg-red-100 text-red-800",
};

const LABELS: Record<ScanStatus, string> = {
  queued: "Na fila",
  running: "Rodando",
  done: "Concluido",
  failed: "Falhou",
};

export default function ScanStatusPill({ status }: { status: ScanStatus }) {
  const showSpinner = status === "queued" || status === "running";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs font-medium ${CLASSES[status]}`}
    >
      {showSpinner && <Spinner className="h-3 w-3" />}
      {LABELS[status]}
    </span>
  );
}
