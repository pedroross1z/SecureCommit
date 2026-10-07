export type SeverityLevel =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "unknown";

const _dtFmt = new Intl.DateTimeFormat("pt-BR", {
  dateStyle: "short",
  timeStyle: "short",
});

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  try {
    return _dtFmt.format(new Date(iso));
  } catch {
    return iso;
  }
}

export function severityToLevel(raw: string | null | undefined): SeverityLevel {
  if (!raw) return "unknown";
  const s = String(raw).toLowerCase().trim();
  if (["critical", "crit"].includes(s)) return "critical";
  if (["high", "error"].includes(s)) return "high";
  if (["medium", "moderate", "warning"].includes(s)) return "medium";
  if (["low", "note", "info-low"].includes(s)) return "low";
  if (["info", "informational", "note-info"].includes(s)) return "info";
  // Score CVSS-like (float)
  const n = Number(s);
  if (!Number.isNaN(n)) {
    if (n >= 9) return "critical";
    if (n >= 7) return "high";
    if (n >= 4) return "medium";
    if (n > 0) return "low";
  }
  return "unknown";
}

export function riskScoreColor(score: number): {
  bg: string;
  text: string;
} {
  if (score >= 80) return { bg: "bg-risk-critical", text: "text-white" };
  if (score >= 60) return { bg: "bg-risk-high", text: "text-white" };
  if (score >= 40) return { bg: "bg-risk-elevated", text: "text-slate-900" };
  if (score >= 20) return { bg: "bg-risk-moderate", text: "text-white" };
  return { bg: "bg-risk-low", text: "text-white" };
}

export function criticalityLabel(n: number | null | undefined): string {
  if (n == null) return "desconhecida";
  return ({
    1: "1 - muito baixa",
    2: "2 - baixa",
    3: "3 - media",
    4: "4 - alta",
    5: "5 - critica",
  } as Record<number, string>)[n] ?? String(n);
}
