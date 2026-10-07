import { useQuery } from "@tanstack/react-query";
import { getDastScan } from "../lib/api";
import { SCAN_POLL_MS, qk } from "../lib/queries";
import type { DastScanOut } from "../lib/types";

export function useDastScanStatus(scanId: string | undefined) {
  return useQuery<DastScanOut>({
    queryKey: qk.dastScan(scanId ?? ""),
    queryFn: () => getDastScan(scanId!),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      return s === "pending" || s === "queued" || s === "running"
        ? SCAN_POLL_MS
        : false;
    },
  });
}
