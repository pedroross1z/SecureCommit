import { useQuery } from "@tanstack/react-query";
import { getScan } from "../lib/api";
import { SCAN_POLL_MS, qk } from "../lib/queries";
import type { ScanOut } from "../lib/types";

export function useScanStatus(scanId: string | undefined) {
  return useQuery<ScanOut>({
    queryKey: qk.scan(scanId ?? ""),
    queryFn: () => getScan(scanId!),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      return s === "queued" || s === "running" ? SCAN_POLL_MS : false;
    },
  });
}
