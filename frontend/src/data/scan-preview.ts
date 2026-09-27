import type { ScanStatus } from "@/components/shared/scan-status-badge";

/** Empty preview data by design: no target has been scanned by this UI. */
export type ScanListItem = {
  id: string;
  targetUrl: string;
  createdAt: string;
  status: ScanStatus;
  score: number | null;
  findingCount: number | null;
};

export const scanPreviewData: ScanListItem[] = [];
