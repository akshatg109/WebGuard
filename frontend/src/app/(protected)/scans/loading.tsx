import { ScanListSkeleton } from "@/components/shared/loading-skeleton";
import { Skeleton } from "@/components/ui/skeleton";

export default function ScansLoading() {
  return (
    <div aria-busy="true" aria-label="Loading scans" className="space-y-6" role="status">
      <div className="space-y-3"><Skeleton className="h-8 w-36" /><Skeleton className="h-4 w-96 max-w-full" /></div>
      <ScanListSkeleton />
    </div>
  );
}
