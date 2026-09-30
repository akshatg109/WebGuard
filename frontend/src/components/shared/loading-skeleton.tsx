import { Skeleton } from "@/components/ui/skeleton";

export function DashboardSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading dashboard" className="space-y-6" role="status">
      <div className="space-y-3"><Skeleton className="h-8 w-56" /><Skeleton className="h-4 w-80 max-w-full" /></div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {Array.from({ length: 5 }, (_, index) => <Skeleton className="h-28 rounded-xl" key={index} />)}
      </div>
      <div className="grid gap-4 xl:grid-cols-[1.1fr_1.9fr]">
        <Skeleton className="h-64 rounded-xl" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
      <span className="sr-only">Loading dashboard content</span>
    </div>
  );
}

export function ScanListSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading scan history" className="space-y-3" role="status">
      {Array.from({ length: 5 }, (_, index) => <Skeleton className="h-14 rounded-lg" key={index} />)}
      <span className="sr-only">Loading scan history</span>
    </div>
  );
}

export function ScanDetailsSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading scan report" className="space-y-6" role="status">
      <div className="space-y-3"><Skeleton className="h-8 w-48" /><Skeleton className="h-4 w-80 max-w-full" /></div>
      <Skeleton className="h-24 rounded-xl" />
      <div className="grid gap-4 xl:grid-cols-2"><Skeleton className="h-56 rounded-xl" /><Skeleton className="h-56 rounded-xl" /></div>
      <Skeleton className="h-40 rounded-xl" />
      <span className="sr-only">Loading scan report</span>
    </div>
  );
}
