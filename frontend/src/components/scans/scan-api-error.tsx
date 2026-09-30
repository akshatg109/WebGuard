import Link from "next/link";
import { CircleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { friendlyScanError, ScannerApiError } from "@/lib/scanner/api-client";

export function ScanApiErrorState({
  error,
  onRetry,
  title = "Scan data could not be loaded",
}: {
  error: unknown;
  onRetry: () => void;
  title?: string;
}) {
  const isUnauthorized = error instanceof ScannerApiError && error.status === 401;
  const code = error instanceof ScannerApiError ? error.code : undefined;

  return (
    <section className="flex flex-col items-center rounded-xl border border-severity-high/25 bg-severity-high/5 px-5 py-8 text-center" role="alert">
      <CircleAlert aria-hidden="true" className="size-7 text-severity-high" />
      <h2 className="mt-3 text-sm font-semibold text-foreground">{title}</h2>
      <p className="mt-1.5 max-w-lg text-xs leading-5 text-muted-foreground">{friendlyScanError(code)}</p>
      <div className="mt-4 flex flex-wrap justify-center gap-2">
        {isUnauthorized && <Button render={<Link href="/login" />} size="sm">Sign in again</Button>}
        <Button onClick={onRetry} size="sm" variant="outline">Try again</Button>
      </div>
    </section>
  );
}
