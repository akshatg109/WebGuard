"use client";

import { useEffect } from "react";
import { CircleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Dashboard route failed", error.digest);
  }, [error.digest]);

  return (
    <section className="flex min-h-[50vh] flex-col items-center justify-center px-5 text-center" role="alert">
      <CircleAlert aria-hidden="true" className="size-8 text-severity-high" />
      <h1 className="mt-4 text-lg font-semibold">We couldn’t load this dashboard</h1>
      <p className="mt-2 max-w-sm text-sm leading-6 text-muted-foreground">Your session is still protected. Try loading the page again.</p>
      <Button className="mt-5" onClick={reset} variant="outline">Try again</Button>
    </section>
  );
}
