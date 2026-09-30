"use client";

import { useState } from "react";
import { AlertCircle, LoaderCircle, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScannerApiError, scannerApi } from "@/lib/scanner/api-client";
import type { FindingAiGuidance, ScanAiSummary } from "@/lib/scanner/types";

export function AiSummaryCard({
  scanId,
  available,
  initialSummary,
}: {
  scanId: string;
  available: boolean;
  initialSummary: ScanAiSummary | null;
}) {
  const [summary, setSummary] = useState(initialSummary);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function generate() {
    if (!available || loading) return;
    setLoading(true);
    setError(null);
    try {
      const next = await scannerApi.generateAiSummary(scanId, summary !== null);
      setSummary(next);
    } catch (cause) {
      setError(safeAiError(cause));
    } finally {
      setLoading(false);
    }
  }

  const content = summary?.content;
  return (
    <Card className="border-primary/20 bg-card/80 shadow-none">
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold tracking-[0.16em] text-primary uppercase">AI-generated guidance</p>
          <CardTitle className="mt-1.5 text-base">AI Security Summary</CardTitle>
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={generate}
          disabled={!available || loading}
          aria-label={summary ? "Regenerate AI security summary" : "Generate AI security summary"}
        >
          {loading ? <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" /> : <Sparkles aria-hidden="true" className="size-3.5" />}
          {loading ? "Generating…" : summary ? "Regenerate summary" : "Generate summary"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-4" aria-busy={loading}>
        {!available && !summary && <UnavailableNotice />}
        {error && <ErrorNotice message={error} onRetry={generate} loading={loading} />}
        {content && (
          <div className="space-y-4">
            <GuidanceBlock title="Short explanation">{content.posture}</GuidanceBlock>
            <div className="grid gap-4 sm:grid-cols-2">
              <GuidanceList title="Strongest observed controls" items={content.strongest_observed_controls} />
              <GuidanceList title="Important observed weaknesses" items={content.important_observed_weaknesses} />
            </div>
            <GuidanceList title="Recommended next steps" items={content.recommended_next_steps} />
            <p className="border-t border-border/60 pt-3 text-[11px] leading-5 text-muted-foreground">
              Limitations: {content.limitations}
            </p>
            <GeneratedMeta generatedAt={summary.generated_at} provider={summary.provider} model={summary.model} cached={summary.cached} />
          </div>
        )}
        <p className="text-[10px] leading-4 text-muted-foreground">
          No model calls happen when a report loads. Generating sends bounded, redacted findings to the configured server-side provider. AI guidance never changes WebGuard findings, severity, or score; the deterministic scan remains authoritative.
        </p>
      </CardContent>
    </Card>
  );
}

export function AiFindingGuidance({
  scanId,
  findingId,
  available,
  initialGuidance,
}: {
  scanId: string;
  findingId: string | null | undefined;
  available: boolean;
  initialGuidance: FindingAiGuidance | null;
}) {
  const [guidance, setGuidance] = useState(initialGuidance);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function generate() {
    if (!available || !findingId || loading) return;
    setLoading(true);
    setError(null);
    try {
      const next = await scannerApi.explainFinding(scanId, findingId, guidance !== null);
      setGuidance(next);
    } catch (cause) {
      setError(safeAiError(cause));
    } finally {
      setLoading(false);
    }
  }

  const content = guidance?.content;
  return (
    <section aria-label={`AI explanation for ${guidance?.finding_id ?? "finding"}`} className="space-y-3 rounded-lg border border-primary/15 bg-primary/[0.035] p-3.5 sm:p-4" aria-busy={loading}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold tracking-wide text-primary uppercase">AI-generated guidance</p>
          <h4 className="mt-1 text-xs font-semibold text-foreground">AI Explanation</h4>
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={generate}
          disabled={!available || !findingId || loading}
          aria-label={guidance ? "Regenerate AI finding explanation" : "Generate AI finding explanation"}
        >
          {loading ? <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" /> : <Sparkles aria-hidden="true" className="size-3.5" />}
          {loading ? "Generating…" : guidance ? "Regenerate" : "Explain with AI"}
        </Button>
      </div>
      {!available && !guidance && <UnavailableNotice />}
      {error && <ErrorNotice message={error} onRetry={generate} loading={loading} />}
      {content && (
        <div className="space-y-3">
          <GuidanceBlock title="What this means">{content.what_it_means}</GuidanceBlock>
          <GuidanceBlock title="Why it matters">{content.why_it_matters}</GuidanceBlock>
          <GuidanceBlock title="What WebGuard observed">{content.observed_evidence}</GuidanceBlock>
          <GuidanceBlock title="How to improve">{content.remediation}</GuidanceBlock>
          <p className="text-[10px] leading-4 text-muted-foreground">Limitations: {content.limitations}</p>
          {guidance && <GeneratedMeta generatedAt={guidance.generated_at} provider={guidance.provider} model={guidance.model} cached={guidance.cached} />}
        </div>
      )}
    </section>
  );
}

function GuidanceBlock({ title, children }: { title: string; children: string }) {
  return (
    <div>
      <p className="text-[10px] font-semibold text-muted-foreground">{title}</p>
      <p className="mt-1 whitespace-pre-wrap break-words text-xs leading-5 text-foreground/90">{children}</p>
    </div>
  );
}

function GuidanceList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <p className="text-[10px] font-semibold text-muted-foreground">{title}</p>
      {items.length > 0 ? (
        <ul className="mt-1 space-y-1.5 pl-4 text-xs leading-5 text-foreground/90">
          {items.map((item, index) => <li className="list-disc" key={`${index}:${item}`}>{item}</li>)}
        </ul>
      ) : (
        <p className="mt-1 text-xs leading-5 text-muted-foreground">No items were returned for this section.</p>
      )}
    </div>
  );
}

function UnavailableNotice() {
  return (
    <p className="rounded-md border border-border/70 bg-muted/20 p-3 text-xs leading-5 text-muted-foreground" role="status">
      AI guidance is unavailable because no server-side provider is configured. Deterministic findings and remediation remain available.
    </p>
  );
}

function ErrorNotice({ message, onRetry, loading }: { message: string; onRetry: () => void; loading: boolean }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-severity-high/25 bg-severity-high/5 p-3" role="alert">
      <p className="flex items-start gap-2 text-xs leading-5 text-foreground/90">
        <AlertCircle aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-severity-high" /> {message}
      </p>
      <Button type="button" variant="ghost" size="sm" onClick={onRetry} disabled={loading}>Try again</Button>
    </div>
  );
}

function GeneratedMeta({ generatedAt, provider, model, cached }: { generatedAt: string; provider: string; model: string; cached: boolean }) {
  const date = new Date(generatedAt);
  const dateLabel = Number.isNaN(date.getTime())
    ? "date unavailable"
    : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
  return (
    <p className="text-[10px] text-muted-foreground">
      {cached ? "Saved guidance" : "Generated"} · {provider} / {model} · {dateLabel}
    </p>
  );
}

function safeAiError(error: unknown): string {
  if (error instanceof ScannerApiError) return error.message;
  return "AI guidance could not be loaded right now. Please try again.";
}
