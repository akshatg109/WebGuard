"use client";

import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { LoaderCircle, ScanLine, ShieldAlert } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { friendlyScanError, scannerApi, ScannerApiError } from "@/lib/scanner/api-client";

const scanUrlSchema = z.object({
  url: z.string()
    .trim()
    .min(1, "Enter a website URL.")
    .max(2_048, "The URL must be 2,048 characters or fewer.")
    .superRefine((value, context) => {
      let parsed: URL;
      try {
        parsed = new URL(value);
      } catch {
        context.addIssue({ code: "custom", message: "Enter a complete URL, such as https://example.com." });
        return;
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        context.addIssue({ code: "custom", message: "Use an HTTP or HTTPS URL." });
      }
      if (!parsed.hostname || parsed.username || parsed.password) {
        context.addIssue({ code: "custom", message: "Enter a website URL without embedded credentials." });
      }
    }),
});

type ScanUrlValues = z.infer<typeof scanUrlSchema>;

export function NewScanDialog() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const form = useForm<ScanUrlValues>({
    resolver: zodResolver(scanUrlSchema),
    defaultValues: { url: "" },
  });
  const requestError = form.formState.errors.root?.serverError?.message;

  async function onSubmit(values: ScanUrlValues) {
    form.clearErrors("root.serverError");
    try {
      const result = await scannerApi.createScan(values.url);
      form.reset();
      setOpen(false);
      router.push(`/scans/${encodeURIComponent(result.id)}`);
      router.refresh();
    } catch (error) {
      const message = error instanceof ScannerApiError
        ? friendlyScanError(error.code)
        : friendlyScanError(undefined);
      form.setError("root.serverError", { type: "server", message });
    }
  }

  return (
    <Dialog
      onOpenChange={(nextOpen) => {
        if (!form.formState.isSubmitting) {
          setOpen(nextOpen);
          if (!nextOpen) form.clearErrors();
        }
      }}
      open={open}
    >
      <DialogTrigger render={<Button className="h-10 gap-2 px-4" />}>
        <ScanLine aria-hidden="true" className="size-4" />
        New scan
      </DialogTrigger>
      <DialogContent className="max-h-[calc(100dvh-2rem)] gap-5 overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <span className="mb-1 grid size-10 place-items-center rounded-xl border border-primary/20 bg-primary/10 text-primary">
            <ShieldAlert aria-hidden="true" className="size-5" />
          </span>
          <DialogTitle>Start a security assessment</DialogTitle>
          <DialogDescription className="leading-6">
            Provide a website URL. WebGuard runs a synchronous, passive configuration scan and saves the result to your account.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-4" noValidate onSubmit={form.handleSubmit(onSubmit)}>
          {requestError && (
            <div className="rounded-lg border border-severity-high/25 bg-severity-high/5 px-3 py-2.5 text-xs leading-5 text-foreground" role="alert">
              {requestError}
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="scan-target-url">Website URL</Label>
            <Input
              {...form.register("url")}
              aria-describedby={form.formState.errors.url ? "scan-target-url-error" : "scan-target-url-help"}
              aria-invalid={Boolean(form.formState.errors.url)}
              autoCapitalize="none"
              autoComplete="url"
              autoCorrect="off"
              className="h-11 font-mono text-sm"
              disabled={form.formState.isSubmitting}
              id="scan-target-url"
              inputMode="url"
              placeholder="https://example.com"
              type="url"
            />
            {form.formState.errors.url ? (
              <p className="text-xs text-destructive" id="scan-target-url-error" role="alert">
                {form.formState.errors.url.message}
              </p>
            ) : (
              <p className="text-[11px] leading-5 text-muted-foreground" id="scan-target-url-help">
                Only scan websites you own or are explicitly authorized to assess. The scanner applies its own target safety checks.
              </p>
            )}
          </div>
          <DialogFooter className="-mx-4 -mb-4">
            <Button className="w-full sm:w-auto" disabled={form.formState.isSubmitting} type="submit">
              {form.formState.isSubmitting ? (
                <><LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> Starting scan…</>
              ) : (
                <><ScanLine aria-hidden="true" className="size-4" /> Start scan</>
              )}
            </Button>
          </DialogFooter>
          <p aria-live="polite" className="sr-only" role="status">
            {form.formState.isSubmitting ? "Submitting scan request" : ""}
          </p>
        </form>
      </DialogContent>
    </Dialog>
  );
}
