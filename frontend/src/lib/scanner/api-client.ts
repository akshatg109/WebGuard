import type {
  FindingAiGuidance,
  Scan,
  ScanAiSummary,
  ScanFailure,
  ScanListResponse,
} from "@/lib/scanner/types";

const API_BASE = "/api/scans";

const ERROR_MESSAGES: Record<string, string> = {
  unauthorized: "Your session has expired. Sign in again to continue.",
  authentication_unavailable: "Authentication is temporarily unavailable. Please try again shortly.",
  auth_unavailable: "Authentication is not configured for this workspace.",
  rate_limit_exceeded: "You’ve reached the scan limit for now. Please wait before trying again.",
  invalid_request: "Enter a valid website URL and try again.",
  invalid_target: "That URL is invalid or cannot be scanned. Check it and try again.",
  blocked_target: "This target is not allowed by the scanner’s safety policy.",
  scan_not_found: "This scan could not be found in your account.",
  persistence_failure: "Scan data is temporarily unavailable. Please try again later.",
  network_failure: "The target could not be reached safely.",
  timeout: "The target took too long to respond. You can try again later.",
  scanner_error: "The scan could not be completed safely.",
  scanner_unavailable: "The scanner is temporarily unavailable. Please try again later.",
  ai_unavailable: "AI guidance is not configured. Deterministic scan findings remain available.",
  ai_provider_failure: "AI guidance could not be generated right now. Please retry later.",
  ai_invalid_response: "AI guidance returned an invalid response. Please retry later.",
  ai_persistence_failure: "AI guidance could not be saved right now. Please retry later.",
  ai_rate_limit_exceeded: "You’ve reached the AI guidance limit for now. Please wait before trying again.",
  ai_scan_not_complete: "AI guidance is available after a scan has completed.",
  ai_finding_not_found: "This finding could not be found in the selected scan.",
  ai_input_too_large: "AI guidance is unavailable because this scan has too much finding data.",
  internal_error: "The request could not be completed. Please try again.",
};

export class ScannerApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.internal_error);
    this.name = "ScannerApiError";
    this.status = status;
    this.code = ERROR_MESSAGES[code] ? code : "internal_error";
  }
}

type ApiErrorBody = { error?: { code?: unknown } };

async function readResponseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function apiError(response: Response, payload: unknown): ScannerApiError {
  const error = isRecord(payload) && isRecord((payload as ApiErrorBody).error)
    ? (payload as ApiErrorBody).error
    : undefined;
  const code = typeof error?.code === "string"
    ? error.code
    : response.status === 401
      ? "unauthorized"
      : response.status === 429
        ? "rate_limit_exceeded"
        : "internal_error";
  return new ScannerApiError(response.status, code);
}

function isScanFailure(value: unknown): value is ScanFailure {
  if (!isRecord(value) || value.status !== "failed") return false;
  return typeof value.id === "string" && typeof value.target_url === "string" && isRecord(value.error)
    && typeof value.error.code === "string" && typeof value.error.message === "string";
}

async function scannerFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json", ...init?.headers },
    });
  } catch {
    throw new ScannerApiError(0, "scanner_unavailable");
  }

  const payload = await readResponseBody(response);
  if (!response.ok) throw apiError(response, payload);
  if (payload === null) throw new ScannerApiError(response.status, "internal_error");
  return payload as T;
}

export const scannerApi = {
  listScans({ limit = 100, offset = 0 }: { limit?: number; offset?: number } = {}) {
    const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return scannerFetch<ScanListResponse>(`${API_BASE}?${query.toString()}`);
  },

  getScan(scanId: string) {
    return scannerFetch<Scan>(`${API_BASE}/${encodeURIComponent(scanId)}`);
  },

  generateAiSummary(scanId: string, regenerate = false) {
    return scannerFetch<ScanAiSummary>(`${API_BASE}/${encodeURIComponent(scanId)}/ai/summary`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ regenerate }),
    });
  },

  explainFinding(scanId: string, findingId: string, regenerate = false) {
    return scannerFetch<FindingAiGuidance>(
      `${API_BASE}/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/ai/explanation`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regenerate }),
      },
    );
  },

  async createScan(url: string): Promise<Scan | ScanFailure> {
    let response: Response;
    try {
      response = await fetch(API_BASE, {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
    } catch {
      throw new ScannerApiError(0, "scanner_unavailable");
    }

    const payload = await readResponseBody(response);
    if (isScanFailure(payload)) return payload;
    if (!response.ok) throw apiError(response, payload);
    if (!isRecord(payload) || typeof payload.id !== "string") {
      throw new ScannerApiError(response.status, "internal_error");
    }
    return payload as Scan;
  },
};

export function friendlyScanError(code: string | undefined): string {
  return ERROR_MESSAGES[code ?? ""] ?? ERROR_MESSAGES.internal_error;
}
