import "server-only";

import { createClient } from "@/lib/supabase/server";
import { hasSupabasePublicConfig } from "@/lib/supabase/config";

const SAFE_MESSAGES: Record<string, string> = {
  unauthorized: "Your session has expired. Sign in again to continue.",
  authentication_unavailable: "Authentication is temporarily unavailable. Please try again shortly.",
  rate_limit_exceeded: "You’ve reached the scan limit for now. Please wait before trying again.",
  invalid_request: "Enter a valid website URL and try again.",
  invalid_target: "That URL is invalid or cannot be scanned. Check it and try again.",
  blocked_target: "This target is not allowed by the scanner’s safety policy.",
  scan_not_found: "This scan could not be found in your account.",
  persistence_failure: "Scan data is temporarily unavailable. Please try again later.",
  network_failure: "The target could not be reached safely.",
  timeout: "The target took too long to respond. You can try again later.",
  scanner_error: "The scan could not be completed safely.",
  internal_error: "The request could not be completed. Please try again.",
  scanner_unavailable: "The scanner is temporarily unavailable. Please try again later.",
  ai_unavailable: "AI guidance is not configured. Deterministic scan findings remain available.",
  ai_provider_failure: "AI guidance could not be generated right now. Please retry later.",
  ai_invalid_response: "AI guidance returned an invalid response. Please retry later.",
  ai_persistence_failure: "AI guidance could not be saved right now. Please retry later.",
  ai_rate_limit_exceeded: "You’ve reached the AI guidance limit for now. Please wait before trying again.",
  ai_scan_not_complete: "AI guidance is available after a scan has completed.",
  ai_finding_not_found: "This finding could not be found in the selected scan.",
  ai_input_too_large: "AI guidance is unavailable because this scan has too much finding data.",
};

const SCANNER_ERROR_CODES = new Set(Object.keys(SAFE_MESSAGES));
const SCAN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FINDING_ID_PATTERN = SCAN_ID_PATTERN;
const RENDER_PRIVATE_HOSTPORT_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:10000$/i;
const MAX_UPSTREAM_RESPONSE_BYTES = 2 * 1024 * 1024;

type ScannerResource =
  | "list"
  | { scanId: string }
  | { scanId: string; aiAction: "summary" }
  | { scanId: string; findingId: string; aiAction: "explanation" };

function jsonError(status: number, code: string, retryAfter?: string | null): Response {
  const safeCode = SCANNER_ERROR_CODES.has(code) ? code : "internal_error";
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  if (status === 429 && retryAfter && /^\d{1,5}$/.test(retryAfter)) {
    headers.set("Retry-After", retryAfter);
  }
  return new Response(JSON.stringify({ error: { code: safeCode, message: SAFE_MESSAGES[safeCode] } }), {
    status,
    headers,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function getVerifiedAccessToken(): Promise<{ token: string } | { error: Response }> {
  if (!hasSupabasePublicConfig()) {
    return { error: jsonError(503, "authentication_unavailable") };
  }

  try {
    const supabase = await createClient();
    const { data: claimsData, error: claimsError } = await supabase.auth.getClaims();
    if (claimsError || typeof claimsData?.claims?.sub !== "string") {
      return { error: jsonError(401, "unauthorized") };
    }

    const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
    const session = sessionData.session;
    if (
      sessionError ||
      !session?.access_token ||
      session.user.id !== claimsData.claims.sub
    ) {
      return { error: jsonError(401, "unauthorized") };
    }
    return { token: session.access_token };
  } catch {
    return { error: jsonError(503, "authentication_unavailable") };
  }
}

function scannerEndpoint(
  resource: ScannerResource,
  query?: { limit: number; offset: number },
): string | null {
  let base: URL;
  try {
    if (process.env.NODE_ENV === "production") {
      // Production is restricted to Render's Blueprint-sourced private
      // host:port. Do not fall back to SCANNER_API_URL, which could point at a
      // public scanner endpoint. Render's private network is not documented as
      // transport-encrypted, so the service and user credentials remain
      // mandatory defense in depth rather than a substitute for TLS.
      const privateHostport = process.env.SCANNER_API_PRIVATE_HOSTPORT;
      if (
        !privateHostport ||
        privateHostport !== privateHostport.trim() ||
        !RENDER_PRIVATE_HOSTPORT_PATTERN.test(privateHostport)
      ) {
        return null;
      }
      base = new URL(`http://${privateHostport}`);
    } else {
      const configured = process.env.SCANNER_API_URL?.trim();
      if (!configured) return null;

      base = new URL(configured);
      const isLocalHost = ["localhost", "127.0.0.1", "[::1]"].includes(
        base.hostname.toLowerCase(),
      );
      const localDevelopmentHttp =
        base.protocol === "http:" && isLocalHost;
      if (
        (base.protocol !== "https:" && !localDevelopmentHttp) ||
        base.username || base.password || base.search || base.hash
      ) {
        return null;
      }
    }

    const prefix = base.pathname.replace(/\/+$/, "");
    const path = resource === "list"
      ? "/api/scans"
      : "aiAction" in resource
        ? resource.aiAction === "summary"
          ? `/api/scans/${resource.scanId}/ai/summary`
          : `/api/scans/${resource.scanId}/findings/${resource.findingId}/ai/explanation`
        : `/api/scans/${resource.scanId}`;
    const endpoint = new URL(`${base.origin}${prefix}${path}`);
    if (resource === "list" && query) {
      endpoint.searchParams.set("limit", String(query.limit));
      endpoint.searchParams.set("offset", String(query.offset));
    }
    return endpoint.toString();
  } catch {
    return null;
  }
}

export async function callScannerApi({
  resource,
  method,
  body,
  query,
  allowFailureResult = false,
}: {
  resource: ScannerResource;
  method: "GET" | "POST";
  body?: { url: string } | { regenerate: boolean };
  query?: { limit: number; offset: number };
  allowFailureResult?: boolean;
}): Promise<Response> {
  if (resource !== "list" && !SCAN_ID_PATTERN.test(resource.scanId)) {
    return jsonError(404, "scan_not_found");
  }
  if (resource !== "list" && "findingId" in resource && !FINDING_ID_PATTERN.test(resource.findingId)) {
    return jsonError(404, "ai_finding_not_found");
  }

  const scannerServiceToken = process.env.SCANNER_API_TOKEN;
  if (
    !scannerServiceToken ||
    scannerServiceToken.length < 32 ||
    scannerServiceToken.trim() !== scannerServiceToken
  ) {
    return jsonError(503, "scanner_unavailable");
  }

  const auth = await getVerifiedAccessToken();
  if ("error" in auth) return auth.error;

  const endpoint = scannerEndpoint(resource, query);
  if (!endpoint) return jsonError(503, "scanner_unavailable");

  let upstream: Response;
  try {
    upstream = await fetch(endpoint, {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${auth.token}`,
        "X-WebGuard-Scanner-Token": scannerServiceToken,
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(45_000),
    });
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      return jsonError(504, "timeout");
    }
    return jsonError(503, "scanner_unavailable");
  }

  let payload: unknown;
  try {
    const contentLength = upstream.headers.get("content-length");
    if (contentLength && Number(contentLength) > MAX_UPSTREAM_RESPONSE_BYTES) {
      return jsonError(502, "scanner_unavailable");
    }
    const reader = upstream.body?.getReader();
    if (!reader) return jsonError(502, "scanner_unavailable");
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_UPSTREAM_RESPONSE_BYTES) {
        await reader.cancel();
        return jsonError(502, "scanner_unavailable");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return jsonError(502, "scanner_unavailable");
  }

  if (!upstream.ok) {
    if (
      allowFailureResult &&
      isRecord(payload) &&
      payload.status === "failed" &&
      typeof payload.id === "string" &&
      typeof payload.target_url === "string" &&
      isRecord(payload.error)
    ) {
      const errorCode = typeof payload.error.code === "string" && SCANNER_ERROR_CODES.has(payload.error.code)
        ? payload.error.code
        : "scanner_error";
      return Response.json(
        {
          id: payload.id,
          target_url: payload.target_url,
          status: "failed",
          error: { code: errorCode, message: SAFE_MESSAGES[errorCode] },
        },
        { status: upstream.status, headers: { "Cache-Control": "no-store" } },
      );
    }

    const error = isRecord(payload) && isRecord(payload.error) ? payload.error : null;
    const code = error && typeof error.code === "string" && SCANNER_ERROR_CODES.has(error.code)
      ? error.code
      : upstream.status === 401
        ? "unauthorized"
        : upstream.status === 429
          ? "rate_limit_exceeded"
          : upstream.status === 404
            ? "scan_not_found"
            : "internal_error";
    return jsonError(upstream.status, code, upstream.headers.get("Retry-After"));
  }

  if (!isRecord(payload)) return jsonError(502, "scanner_unavailable");
  return Response.json(payload, {
    status: upstream.status,
    headers: { "Cache-Control": "no-store" },
  });
}

export async function readLimitedJson(
  request: Request,
  maxBytes = 8_192,
): Promise<{ value: unknown } | { error: Response }> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    return { error: jsonError(415, "invalid_request") };
  }

  const contentLength = request.headers.get("content-length");
  if (contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes)) {
    return { error: jsonError(413, "invalid_request") };
  }

  const reader = request.body?.getReader();
  if (!reader) return { error: jsonError(400, "invalid_request") };
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        return { error: jsonError(413, "invalid_request") };
      }
      chunks.push(value);
    }
  } catch {
    return { error: jsonError(400, "invalid_request") };
  }

  try {
    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown };
  } catch {
    return { error: jsonError(400, "invalid_request") };
  }
}

export function sameOriginRequest(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const forwardedHost = request.headers.get("x-forwarded-host")?.split(",", 1)[0]?.trim();
    const host = forwardedHost || request.headers.get("host") || new URL(request.url).host;
    const forwardedProtocol = request.headers.get("x-forwarded-proto")?.split(",", 1)[0]?.trim();
    const protocol = forwardedProtocol
      ? `${forwardedProtocol.replace(/:$/, "")}:`
      : new URL(request.url).protocol;
    if (!host || !["http:", "https:"].includes(protocol)) return false;
    const requestOrigin = new URL(`${protocol}//${host}`).origin;
    return new URL(origin).origin === requestOrigin;
  } catch {
    return false;
  }
}

export function invalidRequestResponse(): Response {
  return jsonError(422, "invalid_request");
}

export function forbiddenRequestResponse(): Response {
  return jsonError(403, "invalid_request");
}
