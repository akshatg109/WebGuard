import {
  callScannerApi,
  forbiddenRequestResponse,
  invalidRequestResponse,
  readLimitedJson,
  sameOriginRequest,
} from "@/lib/scanner/server-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET(request: Request): Promise<Response> {
  const query = new URL(request.url).searchParams;
  const limitValue = query.get("limit");
  const offsetValue = query.get("offset");
  const limit = limitValue === null ? 100 : Number(limitValue);
  const offset = offsetValue === null ? 0 : Number(offsetValue);
  if (
    !Number.isInteger(limit) || limit < 1 || limit > 100 ||
    !Number.isInteger(offset) || offset < 0 || offset > 100_000
  ) {
    return invalidRequestResponse();
  }

  return callScannerApi({
    resource: "list",
    method: "GET",
    query: { limit, offset },
  });
}

export async function POST(request: Request): Promise<Response> {
  if (!sameOriginRequest(request)) return forbiddenRequestResponse();

  const parsed = await readLimitedJson(request);
  if ("error" in parsed) return parsed.error;
  const body = parsed.value;
  if (!isRecord(body) || Object.keys(body).length !== 1 || typeof body.url !== "string") {
    return invalidRequestResponse();
  }
  const url = body.url;
  if (!url.trim() || url.length > 2_048) return invalidRequestResponse();

  return callScannerApi({
    resource: "list",
    method: "POST",
    body: { url: url.trim() },
    allowFailureResult: true,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
