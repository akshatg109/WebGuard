import {
  callScannerApi,
  forbiddenRequestResponse,
  invalidRequestResponse,
  readLimitedJson,
  sameOriginRequest,
} from "@/lib/scanner/server-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

export async function POST(
  request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  if (!sameOriginRequest(request)) return forbiddenRequestResponse();
  const parsed = await readLimitedJson(request, 1_024);
  if ("error" in parsed) return parsed.error;
  const body = parsed.value;
  if (!isGenerationRequest(body)) return invalidRequestResponse();

  const { id } = await context.params;
  return callScannerApi({
    resource: { scanId: id, aiAction: "summary" },
    method: "POST",
    body: { regenerate: body.regenerate === true },
  });
}

function isGenerationRequest(value: unknown): value is { regenerate: boolean } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const body = value as Record<string, unknown>;
  const keys = Object.keys(body);
  return keys.length === 0 || (keys.length === 1 && keys[0] === "regenerate" && typeof body.regenerate === "boolean");
}
