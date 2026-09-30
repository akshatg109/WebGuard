import { callScannerApi } from "@/lib/scanner/server-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await context.params;
  return callScannerApi({ resource: { scanId: id }, method: "GET" });
}
