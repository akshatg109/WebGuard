import type { Finding, JsonObject, JsonValue, Scan, ScanSummary, Severity, SeverityCounts } from "@/lib/scanner/types";

const SENSITIVE_EVIDENCE_KEY = /authorization|cookie.?value|set-cookie|token|secret|password|stack|trace|exception|response.?body|server_values|x_powered_by_values|resolved_addresses/i;
const URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IPV4_LITERAL_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6_PATTERN = /\b(?:[\da-f]{1,4}:){2,7}[\da-f]{0,4}\b/gi;

const CHECK_LABELS: Record<string, string> = {
  "transport.https": "HTTPS availability",
  "transport.http_to_https_redirect": "HTTP-to-HTTPS redirect",
  "transport.final_scheme": "Final URL scheme",
  "headers.hsts": "HTTP Strict Transport Security",
  "headers.csp": "Content Security Policy",
  "headers.x_content_type_options": "X-Content-Type-Options",
  "headers.referrer_policy": "Referrer Policy",
  "headers.permissions_policy": "Permissions Policy",
  "headers.frame_protection": "Frame protection",
  "exposure.server_headers": "Server information exposure",
  "cookies.security_attributes": "Cookie security attributes",
  "content.mixed_http_resources": "Mixed-content references",
  "technology.passive_indicators": "Passive technology indicators",
};

export function checkLabel(checkId: string): string {
  return CHECK_LABELS[checkId] ?? checkId.replaceAll(".", " · ").replaceAll("_", " ");
}

export function scoreDisplay(scan: Scan | ScanSummary | null) {
  if (!scan || scan.status !== "completed") return null;
  const counts = emptySeverityCounts();
  let findingCount = 0;
  if ("findings" in scan) {
    for (const finding of scan.findings) {
      if (finding.status !== "fail" && finding.status !== "warn" && finding.status !== "error") continue;
      counts[finding.severity] += 1;
      findingCount += 1;
    }
    return { counts, findingCount };
  }
  return scan.severity_counts === null
    ? { counts: null, findingCount: null }
    : { counts: scan.severity_counts, findingCount: scan.finding_count };
}

export function emptySeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

export function formatEvidence(evidence: JsonObject): string {
  const entries = Object.entries(evidence)
    .filter(([key]) => !SENSITIVE_EVIDENCE_KEY.test(key))
    .map(([key, value]) => `${key.replaceAll("_", " ")}: ${formatJsonValue(value, key)}`)
    .filter((entry) => !entry.endsWith(": "));
  return entries.length > 0 ? entries.join(" · ") : "No shareable evidence provided.";
}

function formatJsonValue(value: JsonValue, key: string): string {
  if (SENSITIVE_EVIDENCE_KEY.test(key)) return "[redacted]";
  if (typeof value === "string") return sanitizeEvidenceText(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value === null) return "not observed";
  if (Array.isArray(value)) {
    return value.map((item) => formatJsonValue(item, key)).filter(Boolean).join(", ");
  }
  const safeEntries = Object.entries(value)
    .filter(([childKey]) => !SENSITIVE_EVIDENCE_KEY.test(childKey))
    .map(([childKey, childValue]) => `${childKey.replaceAll("_", " ")}: ${formatJsonValue(childValue, childKey)}`);
  return safeEntries.join(", ");
}

function sanitizeEvidenceText(value: string): string {
  const noSensitiveUrls = value.replace(URL_PATTERN, (rawUrl) => {
    try {
      const url = new URL(rawUrl);
      url.username = "";
      url.password = "";
      url.search = "";
      url.hash = "";
      const host = url.hostname.toLowerCase();
      if (
        host === "localhost" ||
        host.endsWith(".localhost") ||
        host.endsWith(".local") ||
        host.endsWith(".internal") ||
        isIpLiteral(host)
      ) {
        return "[destination redacted]";
      }
      return url.toString();
    } catch {
      return "[URL redacted]";
    }
  });
  return noSensitiveUrls.replace(IPV4_PATTERN, "[address redacted]").replace(IPV6_PATTERN, "[address redacted]");
}

function isIpLiteral(host: string): boolean {
  return IPV4_LITERAL_PATTERN.test(host) || host.includes(":");
}

export function actionableFindings(scan: Scan): Finding[] {
  return scan.findings.filter((finding) => ["fail", "warn", "error"].includes(finding.status));
}

export function severityLabel(severity: Severity): string {
  return severity[0].toUpperCase() + severity.slice(1);
}
