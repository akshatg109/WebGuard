export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type CheckStatus = "pass" | "fail" | "warn" | "not_applicable" | "error";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type ScoreConfidence = "complete" | "partial" | "limited";
export type FindingCategory = "transport" | "headers" | "exposure" | "cookies" | "content" | "technology";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

export type Score = {
  value: number | null;
  available: boolean;
  confidence: ScoreConfidence | null;
  scoringVersion: string | null;
};

export type CategoryBreakdown = {
  category: FindingCategory;
  budget_points: number;
  available_points: number;
  resolved_points: number;
  unassessed_points: number;
  deductions: number;
  resulting_points: number;
  state: string;
};

export type ScoreBreakdown = {
  applicable_points?: number;
  resolved_points?: number;
  unassessed_points?: number;
  deductions?: number;
  point_coverage_percent?: number | null;
  applicable_checks?: number;
  resolved_checks?: number;
  check_coverage_percent?: number | null;
  categories?: CategoryBreakdown[];
  weakest_categories?: FindingCategory[];
  unavailability_reasons?: string[];
};

export type Finding = {
  id?: string | null;
  check_id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  status: CheckStatus;
  summary: string;
  why_it_matters: string;
  evidence: JsonObject;
  remediation: string;
  affected_url: string;
  metadata: JsonObject;
};

export type FindingAiGuidance = {
  finding_id: string;
  generated_at: string;
  provider: string;
  model: string;
  prompt_version: string;
  cached: boolean;
  content: {
    what_it_means: string;
    why_it_matters: string;
    observed_evidence: string;
    remediation: string;
    limitations: string;
  };
};

export type ScanAiSummary = {
  generated_at: string;
  provider: string;
  model: string;
  prompt_version: string;
  cached: boolean;
  content: {
    posture: string;
    strongest_observed_controls: string[];
    important_observed_weaknesses: string[];
    recommended_next_steps: string[];
    limitations: string;
  };
};

export type Technology = {
  name: string;
  category: string;
  confidence: "low" | "medium" | "high" | null;
  evidence: JsonValue[];
};

export type CheckResult = {
  check_id: string;
  status: CheckStatus;
  severity: Severity | null;
  scoring_relevant: boolean;
  scoring_version: string;
  check_version: string;
  reason: string;
  evidence: JsonObject;
  score_explanation: JsonObject;
};

export type ApiError = {
  code: string;
  message: string;
};

export type Scan = {
  id: string;
  target_url: string;
  normalized_url: string | null;
  status: ScanStatus;
  created_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  score: number | null;
  score_available: boolean;
  confidence: ScoreConfidence | null;
  scoring_version: string | null;
  score_unavailability_reasons: string[];
  score_details: ScoreBreakdown;
  summary: string;
  findings: Finding[];
  technologies: Technology[];
  check_results: CheckResult[];
  ai_available: boolean;
  ai_summary: ScanAiSummary | null;
  ai_explanations: FindingAiGuidance[];
  error: ApiError | null;
};

export type ScanFailure = {
  id: string;
  target_url: string;
  status: "failed";
  error: ApiError;
};

export type SeverityCounts = Record<Severity, number>;

export type ScanSummary = {
  id: string;
  target_url: string;
  normalized_url: string | null;
  status: ScanStatus;
  score: number | null;
  score_available: boolean;
  confidence: ScoreConfidence | null;
  created_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  finding_count: number | null;
  severity_counts: SeverityCounts | null;
};

export type ScanListResponse = {
  items: ScanSummary[];
  total: number;
  limit: number;
  offset: number;
};

export function scoreFromScan(scan: Pick<Scan, "score" | "score_available" | "confidence" | "scoring_version"> | ScanSummary): Score {
  return {
    value: scan.score,
    available: scan.score_available,
    confidence: scan.confidence,
    scoringVersion: "scoring_version" in scan ? scan.scoring_version : null,
  };
}
