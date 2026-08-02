export type Project = {
  id: string;
  name: string;
  created_at: string;
};

export type DashboardSummary = {
  schema_version: "v1";
  phase: "web-foundation";
  execution_available: boolean;
  counts: {
    projects: number;
    engagements: number;
    active_actions: number;
    pending_approvals: number;
    evidence: number;
    findings: number;
  };
  recent_projects: Project[];
};

export type ProjectList = {
  schema_version: "v1";
  items: Project[];
  total: number;
};

export type HealthStatus = {
  schema_version: "v1";
  version: string;
};

export type Engagement = {
  id: string;
  project_id: string;
  name: string;
};

export type AssessmentSummary = {
  schema_version: "v1";
  action_id: string;
  engagement_id: string;
  state: string;
  evidence_ids: string[];
  finding_ids: string[];
  findings_count: number;
  error_code: string | null;
  replayed: boolean;
  pages_scanned: number;
  crawl_truncated: boolean;
  active_probes_run: number;
  active_probe_truncated: boolean;
  report_url: string;
  markdown_report_url: string;
  html_report_url: string;
};

export type AssessmentHistoryItem = {
  action_id: string;
  engagement_id: string;
  project_id: string;
  target: string;
  state: string;
  created_at: string;
  completed_at: string | null;
  evidence_count: number;
  findings_count: number;
  error_code: string | null;
  report_url: string;
  markdown_report_url: string;
};

export type AssessmentList = {
  schema_version: "v1";
  items: AssessmentHistoryItem[];
  total: number;
};

export type EngagementReport = {
  schema_version: "v1";
  report_version: "v1";
  generated_at: string;
  engagement_id: string;
  project_id: string;
  engagement_name: string;
  counts: {
    actions: number;
    evidence: number;
    findings: number;
  };
  evidence_integrity: {
    status: "valid" | "invalid" | "not_available";
    checked_records: number;
    reason: string | null;
  };
  discovery: {
    pages_scanned: number;
    scanned_targets: string[];
    candidate_targets: string[];
  };
  api_inventory: {
    documents_found: number;
    operations_total: number;
    read_operations: number;
    write_operations: number;
    safe_probe_operations: number;
    active_probes_run: number;
    inventory_truncated: boolean;
    operations: Array<{
      method: string;
      path: string;
      target: string;
      operation_id: string | null;
      requires_authentication: boolean;
      safe_to_probe: boolean;
    }>;
  };
  execution_available: boolean;
  findings: Array<{
    id: string;
    title: string;
    vulnerability_class: string;
    affected_target: string;
    status: string;
    severity: string;
    confidence: string;
    remediation: string;
    created_at: string;
  }>;
};
