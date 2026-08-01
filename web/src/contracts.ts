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
  report_url: string;
  markdown_report_url: string;
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
