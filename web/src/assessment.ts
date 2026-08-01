export type PreparedAssessment = {
  displayTarget: string;
  engagementName: string;
  engagementPayload: {
    name: string;
    starts_at: string;
    ends_at: string;
    maximum_risk: "L0";
    destructive_actions_enabled: false;
    scope: {
      allowed_hostnames: string[];
      allowed_cidrs: string[];
      allowed_ports: number[];
      allowed_schemes: Array<"http" | "https">;
      allowed_paths: string[];
    };
  };
};

const DEFAULT_PORTS = { http: 80, https: 443 } as const;

export function prepareAssessment(rawTarget: string, now = new Date()): PreparedAssessment {
  let target: URL;
  try {
    target = new URL(rawTarget.trim());
  } catch {
    throw new Error("invalid_url");
  }
  const scheme = target.protocol.slice(0, -1);
  if (scheme !== "http" && scheme !== "https") throw new Error("unsupported_scheme");
  if (target.username || target.password) throw new Error("embedded_credentials");

  const hostname = target.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const port = target.port ? Number(target.port) : DEFAULT_PORTS[scheme];
  const path = target.pathname || "/";
  const isIpLiteral = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
  if (isIpLiteral) throw new Error("ip_literal_requires_manual_scope");
  const displayTarget = `${scheme}://${hostname}:${port}${path}`;
  const startsAt = new Date(now.getTime() - 60_000);
  const endsAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  return {
    displayTarget,
    engagementName: `Passive assessment: ${hostname}`,
    engagementPayload: {
      name: `Passive assessment: ${hostname}`,
      starts_at: startsAt.toISOString(),
      ends_at: endsAt.toISOString(),
      maximum_risk: "L0",
      destructive_actions_enabled: false,
      scope: {
        allowed_hostnames: [hostname],
        allowed_cidrs: [],
        allowed_ports: [port],
        allowed_schemes: [scheme],
        allowed_paths: [path],
      },
    },
  };
}

export function assessmentIdempotencyKey(): string {
  return `console-${crypto.randomUUID()}`;
}

export function assessmentHistoryPath(projectId: string): string {
  const parameters = new URLSearchParams({ limit: "50" });
  if (projectId) parameters.set("project_id", projectId);
  return `/api/v1/assessments?${parameters.toString()}`;
}
