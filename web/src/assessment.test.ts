import { describe, expect, it, vi } from "vitest";

import {
  assessmentHistoryPath,
  assessmentIdempotencyKey,
  prepareAssessment,
  resolveAssessmentProjectId,
} from "./assessment";

describe("prepareAssessment", () => {
  it("builds a narrow hostname scope and removes query and fragment data", () => {
    const prepared = prepareAssessment(
      " HTTPS://Example.COM/account?token=secret#section ",
      new Date("2026-08-01T00:00:00Z"),
    );

    expect(prepared.displayTarget).toBe("https://example.com:443/account");
    expect(prepared.engagementPayload.scope).toEqual({
      allowed_hostnames: ["example.com"],
      allowed_cidrs: [],
      allowed_ports: [443],
      allowed_schemes: ["https"],
      allowed_paths: ["/account"],
    });
    expect(prepared.engagementPayload.maximum_risk).toBe("L0");
    expect(prepared.engagementPayload.destructive_actions_enabled).toBe(false);
    expect(prepared.engagementPayload.starts_at).toBe("2026-07-31T23:59:00.000Z");
    expect(prepared.engagementPayload.ends_at).toBe("2026-08-02T00:00:00.000Z");
  });

  it.each([
    ["not a URL", "invalid_url"],
    ["ftp://example.com/file", "unsupported_scheme"],
    ["https://user:password@example.com/", "embedded_credentials"],
    ["http://127.0.0.1:8080/", "ip_literal_requires_manual_scope"],
    ["http://2130706433/", "ip_literal_requires_manual_scope"],
    ["https://[::1]/", "ip_literal_requires_manual_scope"],
  ])("rejects unsafe target %s", (target, error) => {
    expect(() => prepareAssessment(target)).toThrow(error);
  });
});

it("creates a unique console idempotency key without target content", () => {
  vi.stubGlobal("crypto", { randomUUID: () => "00000000-0000-4000-8000-000000000001" });
  const key = assessmentIdempotencyKey();
  expect(key).toBe("console-00000000-0000-4000-8000-000000000001");
  vi.unstubAllGlobals();
});

it("builds bounded and encoded assessment history URLs", () => {
  expect(assessmentHistoryPath("")).toBe("/api/v1/assessments?limit=50");
  expect(assessmentHistoryPath("project id/one")).toBe(
    "/api/v1/assessments?limit=50&project_id=project+id%2Fone",
  );
});

describe("resolveAssessmentProjectId", () => {
  it("keeps an explicitly selected project", async () => {
    let created = false;
    const projectId = await resolveAssessmentProjectId("selected", [{ id: "first" }], async () => {
      created = true;
      return { id: "created" };
    });
    expect(projectId).toBe("selected");
    expect(created).toBe(false);
  });

  it("uses an existing project without extra setup", async () => {
    const projectId = await resolveAssessmentProjectId("", [{ id: "first" }], async () => ({
      id: "created",
    }));
    expect(projectId).toBe("first");
  });

  it("creates the first private workspace when none exists", async () => {
    const projectId = await resolveAssessmentProjectId("", [], async () => ({ id: "created" }));
    expect(projectId).toBe("created");
  });
});
