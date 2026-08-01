import { describe, expect, it } from "vitest";

import { viewFromHash } from "./navigation";

describe("viewFromHash", () => {
  it("restores a supported deep-linked view", () => {
    expect(viewFromHash("#assessments")).toBe("assessments");
  });

  it.each(["", "#unknown", "assessments"])("fails closed to overview for %s", (hash) => {
    expect(viewFromHash(hash)).toBe("overview");
  });
});
