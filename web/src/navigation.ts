export const views = [
  "overview",
  "projects",
  "assessments",
  "approvals",
  "evidence",
  "findings",
  "policy",
] as const;

export type View = (typeof views)[number];

export function viewFromHash(hash: string): View {
  if (hash && !hash.startsWith("#")) return "overview";
  const candidate = hash.replace(/^#/, "");
  return views.find((view) => view === candidate) ?? "overview";
}
