# Finding validation model

[繁體中文](FINDING_VALIDATION.zh-TW.md) | **English**

ProofClaw must be able to answer two different questions for every finding:

1. **Is the evidence intact and attributable within this engagement?** The stored bytes, canonical
   metadata, order, and hash-chain links can be checked for changes. The evidence must
   also come from an Action in the same engagement.
2. **Does that evidence establish this exact security claim?** A valid hash proves
   neither the target's intended policy nor exploitability. The claim needs an explicit
   verification method, an expected result, an observed result, and enough context to
   rule out ordinary alternative explanations.

The offline disclosure-bundle verifier checks package and evidence-chain integrity.
It does **not** independently replay a request, validate authorization assumptions,
prove a vulnerability, or identify the bundle's author.

## Current boundaries

- Deterministic passive HTTP checks can emit `verified` findings for directly
  observed header or transport properties of one captured response. These findings
  establish the observed property, not a successful exploit.
- An OpenAPI declaration paired with an unauthenticated successful response produces a
  `candidate`: the API specification alone cannot establish that the returned content
  was meant to be private.
- The `nuclei` parser emits `pending_verification` findings and the `httpx` parser
  emits `candidate` findings for selected target-derived observations; other scanner
  records are suppressed. Their output needs independent review before a verified
  claim. Template severity, a CVE label, or an LLM assertion is not evidence of impact.
- The autonomous mission path turns scanner observations into Candidates and Leads.
  `VerificationOutcome` computes a verdict from structured answers, and deterministic
  authorization oracles can compare identity probes. An outcome without a stated
  method cannot automatically become `verified`. The repository checks evidence
  provenance and integrity when a verified Finding is saved, but the outcome's probe
  fields are not independently derived from stored captures or checked against Action
  authorization and the expected security policy. Treat this path as an investigation
  aid until that semantic binding is implemented.
- `POST /api/v1/automation/verify` computes `pass`, `candidate`, or `inconclusive`
  from caller-supplied observations. Its output is not a persisted Finding decision or
  a substitute for evidence-backed review. The Planner/Operator/Verifier next-step
  endpoint selects a role; it does not perform a target retest.
- The Finding review API handles a human decision with optimistic version checking
  and an audit event. Every repository write of a `verified` Finding checks the full
  engagement evidence chain and linked evidence ownership and existence; a review
  transition also requires a stated verification method and explicit reviewer
  rationale. It does not yet check Action success, semantic target match, or whether
  the response proves the claim. A differential review rejects byte-identical test
  and control captures, but does not yet evaluate whether the changed bytes establish
  the claim. See
  [Finding review](FINDING_REVIEW.md).

## Required claim and proof

The unit of validation is a **specific claim about a specific target and condition**.
For example, "this response lacks `HttpOnly` on cookie X" can be established from one
capture. "User A can read User B's private record" requires the two identities, a
record known to belong to B, comparable requests, and a response showing B's data.
The status code alone is insufficient.

Each validation case should record:

- the affected target and exact claim, plus the expected security boundary;
- the finding and engagement IDs, rule/verifier version, Action IDs, approval and
  parameter digests, and linked evidence IDs with their distinct roles;
- the principal or anonymous context used in each capture, without exporting secrets;
- the minimal safe reproduction steps, decisive observed fields, and any limits;
- the verdict (`verified`, `rejected`, or `needs_manual_review`/`inconclusive`), reason,
  reviewer/verifier identity, time, and any repeat attempts.

`observed` means one target-derived artifact directly demonstrates the narrowly
worded claim against a fixed expectation. It must not turn a banner, fingerprint,
scanner match, or reachable endpoint into an unsupported CVE or access-control claim.

`differential` means a controlled comparison establishes the claim. It needs both
payload/test evidence and **separate control evidence**. The baseline shows normal
behavior; a negative control removes the condition alleged to cause the result. Keep
the target, relevant inputs, timing, and identity context comparable. If these cannot
be captured safely, the result remains inconclusive or needs manual review.

## Promotion criteria

A candidate may become `verified` only when all applicable checks pass:

1. The claim is precise, and the linked evidence is available, integrity-valid,
   attributable to this engagement and the intended Action/target, and captured under
   the applicable scope and approval policy.
2. The verification method matches the claim. A differential claim has an independent
   control; the same evidence record cannot serve as both test and control.
3. The decisive content supports the claim, rather than merely a tool's conclusion,
   rule metadata, HTTP status, or a generic error. The expected behavior and observed
   deviation are recorded.
4. A safe, bounded repeat or independent check supports findings that depend on timing,
   identity, state, or interactions. If repeatability is impossible, record why and
   require a human decision rather than silently claiming certainty.
5. Plausible alternatives are addressed: public data, caching, redirects, error pages,
   user-controlled reflection, authorization policy, middleware effects, and target
   state changes as relevant to the claim.

Missing, conflicting, cross-engagement, failed-action, or integrity-invalid evidence
must block promotion. A failed retest or contradictory control is not silently
discarded. `rejected` means the available evidence refutes or fails to support the
claim after review; `needs_manual_review` means the answer is unresolved.

## Safe validation path

Validation is a new target-facing action when it sends a request. It must pass the
same scope, DNS pinning, time window, risk classification, approval, Worker isolation,
request count, and response-size limits as discovery. A review click never authorizes
or performs such an action. Prefer read-only checks and inert markers. Tests that can
alter data, invoke callbacks, use another account, or affect availability require an
explicitly reviewed plan and the corresponding policy decision. Stop on unexpected
side effects, scope drift, inconsistent identity, or exhausted budgets.

## Implementation sequence

1. **Evidence-bound decisions (first gate implemented):** verified repository writes
   and report generation fail closed on missing, corrupt, or foreign-engagement linked
   evidence; review records the decision. SARIF contains only verified findings.
   Next, bind each evidence record to a successful Action and the precise target.
2. **Verification cases:** persist structured claim, method, expected/observed
   assertions, evidence roles, verifier version, attempts, and an immutable verdict.
   Build observations from stored captures, not client-supplied response summaries.
3. **Bounded retest runners:** add approved, scoped recipes per vulnerability class;
   capture test, baseline, and negative-control exchanges as separate evidence.
   Keep the Verifier independent of the discovery text and make uncertain outcomes
   explicit.
4. **Disclosure quality:** expose verdict basis, control references, reproduction
   instructions, and limitations consistently in JSON, Markdown, HTML, SARIF, and
   bundles. Distinguish candidates from verified findings in counts and presentation.
   Give future stored exports a versioned per-finding proof manifest; historical
   Markdown exports currently revalidate verified claims by exact table row because
   that format does not carry a stable finding ID.

Acceptance tests should cover forged observation input, missing or altered evidence,
cross-engagement links, wrong Action/target, missing controls, failed execution,
conflicting responses, safe repeat success, timeout/inconclusive outcomes, and reports
that retain the same verdict and proof references in every format.
