# Web Console

[繁體中文](WEB_UI.zh-TW.md) | **English**

The bundled Web console is the first interactive control surface for ProofClaw. It is a React and TypeScript single-page application served by the FastAPI process, so the default Docker Compose deployment exposes one local endpoint and does not require a separate Web server.

## Current scope

The Web foundation currently provides:

- English and Traditional Chinese interfaces.
- Live API and database readiness state.
- Persisted control-plane counts.
- Project listing and project creation.
- A deep-linkable authorized URL assessment workspace.
- Automatic creation of a narrow 24-hour L0 Engagement from the confirmed target.
- Safe/Fast/Deep same-origin discovery, page/Evidence/Finding counts, prioritized
  remediation, and JSON/Markdown/HTML reporting.
- Persistent newest-first assessment history with project filtering, failure status, and repeat report downloads after refresh.
- Optional operator Bearer-token input for authenticated deployments.
- The enforced L0-L4 risk-policy reference.
- Explicit status for capabilities that are operational or still locked.

The browser can start only bounded, credential-free, GET-only discovery. It does not
authenticate to targets, submit forms, run external tools or payloads, approve risky
actions, render raw Evidence, or independently verify Findings.

## Open the console

Start the stack:

```bash
docker compose up --build -d
```

Open <http://127.0.0.1:8080/>. API documentation remains available at <http://127.0.0.1:8080/docs>.

## Frontend development

Requirements: Node.js 22 or newer and npm.

```bash
cd web
npm ci
npm test
npm run typecheck
npm run build
```

The production build is written to `src/vuln_proof_claw/web` and packaged with the Python application. For development with Vite hot reload, start the FastAPI service on port 8080 and run:

```bash
cd web
npm run dev
```

Vite listens only on `127.0.0.1:5173` and proxies `/api` to `127.0.0.1:8080`.

## Security posture

- The UI uses same-origin API requests and no external CDN resources.
- The Compose API remains bound to `127.0.0.1` by default.
- The optional operator token is kept in tab-scoped `sessionStorage`, never placed in
  a URL, and can be explicitly cleared. Production deployments still need a hardened
  session strategy before general multi-user use.
- Query strings and fragments are removed from a submitted target; embedded
  credentials, IP literals, and non-HTTP(S) schemes are rejected; and the user must
  explicitly confirm authorization. Private and IP-literal targets require a
  separately reviewed API-created Scope.
- The generated Engagement allows only the target hostname, scheme,
  port, and path, expires after 24 hours, uses maximum risk L0, and keeps destructive
  actions disabled.
- UI visibility is not an authorization boundary. Policy, scope, approval, and execution checks remain server-side.
- Target traffic remains disabled until the server-side assessment setting is enabled.

## API contracts

The foundation UI consumes:

- `GET /api/v1/health/ready`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/projects`
- `POST /api/v1/projects`
- `POST /api/v1/projects/{project_id}/engagements`
- `POST /api/v1/engagements/{engagement_id}/assessments`
- `GET /api/v1/assessments?project_id={project_id}&limit=50&offset=0`
- `GET /api/v1/engagements/{engagement_id}/report`
- `GET /api/v1/engagements/{engagement_id}/report.md`
