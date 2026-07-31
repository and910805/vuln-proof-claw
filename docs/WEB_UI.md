# Web Console

[繁體中文](WEB_UI.zh-TW.md) | **English**

The bundled Web console is the first interactive control surface for ProofClaw. It is a React and TypeScript single-page application served by the FastAPI process, so the default Docker Compose deployment exposes one local endpoint and does not require a separate Web server.

## Current scope

The Web foundation currently provides:

- English and Traditional Chinese interfaces.
- Live API and database readiness state.
- Persisted control-plane counts.
- Project listing and project creation.
- The enforced L0-L4 risk-policy reference.
- Explicit status for capabilities that are operational or still locked.

It does not yet start flows, execute target-facing tools, approve actions, render raw evidence, or verify findings. Those controls stay visibly unavailable until their backing API, authorization, and execution-boundary enforcement are implemented.

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
- Project creation is intended for local pre-alpha use; production deployment requires authentication readiness.
- UI visibility is not an authorization boundary. Policy, scope, approval, and execution checks remain server-side.
- Unimplemented actions are not simulated and cannot be enabled from the browser.

## API contracts

The foundation UI consumes:

- `GET /api/v1/health/ready`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/projects`
- `POST /api/v1/projects`
