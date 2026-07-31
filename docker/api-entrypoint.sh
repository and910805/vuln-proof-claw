#!/bin/sh
set -eu

python -m alembic -c /app/alembic.ini upgrade head
exec python -m uvicorn vuln_proof_claw.api.app:create_app \
    --factory \
    --host 0.0.0.0 \
    --port 8080 \
    --no-access-log
