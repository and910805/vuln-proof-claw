FROM python:3.14-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
# Patch build backend tooling so the copied venv carries fixed pip/setuptools/wheel.
RUN python -m pip install --upgrade pip setuptools wheel

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install ".[browser]"

FROM python:3.14-slim AS runtime

ARG VCS_REF="unknown"
LABEL org.opencontainers.image.revision="${VCS_REF}"

ENV PATH="/opt/venv/bin:${PATH}" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10002 worker \
    && useradd --uid 10002 --gid worker --no-create-home --home-dir /nonexistent worker \
    && mkdir /work \
    && chown 10002:10002 /work

WORKDIR /work
COPY --from=builder /opt/venv /opt/venv

RUN mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}" \
    && python -m playwright install --with-deps chromium \
    && apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX "${PLAYWRIGHT_BROWSERS_PATH}"

USER 10002:10002
ENTRYPOINT ["python", "-m", "vuln_proof_claw.execution.worker"]
