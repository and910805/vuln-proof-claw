# Disposable browser worker image. Built on Python 3.12 (the platform floor)
# with Playwright and a pinned Chromium installed into a shared, world-readable
# browser path so the non-root worker can launch it. System libraries are
# installed explicitly (rather than `playwright install --with-deps`, whose
# package list targets Ubuntu) to stay valid on Debian bookworm.
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

WORKDIR /work
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates fonts-liberation \
        libasound2 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 libcairo2 \
        libcups2 libdbus-1-3 libdrm2 libgbm1 libnspr4 libnss3 libpango-1.0-0 \
        libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
        libxkbcommon0 libxrandr2 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install . "playwright==1.47.0" \
    && python -m playwright install chromium \
    && useradd --uid 10003 --no-create-home --home-dir /nonexistent worker

USER 10003:10003
ENTRYPOINT ["python", "-m", "vuln_proof_claw.execution.browser_worker"]
