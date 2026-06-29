# ════════════════════════════════════════════════════════════════════════════
# SecureScope — Dockerfile
# Multi-stage build: keeps the final image lean by separating build-time
# tooling from the runtime layer.
#
# Build:
#   docker build -t securescope .
#
# Run (web UI on http://localhost:5001):
#   docker run -p 5001:5001 \
#     -e ANTHROPIC_API_KEY=sk-ant-... \
#     ghcr.io/omarrao/secure-scope:latest
#
# Optional env vars:
#   OPENAI_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, GITHUB_TOKEN
# ════════════════════════════════════════════════════════════════════════════


# ── Stage 1: Builder ─────────────────────────────────────────────────────────
# Installs all Python dependencies into a virtual-env so only the venv
# directory needs to be copied into the final stage — no build tools carried
# over.
FROM python:3.11-slim AS builder

# Install OS packages needed to compile certain Python wheels (e.g. cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# Create an isolated virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only the requirements file first — this layer is cached unless
# requirements.txt changes, keeping rebuilds fast.
COPY requirements.txt /tmp/requirements.txt

# Install core dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Install the web-server extras that are imported at runtime but not listed
# in requirements.txt (they are optional/UI-only deps)
RUN pip install --no-cache-dir \
        flask \
        flask-socketio \
        python-socketio \
        python-engineio \
        simple-websocket \
        requests \
        jinja2 \
        playwright

# Install Playwright browser binaries used to render the PDF report.
# Install into a shared, world-readable path (NOT /root/.cache) so the non-root
# runtime user can read them. Chromium only — minimises image size.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install chromium && \
    playwright install-deps chromium


# ── Stage 2: Final runtime image ─────────────────────────────────────────────
# Slim base — no build tools, no compiler.
FROM python:3.11-slim AS runtime

# ── Labels (OCI image spec) ───────────────────────────────────────────────────
LABEL org.opencontainers.image.title="SecureScope"
LABEL org.opencontainers.image.description="AI-powered security analysis for any GitHub repository. MITRE ATT&CK mapping, ransomware detection, YARA scanning, and multi-LLM fix advisor."
LABEL org.opencontainers.image.url="https://github.com/OmarRao/secure-scope"
LABEL org.opencontainers.image.source="https://github.com/OmarRao/secure-scope"
LABEL org.opencontainers.image.licenses="LicenseRef-Proprietary-AllRightsReserved"
LABEL org.opencontainers.image.vendor="Omar Rao"
LABEL org.opencontainers.image.authors="Omar Rao — Cybersecurity, Privacy and Resilience Expert <https://www.linkedin.com/in/omarrao/>"

# Install only the OS runtime libraries needed (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Required by Playwright/Chromium
        libnss3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libasound2 \
        libpango-1.0-0 \
        libcairo2 \
        # Required for git clone (analyzer.py clones target repos)
        git \
        # Required by pip-audit for subprocess calls
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy Playwright browser binaries from builder into a shared, world-readable
# location and point Playwright at it (used by the non-root runtime user).
COPY --from=builder /ms-playwright /ms-playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN chmod -R a+rX /ms-playwright

# Activate the virtual environment for all subsequent commands
ENV PATH="/opt/venv/bin:$PATH"

# ── Application setup ─────────────────────────────────────────────────────────

# Create a non-root user to run the application — reduces blast radius if
# the container is compromised while scanning a malicious repository.
RUN groupadd --gid 1001 securescope && \
    useradd  --uid 1001 --gid securescope --shell /bin/bash --create-home securescope

# Set the working directory
WORKDIR /app

# Copy application source code.
# Ordered from least-to-most frequently changed to maximise layer cache hits.
COPY yara_rules/          ./yara_rules/
COPY ui/                  ./ui/
COPY requirements.txt     .
# Copy every root-level Python module. Using a glob (rather than an explicit
# per-file list) ensures new modules — pdf_report, secret/dependency/iac
# scanners, gist_storage, autofix, etc. — are always included in the image.
# .dockerignore already excludes dev-only generators and scan output.
COPY *.py                 .

# Create the reports directory that the server writes scan results to.
# Owned by the non-root user so the server can write without sudo.
RUN mkdir -p /app/reports && chown -R securescope:securescope /app

# Switch to the non-root user for all runtime commands
USER securescope

# ── Runtime configuration ─────────────────────────────────────────────────────

# Port the Flask + Socket.IO server listens on
EXPOSE 5001

# LLM API keys — passed at runtime via -e flags, never baked into the image.
# Empty defaults are intentional: the container starts without keys; the user
# supplies real values at `docker run -e ANTHROPIC_API_KEY=sk-ant-...`.
# hadolint ignore=DL3044
ENV ANTHROPIC_API_KEY="" \
    OPENAI_API_KEY="" \
    GEMINI_API_KEY="" \
    GROQ_API_KEY="" \
    GITHUB_TOKEN=""

# Flask configuration
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health-check — hits the root route every 30 seconds.
# Gives Docker / Kubernetes 10 seconds to start before the first check.
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fs http://localhost:5001/ || exit 1

# Default command — start the web UI server
CMD ["python", "-m", "ui.server"]
