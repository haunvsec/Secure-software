FROM python:3.11-slim

WORKDIR /app

# Install git for sync jobs
RUN apt-get update && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./
COPY scripts/ scripts/

# Ensure entrypoint is executable
RUN chmod +x scripts/entrypoint.sh

# Environment defaults
ENV DATABASE_URL=mysql+pymysql://cvedb:cvedb@db:3306/cve_database?charset=utf8mb4
ENV CVE_REPO_PATH=/app/data/cvelistV5
ENV ADVISORY_REPO_PATH=/app/data/security-advisory-db
ENV SYNC_INTERVAL_HOURS=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

CMD ["bash", "scripts/entrypoint.sh"]
