FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./
COPY scripts/ scripts/

# Copy SQLite database (for standalone mode)
COPY cve_database.db ./

# Environment defaults
ENV DB_TYPE=sqlite
ENV SQLITE_PATH=/app/cve_database.db

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "app:app"]
