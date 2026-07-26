FROM python:3.14-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY cspm ./cspm
RUN pip install --no-cache-dir .

COPY web ./web
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

# Run as a non-root user.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# Default: API server. The worker overrides the command in compose.
CMD ["uvicorn", "cspm.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
