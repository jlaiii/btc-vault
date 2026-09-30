FROM python:3.12-slim

# curl = container healthcheck; postgresql-client = pg_isready wait-loop
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user with a FIXED uid/gid (1500). The master key is mounted
# in with 0600 ownership matching this uid, so the container can read the key
# while host users cannot — a random uid would make that impossible.
RUN groupadd -g 1500 -r btcwallet && useradd -u 1500 -g 1500 -r -m -s /bin/bash btcwallet

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=btcwallet:btcwallet app ./app
COPY --chown=btcwallet:btcwallet scripts ./scripts

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

USER btcwallet
EXPOSE 8810

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -fs http://localhost:8810/health || exit 1

# -w 1: the wallet's own auth throttling is DB-backed (exact across workers);
# a single threaded worker keeps the in-process limiter coherent and the
# container small on a 2-core box.
CMD ["gunicorn", "-w", "1", "-k", "gthread", "--threads", "8", \
     "-b", "0.0.0.0:8810", "--forwarded-allow-ips=*", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "--timeout", "90", "app:create_app()"]
