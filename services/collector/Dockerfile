FROM fluent/fluent-bit:5.1.3-debug@sha256:5c7b210ba86ab7625a32128dbc5b2fca78a4ea636762b2e6278f04766d0d4544 AS fluent
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update \
    && apt-get install --yes --no-install-recommends libyaml-0-2 libsystemd0 libcurl4t64 libsasl2-2 libpq5 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=fluent /fluent-bit/bin/fluent-bit /fluent-bit/bin/fluent-bit
COPY services/core/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt \
    && pip uninstall --yes setuptools wheel \
    && addgroup --system --gid 10001 collector \
    && adduser --system --uid 10001 --ingroup collector --no-create-home collector \
    && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data
COPY --chown=10001:10001 services/core/ai_sentinel_core ./ai_sentinel_core
COPY services/collector/fluent-bit.conf /etc/collector/fluent-bit.conf
USER 10001:10001
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import time; from pathlib import Path; from urllib.request import urlopen; assert time.time()-float(Path('/data/heartbeat').read_text())<30; urlopen('http://127.0.0.1:8090/health',timeout=3)"]
CMD ["python", "-m", "ai_sentinel_core.collector"]
