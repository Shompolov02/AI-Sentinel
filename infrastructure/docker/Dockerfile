FROM python:3.11.11-slim-bookworm@sha256:081075da77b2b55c23c088251026fb69a7b2bf92471e491ff5fd75c192fd38e5 AS builder

WORKDIR /src
COPY packages/smoke/src/ai_sentinel_smoke /src/ai_sentinel_smoke
RUN python -m compileall --quiet --invalidation-mode checked-hash /src/ai_sentinel_smoke \
    && mkdir -p /opt/smoke \
    && cp -a /src/ai_sentinel_smoke /opt/smoke/

FROM python:3.11.11-slim-bookworm@sha256:081075da77b2b55c23c088251026fb69a7b2bf92471e491ff5fd75c192fd38e5 AS runtime

LABEL org.opencontainers.image.title="AI-Sentinel smoke" \
      org.opencontainers.image.description="Non-privileged container baseline for AI-Sentinel"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/smoke

COPY --from=builder --chown=10001:10001 /opt/smoke /opt/smoke

USER 10001:10001
WORKDIR /opt/smoke

HEALTHCHECK --interval=30s --timeout=3s --start-period=2s --retries=3 \
    CMD ["python", "-c", "from ai_sentinel_smoke import smoke_status; raise SystemExit(0 if smoke_status()[\"status\"] == \"ok\" else 1)"]

ENTRYPOINT ["python", "-m", "ai_sentinel_smoke"]