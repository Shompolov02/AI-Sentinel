FROM python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56 AS builder

WORKDIR /src
COPY packages/smoke/src/ai_sentinel_smoke /src/ai_sentinel_smoke
RUN python -m compileall -q --invalidation-mode checked-hash /src/ai_sentinel_smoke \
    && mkdir -p /opt/smoke \
    && cp -a /src/ai_sentinel_smoke /opt/smoke/

FROM python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56 AS runtime

LABEL org.opencontainers.image.title="AI-Sentinel smoke" \
      org.opencontainers.image.description="Non-privileged container baseline for AI-Sentinel"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/smoke

COPY --from=builder --chown=10001:10001 /opt/smoke /opt/smoke

RUN rm -rf /usr/local/lib/python3.11/site-packages/setuptools \
    /usr/local/lib/python3.11/site-packages/setuptools-*.dist-info \
    /usr/local/lib/python3.11/site-packages/wheel \
    /usr/local/lib/python3.11/site-packages/wheel-*.dist-info

USER 10001:10001
WORKDIR /opt/smoke

HEALTHCHECK --interval=30s --timeout=3s --start-period=2s --retries=3 \
    CMD ["python", "-c", "from ai_sentinel_smoke import smoke_status; raise SystemExit(0 if smoke_status()[\"status\"] == \"ok\" else 1)"]

ENTRYPOINT ["python", "-m", "ai_sentinel_smoke"]