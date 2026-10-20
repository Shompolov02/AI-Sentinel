FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/core/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt \
    && pip uninstall --yes setuptools wheel \
    && addgroup --system --gid 10001 core \
    && adduser --system --uid 10001 --ingroup core --no-create-home core \
    && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data
COPY --chown=10001:10001 services/core/ai_sentinel_core ./ai_sentinel_core
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health',timeout=3)"]
CMD ["uvicorn", "ai_sentinel_core.__main__:application", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
