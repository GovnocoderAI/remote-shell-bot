FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    RSB_DATA_DIR=/data

WORKDIR /app

RUN groupadd --system --gid 10001 rsb \
    && useradd --uid 10001 --gid rsb --home-dir /app --shell /usr/sbin/nologin rsb \
    && mkdir -p /data \
    && chown -R rsb:rsb /app /data

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

USER rsb

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz')"]

CMD ["rsb", "server"]
