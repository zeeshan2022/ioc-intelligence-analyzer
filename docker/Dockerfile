# IOC Intelligence Analyzer — hardened production image
# Build:  docker build -f docker/Dockerfile -t ioc-intelligence-analyzer:1.0.0 .
FROM python:3.12-slim AS base

# Supply-chain hygiene: pinned deps (requirements.txt), no apt recommends, cleanup cache
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (UID/GID 10001)
RUN groupadd --gid 10001 analyzer \
 && useradd  --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin analyzer

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    IOC_REPORT_DIR=/app/reports

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py pyproject.toml setup.cfg ./
COPY app ./app

# Reports volume (host-mountable output)
RUN mkdir -p /app/reports && chown -R analyzer:analyzer /app
VOLUME ["/app/reports"]

USER analyzer:analyzer

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import sys; sys.exit(0 if __import__('subprocess').run([sys.executable,'main.py','--validate','8.8.8.8'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0 else 1)"]

ENTRYPOINT ["python", "main.py"]
CMD ["--demo"]
