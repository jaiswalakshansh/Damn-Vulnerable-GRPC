FROM python:3.11-slim

LABEL org.opencontainers.image.title="Damn Vulnerable gRPC"
LABEL org.opencontainers.image.description="Intentionally insecure gRPC server for CTF training and security research"
LABEL org.opencontainers.image.source="https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC"
LABEL org.opencontainers.image.licenses="MIT"

# Install system utilities used by the command-injection challenge and healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    dnsutils \
    traceroute \
    whois \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY proto/   ./proto/
COPY server/  ./server/

# Create runtime directories
RUN mkdir -p /app/data /app/keys /app/uploads /app/secret /app/generated

# Drop to an unprivileged user — the app itself is vulnerable, but running as
# root makes the command-injection challenge dangerously powerful.
RUN groupadd -r dvgrpc && useradd -r -g dvgrpc -d /app -s /sbin/nologin dvgrpc \
    && chown -R dvgrpc:dvgrpc /app
USER dvgrpc

ENV DVGRPC_ROOT=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 50051

# Lightweight healthcheck — try a reflection list via grpcurl-less Python call
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import grpc; grpc.channel_ready_future(grpc.insecure_channel('localhost:50051')).result(timeout=3)" \
    || exit 1

# Start server (proto generation happens at startup)
CMD ["python", "-m", "server.main"]
