FROM python:3.11-slim

LABEL maintainer="jaiswalakshansh"
LABEL description="Damn Vulnerable gRPC — intentionally insecure gRPC server for CTF training"

# Install system utilities used by command injection challenges
RUN apt-get update && apt-get install -y \
    iputils-ping \
    dnsutils \
    traceroute \
    whois \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY proto/   ./proto/
COPY server/  ./server/

# Create runtime directories
RUN mkdir -p /app/data /app/keys /app/uploads /app/secret /app/generated

# Expose gRPC port
EXPOSE 50051

# Start server (proto generation happens at startup)
CMD ["python", "-m", "server.main"]
