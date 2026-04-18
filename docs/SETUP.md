# Setup Guide

This document walks through every supported way to run **Damn Vulnerable gRPC**.
Pick whichever path fits your environment.

---

## TL;DR

```bash
git clone https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC.git
cd Damn-Vulnerable-GRPC

# Docker (recommended)
make up

# …or native Python
make setup
make run
```

Server listens on **`localhost:50051`** (no TLS, intentional).

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Option A — Docker Compose](#option-a--docker-compose-recommended)
3. [Option B — Local Python](#option-b--local-python)
4. [Option C — GitHub Codespaces / VS Code Dev Containers](#option-c--github-codespaces--vs-code-dev-containers)
5. [Environment Variables](#environment-variables)
6. [Proto compilation](#proto-compilation)
7. [Installing grpcurl](#installing-grpcurl)
8. [Uninstall / Cleanup](#uninstall--cleanup)

---

## Prerequisites

| Platform           | Requirements                                                                |
|--------------------|-----------------------------------------------------------------------------|
| **Docker path**    | Docker Desktop ≥ 4.27 (or Docker Engine ≥ 24 + Compose V2)                  |
| **Local path**     | Python **3.10+** with `pip`, GNU `make`                                     |
| **Windows users**  | Docker Desktop **or** WSL 2 (Ubuntu 22.04 image recommended)                |
| **All paths**      | `grpcurl` (see [below](#installing-grpcurl)) — optional but very handy      |

> ⚠️  **Do not run DVGRPC on a shared or public host.** It is intentionally
> vulnerable, including remote command execution.

---

## Option A — Docker Compose (recommended)

```bash
make up            # build image + start container
make logs          # tail server logs
make enumerate     # grpcurl list (smoke test)
make down          # stop and remove container
```

The server listens on `localhost:50051`. Data, SQLite db, and RSA keys
persist in named volumes (`dvgrpc_data`, `dvgrpc_keys`). Reset everything
with:

```bash
make down
docker volume rm dvgrpc_data dvgrpc_keys
```

### Port conflicts

If port `50051` is already taken, change it via `.env`:

```bash
cp .env.example .env
echo "DVGRPC_PORT=50151" >> .env
make up
```

---

## Option B — Local Python

```bash
make setup          # creates .venv, installs runtime + dev deps
source .venv/bin/activate
make run            # starts the server on localhost:50051
```

Runtime data goes to `./.dvgrpc/` (db, keys, uploads, secret). This keeps
your system clean and makes `make clean` idempotent.

Reset the database without touching your keys/uploads:

```bash
make reset-db
```

### Manual steps (if you don't want make)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
DVGRPC_ROOT=./.dvgrpc python -m server.main
```

---

## Option C — GitHub Codespaces / VS Code Dev Containers

1. Click **Code → Create codespace on `main`** on GitHub, **or**
2. Open the repo in VS Code with the *Dev Containers* extension and pick
   **"Reopen in Container"**.

The container image:

- Installs Python 3.11 with all runtime + dev deps
- Installs `grpcurl` via Go
- Pre-compiles proto stubs
- Forwards port `50051` to your browser

```bash
make run          # inside the codespace terminal
```

---

## Environment Variables

| Variable                     | Default                     | Purpose                                          |
|------------------------------|-----------------------------|--------------------------------------------------|
| `DVGRPC_PORT`                | `50051`                     | host port docker-compose binds to                |
| `DVGRPC_HOST`                | `localhost`                 | hostname clients connect to                      |
| `DVGRPC_HOST_PORT`           | `localhost:50051`           | shortcut for exploit scripts                     |
| `DVGRPC_ROOT`                | `/app` (docker) / `./.dvgrpc` | runtime data root                              |
| `DB_PATH`                    | `$DVGRPC_ROOT/data/dvgrpc.db` | sqlite db path                                 |
| `DVGRPC_LOG_LEVEL`           | `INFO`                      | `DEBUG \| INFO \| WARNING \| ERROR`              |
| `DVGRPC_JWT_SECRET`          | `supersecretkey123`         | HS256 signing key (intentionally weak)           |
| `DVGRPC_ADMIN_USER`          | `admin`                     | seeded admin username                            |
| `DVGRPC_ADMIN_PASS`          | `admin123`                  | seeded admin password                            |
| `DVGRPC_MAX_STREAM_MESSAGES` | `100000`                    | cap for streaming-DoS challenge                  |
| `DVGRPC_PROGRESS_FILE`       | `~/.dvgrpc-progress.json`   | scoreboard persistence location                  |

`.env.example` has a copy-ready template — `cp .env.example .env` and edit.

---

## Proto compilation

`make run` compiles `.proto` files on startup. To do it manually:

```bash
make proto
# → stubs written to ./generated/*_pb2*.py
```

These files are **not** checked into git (see `.gitignore`). If your IDE
complains about missing imports, run `make proto` once and point the
interpreter at `.venv/bin/python`.

---

## Installing grpcurl

`grpcurl` is the Swiss-army knife for gRPC. Every challenge README assumes
it is on your PATH.

| Platform           | Command                                                                |
|--------------------|------------------------------------------------------------------------|
| macOS (Homebrew)   | `brew install grpcurl`                                                 |
| Linux (apt)        | `sudo apt-get install -y grpcurl` (Debian 12+, Ubuntu 24.04+)          |
| Any w/ Go          | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`        |
| Windows (Scoop)    | `scoop install grpcurl`                                                |
| Release binaries   | <https://github.com/fullstorydev/grpcurl/releases>                     |

Smoke test:

```bash
grpcurl -plaintext localhost:50051 list
```

Want a GUI?  `go install github.com/fullstorydev/grpcui/cmd/grpcui@latest`
then `grpcui -plaintext localhost:50051`.

---

## Uninstall / Cleanup

```bash
make down                       # stop container
docker volume rm dvgrpc_data dvgrpc_keys   # remove persisted data
make clean-all                  # wipe .venv, .dvgrpc/, caches
```
