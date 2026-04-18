# Damn Vulnerable gRPC (DVGRPC)

> A deliberately insecure gRPC application for learning and practicing
> gRPC security vulnerabilities. Built for security researchers, CTF
> players, and engineers who want to understand how gRPC apps get
> attacked — and how to defend them.

[![CI](https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC/actions/workflows/ci.yml/badge.svg)](https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC/actions/workflows/codeql.yml/badge.svg)](https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC/actions/workflows/codeql.yml)
![Python 3.10 | 3.11 | 3.12](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Challenges: 15](https://img.shields.io/badge/challenges-15-purple)

---

## ⚠️  Legal & Safety Disclaimer

**DVGRPC is intentionally vulnerable.** It contains remote command
execution, SQL injection, path traversal, and more. Run it **only** on
`localhost` or an isolated lab VM.  Do **not** expose port `50051` to
the public internet.

---

## Contents

1. [Challenges](#challenges)
2. [Quick start](#quick-start)
3. [Architecture](#architecture)
4. [Tools](#tools)
5. [Default credentials](#default-credentials)
6. [Scoreboard](#scoreboard)
7. [Docs index](#docs-index)
8. [Project layout](#project-layout)
9. [Contributing & security](#contributing--security)

---

## Challenges

| #   | Vulnerability                                                      | Category             | Difficulty |
|-----|--------------------------------------------------------------------|----------------------|------------|
| 01  | [Server Reflection](challenges/01-server-reflection/)              | Info Disclosure      | 🟢 Easy    |
| 02  | [Unauthenticated Admin](challenges/02-unauthenticated-admin/)      | Broken Access Control| 🟢 Easy    |
| 03  | [SQL Injection](challenges/03-sql-injection/)                      | Injection            | 🟡 Medium  |
| 04  | [JWT Algorithm Confusion](challenges/04-jwt-confusion/)            | Broken Auth          | 🔴 Hard    |
| 05  | [IDOR](challenges/05-idor/)                                        | Broken Access Control| 🟢 Easy    |
| 06  | [Path Traversal](challenges/06-path-traversal/)                    | Injection            | 🟡 Medium  |
| 07  | [Command Injection](challenges/07-command-injection/)              | Injection            | 🟡 Medium  |
| 08  | [Mass Assignment](challenges/08-mass-assignment/)                  | Misconfiguration     | 🟡 Medium  |
| 09  | [Metadata Bypass](challenges/09-metadata-bypass/)                  | Broken Auth          | 🟡 Medium  |
| 10  | [Hardcoded Credentials](challenges/10-hardcoded-credentials/)      | Misconfiguration     | 🟢 Easy    |
| 11  | [Timing Attack](challenges/11-timing-attack/) ✨                    | Info Disclosure      | 🔴 Hard    |
| 12  | [Streaming DoS](challenges/12-streaming-dos/) ✨                    | Availability         | 🟡 Medium  |
| 13  | [Integer Overflow / Unvalidated Pagination](challenges/13-integer-overflow/) ✨ | Injection / BAC | 🟡 Medium  |
| B1  | [Weak Crypto (ECB)](challenges/bonus-crypto/)                      | Crypto Failures      | 🔴 Hard    |
| B2  | [HMAC Forgery](challenges/bonus-crypto/)                           | Crypto Failures      | 🔴 Hard    |

> ✨  New in v1.1 — mirrors real-world CVEs (GitHub 2016 timing bug,
> CVE-2023-44487 HTTP/2 Rapid Reset).  See [ROADMAP.md](docs/ROADMAP.md)
> for what's next.

---

## Quick start

### Option A — Docker Compose (recommended)

```bash
git clone https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC.git
cd Damn-Vulnerable-GRPC

make up                     # build + run
make enumerate              # smoke test via grpcurl
make logs                   # tail server logs
```

### Option B — Local Python

```bash
make setup                  # .venv + runtime + dev deps
source .venv/bin/activate
make run                    # starts on localhost:50051
```

### Option C — One-click Codespaces

Open the repo on GitHub → **Code → Create codespace on main**. The
devcontainer installs everything and pre-compiles proto stubs.

Full walkthrough of all three paths: **[docs/SETUP.md](docs/SETUP.md)**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                gRPC Server (port 50051)                  │
│                     No TLS — Insecure                    │
├──────────────┬──────────────┬────────────────────────────┤
│  AuthService │  UserService │  AdminService              │
│ (VULN 4,8,10,│  (VULN 5)    │  (VULN 2)                  │
│  11-timing)  │              │                            │
├──────────────┼──────────────┼────────────────────────────┤
│ ProductSvc   │  FileService │  CommandService            │
│ (VULN 3,12)  │  (VULN 6)    │  (VULN 7)                  │
├──────────────┴──────────────┴────────────────────────────┤
│  CryptoService (BONUS 1, 2)                              │
├──────────────────────────────────────────────────────────┤
│  AuthInterceptor (VULN 9 — metadata bypass)              │
├──────────────────────────────────────────────────────────┤
│  SQLite Database (/app/data/dvgrpc.db)                   │
│  tables: users, products, notes, flags, secrets          │
└──────────────────────────────────────────────────────────┘
```

---

## Tools

Every challenge README assumes you have `grpcurl` and a recent Python on
your PATH. The `Makefile` wires everything together:

```bash
make help                      # list every target
make enumerate                 # grpcurl list against localhost:50051
make exploit N=01              # run client/exploits/exploit_01_*.py
make solve-all                 # run every exploit in sequence
make selfcheck                 # verify every challenge still works
make test                      # run the regression suite
make scoreboard                # interactive progress tracker
make reset-db                  # wipe and re-seed the local sqlite db
```

### Observability (opt-in)

DVGRPC ships with an optional Prometheus-compatible metrics sidecar — off
by default so the app mirrors a real "shipped without observability"
service.  Flip it on with one env var:

```bash
DVGRPC_METRICS_PORT=9090 make run
curl -s localhost:9090/metrics
```

Ready-made labels: `method`, `status`. Great for showing learners how an
attack looks from SRE-land.

Want a GUI?  [grpcui](https://github.com/fullstorydev/grpcui) works
out of the box:

```bash
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
grpcui -plaintext localhost:50051
```

---

## Default credentials

| Username  | Password        | Role       |
|-----------|-----------------|------------|
| `admin`   | `admin123`      | admin      |
| `alice`   | `alice123`      | user       |
| `bob`     | `b0bpassw0rd`   | user       |
| `charlie` | `charlie_pass`  | user       |
| `dave`    | `dave1234`      | moderator  |

Flag format: `FLAG{l33t_sp3ak_description}`.
List every flag you've got:

```bash
grpcurl -plaintext localhost:50051 dvgrpc.AdminService/ListAllFlags
```

(yes, that's itself Challenge 02).

---

## Scoreboard

Track your progress locally — no external service, no telemetry.

```bash
make scoreboard
# or:  python scripts/scoreboard.py
```

```
  ╔══════════════════════════════════════════════════════════════╗
  ║              DAMN VULNERABLE gRPC — SCOREBOARD               ║
  ╚══════════════════════════════════════════════════════════════╝

  Progress: ██████░░░░░░░░  5/14  (35%)

  #   D   Title                       Category              Status
  ------------------------------------------------------------------
  01  ●   Server Reflection           Info Disclosure       ✓ solved
  02  ●   Unauthenticated Admin       Access Control        ✓ solved
  03  ●   SQL Injection               Injection             · pending
  ...
```

Paste a captured flag at the prompt to record it. Resets with
`make scoreboard-- --reset` (or `python scripts/scoreboard.py --reset`).

---

## Docs index

| Doc                                              | Purpose                                    |
|--------------------------------------------------|--------------------------------------------|
| [docs/SETUP.md](docs/SETUP.md)                   | Full install guide (Docker / local / Codespaces) |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues + FAQ                        |
| [docs/SOLUTIONS.md](docs/SOLUTIONS.md)           | Complete walkthroughs (⚠️ spoilers)         |
| [docs/ROADMAP.md](docs/ROADMAP.md)               | Ideas for new challenges / infra           |
| [CONTRIBUTING.md](CONTRIBUTING.md)               | How to add a challenge                     |
| [SECURITY.md](SECURITY.md)                       | Responsible disclosure for framework bugs  |
| [challenges/README.md](challenges/README.md)     | Challenge index + difficulty map           |

---

## Project layout

```
Damn-Vulnerable-GRPC/
├── proto/                    # 7 .proto service definitions
├── server/
│   ├── main.py               # entry point + proto generation
│   ├── config.py             # env-configurable, intentionally weak defaults
│   ├── database.py           # SQLite schema + seed data
│   ├── interceptors/         # AuthInterceptor (VULN-9 lives here)
│   └── services/             # auth, user, admin, product, file, command, crypto
├── challenges/               # per-challenge READMEs (12 main + 2 bonus)
├── client/
│   ├── client.py             # generic login helper
│   └── exploits/             # one script per challenge
├── tests/                    # pytest regression suite (guards every flag)
├── scripts/
│   ├── scoreboard.py         # interactive progress tracker
│   ├── reset_db.py           # rebuild the sqlite db
│   └── healthcheck.py        # `docker healthcheck` helper
├── docs/                     # SETUP / TROUBLESHOOTING / SOLUTIONS / ROADMAP
├── .devcontainer/            # Codespaces / VS Code dev container
├── .github/workflows/        # CI + CodeQL
├── Dockerfile                # non-root runtime, pinned Python 3.11
├── docker-compose.yml
├── Makefile                  # dev-friendly entrypoints
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

---

## Contributing & security

- New challenge idea? Open an issue using the **Proposed challenge**
  template, then see [CONTRIBUTING.md](CONTRIBUTING.md).
- Real bug in the *framework* (not an intentional vuln)? See
  [SECURITY.md](SECURITY.md).

---

## Learning resources

- [gRPC Security Best Practices](https://grpc.io/docs/guides/auth/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [PortSwigger — JWT Attacks](https://portswigger.net/web-security/jwt)
- [NCC Group: A pentester's guide to attacking gRPC](https://research.nccgroup.com/2021/10/11/cracking-rdp-and-attacking-grpc-services/)
- [Cloudflare: HTTP/2 Rapid Reset Attack](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)

---

*Inspired by DVWA, WebGoat, and the security research community. For
educational use only. MIT licensed.*
