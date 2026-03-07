# Damn Vulnerable gRPC (DVGRPC)

> A deliberately insecure gRPC application for learning and practicing gRPC security vulnerabilities. Built for security researchers, CTF players, and developers who want to understand how gRPC apps can be attacked and defended.

---

## ⚠️ Legal Disclaimer

**This application is intentionally vulnerable. Do NOT deploy it on a public server or a production environment. It is intended for use in isolated lab/CTF environments only.**

---

## Challenges

| # | Vulnerability | Category | Difficulty |
|---|--------------|----------|------------|
| 01 | [Server Reflection](challenges/01-server-reflection/) | Info Disclosure | 🟢 Easy |
| 02 | [Unauthenticated Admin](challenges/02-unauthenticated-admin/) | Broken Access Control | 🟢 Easy |
| 03 | [SQL Injection](challenges/03-sql-injection/) | Injection | 🟡 Medium |
| 04 | [JWT Algorithm Confusion](challenges/04-jwt-confusion/) | Broken Auth | 🔴 Hard |
| 05 | [IDOR](challenges/05-idor/) | Broken Access Control | 🟢 Easy |
| 06 | [Path Traversal](challenges/06-path-traversal/) | Injection | 🟡 Medium |
| 07 | [Command Injection](challenges/07-command-injection/) | Injection | 🟡 Medium |
| 08 | [Mass Assignment](challenges/08-mass-assignment/) | Misconfiguration | 🟡 Medium |
| 09 | [Metadata Bypass](challenges/09-metadata-bypass/) | Broken Auth | 🟡 Medium |
| 10 | [Hardcoded Credentials](challenges/10-hardcoded-credentials/) | Misconfiguration | 🟢 Easy |
| B1 | [Weak Crypto (ECB)](challenges/bonus-crypto/) | Crypto Failures | 🔴 Hard |
| B2 | [HMAC Forgery](challenges/bonus-crypto/) | Crypto Failures | 🔴 Hard |

---

## Quick Start

### Option A — Docker Compose (Recommended)

```bash
git clone https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC.git
cd Damn-Vulnerable-GRPC
docker-compose up -d

# Verify the server is running
grpcurl -plaintext localhost:50051 list
```

### Option B — Local Python

```bash
git clone https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC.git
cd Damn-Vulnerable-GRPC

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

mkdir -p /app/data /app/keys /app/uploads /app/secret /app/generated
python -m server.main
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              gRPC Server (port 50051)               │
│                   No TLS — Insecure                 │
├──────────────┬──────────────┬───────────────────────┤
│  AuthService │  UserService │  AdminService         │
│ (VULN 4,8,10)│  (VULN 5)   │  (VULN 2)             │
├──────────────┼──────────────┼───────────────────────┤
│ ProductSvc   │  FileService │  CommandService       │
│  (VULN 3)    │  (VULN 6)   │  (VULN 7)             │
├──────────────┴──────────────┴───────────────────────┤
│  CryptoService (BONUS 1, 2)                         │
├─────────────────────────────────────────────────────┤
│  AuthInterceptor (VULN 9 — metadata bypass)         │
├─────────────────────────────────────────────────────┤
│  SQLite Database (/app/data/dvgrpc.db)              │
│  tables: users, products, notes, flags, secrets     │
└─────────────────────────────────────────────────────┘
```

---

## Tools

### grpcurl

```bash
# Install
brew install grpcurl              # macOS
apt-get install grpcurl           # Kali Linux

# Basic usage
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 describe dvgrpc.AuthService
grpcurl -plaintext -d '{"username":"admin","password":"admin123"}' \
  localhost:50051 dvgrpc.AuthService/Login
```

### grpcui (Browser-based UI)

```bash
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
grpcui -plaintext localhost:50051
```

### Python exploit scripts

```bash
pip install grpcio grpcio-tools grpcio-reflection PyJWT cryptography bcrypt

python client/exploits/exploit_01_reflection.py
python client/exploits/exploit_03_sql_injection.py
# ... etc
```

---

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | admin |
| `alice` | `alice123` | user |
| `bob` | `b0bpassw0rd` | user |
| `charlie` | `charlie_pass` | user |
| `dave` | `dave1234` | moderator |

---

## Flag Format

All flags follow the format: `FLAG{l33t_sp3ak_description}`

Run `grpcurl -plaintext localhost:50051 dvgrpc.AdminService/ListAllFlags` to verify your collection (this is itself part of Challenge 02!).

---

## Project Structure

```
Damn-Vulnerable-GRPC/
├── proto/                    # .proto service definitions (7 services)
├── server/
│   ├── main.py               # Entry point + proto generation
│   ├── config.py             # ⚠️  Hardcoded secrets (intentional)
│   ├── database.py           # SQLite setup + seed data
│   ├── interceptors/auth_interceptor.py
│   └── services/             # auth, user, admin, product, file, command, crypto
├── challenges/               # Challenge docs (10 + 2 bonus)
├── client/exploits/          # Ready-to-run Python exploit scripts
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Learning Resources

- [gRPC Security Best Practices](https://grpc.io/docs/guides/auth/)
- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [Analyzing gRPC Security](https://blog.detectify.com/industry-insights/analyzing-grpc-security/)

---

*Inspired by DVWA, WebGoat, and the security research community. For educational use only.*