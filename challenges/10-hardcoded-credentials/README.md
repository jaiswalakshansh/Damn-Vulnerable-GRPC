# Challenge 10 — Hardcoded Credentials

**Category:** Security Misconfiguration
**Difficulty:** 🟢 Easy
**Service:** `AuthService`
**Flag:** `FLAG{h4rdc0d3d_s3cr3ts_4r3_b4d_pr4ct1c3}`

---

## Background

Hardcoded credentials are one of the most common and easily exploited vulnerabilities. In DVGRPC, the admin password is hardcoded in `server/config.py` and seeded into the database at startup. Reading the source (via path traversal) or dumping the database (via SQLi) reveals the credentials immediately.

---

## Discovery Methods

| Method | Challenge | How |
|--------|-----------|-----|
| Source review | — | Read `server/config.py`: `ADMIN_PASSWORD = "admin123"` |
| Path traversal | 06 | `ReadFile("../../server/config.py")` |
| SQL injection | 03 | `UNION SELECT id,username,password,1.0,role FROM users` |
| Unauthenticated admin | 02 | `GetSystemInfo()` leaks `jwt_secret` |

---

## Steps

```bash
# Simply login with the hardcoded credentials
grpcurl -plaintext localhost:50051 dvgrpc.AuthService/Login \
  -d '{"username":"admin","password":"admin123"}'
```

---

## Fix

```python
# Use environment variables — never hardcode
import os
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]  # Fail fast if not set

# Or use a secrets manager
import boto3
secret = boto3.client("secretsmanager").get_secret_value(SecretId="dvgrpc/admin")
```

- Never store credentials in source code
- Never commit `.env` files containing real secrets
- Use `git-secrets`, `truffleHog`, or `gitleaks` in CI to catch leaks
