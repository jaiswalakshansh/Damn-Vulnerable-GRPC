# Security Policy

## 👀 Before you report

This repository is **intentionally vulnerable**.  The following are
*features*, not bugs:

- SQL injection in `ProductService.SearchProducts`
- Command injection in `CommandService.Ping`
- Path traversal in `FileService.ReadFile`
- Hardcoded credentials (`admin:admin123`)
- JWT algorithm confusion in `AuthInterceptor.verify_token`
- Server reflection enabled without auth
- …and everything else called out in `challenges/`.

Please **do not** open issues or PRs "fixing" these — they are the point
of the project.

---

## ✅  What counts as a real security issue?

We *do* want to hear about:

| Category                       | Example                                                              |
|--------------------------------|----------------------------------------------------------------------|
| **Toolchain** vulnerabilities  | Supply-chain issue in CI workflows, dependencies, Docker image       |
| **Privilege escalation** outside the intended vulns | Compose config that could pivot to host |
| **Accidental leaks**           | A real secret checked into git (please don't laugh)                  |
| **Unexpected container breakouts** | Capability/config errors that let `command_injection` escape     |
| **Data-exfil on the maintainer infra** | A workflow inadvertently exposing repo secrets               |

If in doubt, report it anyway.

---

## 📬  How to report

**Do not open a public issue.**  Instead:

1. Use GitHub's *Private vulnerability reporting* on the repo's
   **Security** tab, or
2. Email <security@dvgrpc.local> (replace with the maintainer's address
   in your fork) with:
   - A description of the issue
   - Steps to reproduce
   - Impact assessment
   - Any suggested patch

We aim to acknowledge within **72 hours** and to have an initial triage
within **7 days**.

---

## 🔒  Responsible disclosure

- Please give us **at least 90 days** before publishing details.
- We'll credit you in the release notes unless you prefer to stay
  anonymous.
- We don't currently run a bug-bounty program, but a heartfelt
  thank-you is guaranteed.

---

## 🧰  Hardening the *framework*

Even though the application is insecure, the surrounding infrastructure
follows standard hygiene:

- Dockerfile runs the server as a non-root user (`dvgrpc`).
- Dependencies are pinned in `requirements.txt` and monitored by
  Dependabot (see `.github/dependabot.yml`).
- CI is run on read-only `GITHUB_TOKEN`s. Secrets are not exposed to
  PRs from forks.
- CodeQL runs weekly on `main` (see `.github/workflows/codeql.yml`).

If any of these drift, it's a real bug — please report it.
