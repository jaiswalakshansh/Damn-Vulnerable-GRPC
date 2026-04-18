# Changelog

All notable changes to DVGRPC are documented here. The project loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — 2026-04-18

### Added — new challenges

- **Challenge 11 — Timing Attack (username enumeration)** against
  `AuthService.Login`. Demonstrates the classic "bcrypt only runs for
  existing users" leak (CWE-208).
- **Challenge 12 — Streaming / Resource Exhaustion DoS**. Saturates the
  server's fixed-size thread pool; inspired by CVE-2023-44487 (HTTP/2
  Rapid Reset).
- Exploit scripts and READMEs for both.

### Added — developer & learner experience

- **Makefile** with a dozen convenience targets (`make up`, `make test`,
  `make scoreboard`, `make exploit N=03`, …).
- **Interactive scoreboard** (`scripts/scoreboard.py`) — local CTF
  progress tracker, colourised table, `--verify` probe mode.
- **`scripts/reset_db.py`** and **`scripts/healthcheck.py`**.
- **`.devcontainer/`** for one-click Codespaces / VS Code setup.
- **`pyproject.toml`** (ruff + black + pytest configuration, project
  metadata, console script entry points).
- **`requirements-dev.txt`** with pytest, ruff, black, xdist.
- **`.env.example`** documenting every environment variable.

### Added — infrastructure

- **GitHub Actions CI** (`.github/workflows/ci.yml`): lint, proto
  compile, integration tests (Python 3.10/3.11/3.12), Docker build +
  grpcurl smoke test.
- **CodeQL** weekly scan (with intentional-vuln paths excluded).
- **Dependabot** configuration for pip, GitHub Actions, and Docker.
- **Issue templates** for bug reports and new-challenge proposals.

### Added — documentation

- **`docs/SETUP.md`** — Docker / local / Codespaces walkthroughs.
- **`docs/TROUBLESHOOTING.md`** — decision tree + top-10 common issues.
- **`docs/SOLUTIONS.md`** — spoiler-warned full walkthrough for every
  challenge.
- **`docs/ROADMAP.md`** — prioritised backlog of future challenges.
- **`CONTRIBUTING.md`**, **`SECURITY.md`**, **`CHANGELOG.md`**, **`LICENSE`**.
- README: badges, TOC, real-world CVE references, scoreboard preview.

### Added — tests

- **`tests/`** — pytest integration suite that spins the server in
  process, runs every challenge exploit end-to-end, and fails CI if any
  flag becomes unreachable.

### Changed

- `server/config.py` is now **fully env-configurable**. Paths default to
  `./.dvgrpc/` locally and `/app` in Docker — the server no longer
  needs `sudo mkdir /app/...` for local runs.
- `Dockerfile` drops to a non-root `dvgrpc` user, adds OCI labels,
  bakes in a smarter healthcheck, and uses `--no-install-recommends`.
- `docker-compose.yml` migrated to Compose V2 (no `version:` key),
  parameterised port, inlined start-period.
- Exploit scripts honour `DVGRPC_HOST_PORT` so you can target a remote
  instance (e.g. workshop server) without editing code.
- `client/client.py` resolves proto stubs relative to the repo instead
  of hardcoding `/app`.

### Fixed

- Generated proto stubs now import cleanly when running tests or
  exploit scripts from the repo root.
- Typos and outdated commands in multiple challenge READMEs.

---

## [1.0.0] — 2025-xx-xx (initial)

- 10 main challenges + 2 bonus crypto challenges
- Dockerfile + docker-compose
- Per-challenge README with vulnerable code snippet and mitigation
- Ready-to-run Python exploit scripts

---

[1.1.0]: https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC/releases/tag/v1.1.0
