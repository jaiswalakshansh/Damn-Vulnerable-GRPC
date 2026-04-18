# Changelog

All notable changes to DVGRPC are documented here. The project loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] — 2026-04-18

### Added — new challenge
- **Challenge 13 — Integer Overflow / Unvalidated Pagination.** New
  `ProductService.PaginatedSearch` RPC trusts `int32 per_page` and
  `int32 page` verbatim. Negative `per_page` → SQLite `LIMIT -1` →
  full-table dump (including a hidden "premium" product containing the
  flag). Full README + working exploit script + regression test.

### Added — observability (opt-in)
- **`server/interceptors/metrics_interceptor.py`** — gRPC interceptor
  tracking per-method calls, errors, and latencies; emits Prometheus
  text format via a small HTTP sidecar on `DVGRPC_METRICS_PORT`.
- `/metrics` and `/healthz` endpoints.
- No new runtime dependencies.

### Added — automation
- **`scripts/selfcheck.py`** — probes every intentional vulnerability
  end-to-end, prints a pass/fail table, and can auto-update the local
  scoreboard file.
- **`make solve-all`** runs every exploit in sequence.
- **`make selfcheck`** convenience wrapper for the script above.
- **`make healthcheck`** convenience wrapper.

### Added — supply chain & release
- **`.github/workflows/release.yml`** publishes multi-arch (amd64 +
  arm64) images to `ghcr.io/<owner>/dvgrpc:{latest,vX.Y.Z}` on tags,
  with provenance and SBOM attestations.
- **`.pre-commit-config.yaml`** with ruff, black, gitleaks, and the
  usual hygiene hooks.
- **`.gitleaks.toml`** allowlists the intentional weak secrets so
  gitleaks raises noise *only* for regressions.

### Added — CI coverage for features
- New CI job `feature-scripts` that verifies `make help`,
  `scripts/scoreboard.py --json/--reset`, `scripts/healthcheck.py`,
  proto compilation via Makefile, and `scripts/selfcheck.py` against a
  live server — plus `curl /metrics` to confirm the sidecar.
- New CI job `exploits-compile` that `compileall`s every exploit and
  script.
- New test module `tests/test_features.py` exercising the scoreboard,
  healthcheck, selfcheck, env overrides, metrics interceptor + HTTP
  sidecar, exploit script imports, challenge-dir mappings, and the
  Makefile help output.

### Changed
- `tests/test_challenges.py`: added Challenge-13 regression test.
- `scripts/scoreboard.py` catalogue gains Challenge 13 entry.
- `challenges/README.md`, main `README.md`, and `docs/SOLUTIONS.md`
  updated for Challenge 13 and the metrics feature.

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
