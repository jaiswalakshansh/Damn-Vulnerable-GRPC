# Roadmap

A living wish-list of real-world challenges, tooling, and infra we'd love
to see added. Pick one, open an issue, and go.

## New challenges (real-world flavour)

| Idea                                   | Real-world analogue                                               | Est. difficulty |
|----------------------------------------|-------------------------------------------------------------------|-----------------|
| gRPC-Web CSRF                          | Browser-originated gRPC-Web calls without CORS/Origin checks      | medium          |
| mTLS bypass via `insecure_channel`     | Misconfigured internal service with both insecure & TLS ports     | hard            |
| Protobuf deserialization bomb          | 1MB `Any` nested 100 levels deep exhausts CPU                     | medium          |
| Integer overflow on `int32 page_size`  | Negative page size causes OOB read                                | medium          |
| gRPC **channelz** exposure             | CVE-2020-1912 — internal debug surface exposed on prod             | easy            |
| OAuth/OIDC token replay                | Log in once → replay token after logout (no revocation list)      | medium          |
| GraphQL-style nested batch DoS         | Unbounded "GetAllOrders" with embedded `Item` fetches              | hard            |
| Excessive metadata (header bomb)       | 8k headers crash the default HTTP/2 frame decoder                  | medium          |
| TOCTOU in file upload                  | Validate filename, then reopen for write                           | medium          |
| Race condition in balance transfer     | Classic banking race — send N concurrent `Transfer` calls         | hard            |

## Platform / tooling

- [ ] **Burp extension** for automatic proto decoding
- [ ] **Wireshark capture filter cheatsheet** in `docs/`
- [ ] **Prometheus metrics** (intentionally leaking `jwt_secret` as a label — a fun misconfig challenge)
- [ ] **Grafana dashboard JSON** so instructors can watch attackers in real time
- [ ] **Replay CLI** that records attacker traffic and builds an attack graph
- [ ] **Kubernetes manifests** with deliberate RBAC holes

## Docs

- [ ] Translated READMEs: `README.es.md`, `README.ja.md`, `README.hi.md`
- [ ] `docs/WORKSHOP.md` — a 4-hour instructor-led curriculum
- [ ] Animated GIF in the main README showing a full challenge solve
- [ ] Asciinema recordings per challenge (`docs/asciinema/*.cast`)

## Infra

- [ ] Publish `ghcr.io/jaiswalakshansh/dvgrpc:latest` on every tag
- [ ] Sign images with cosign
- [ ] SBOM (`docker scout sbom`) on release
- [ ] Renovate or keep Dependabot — evaluate which is less noisy

## Bigger bets

- [ ] **Multi-tenant scoreboard** — an opt-in central leaderboard (with
      consent) so classrooms can track progress
- [ ] **Self-grading mode** — replay recorded exploits and auto-grade
      workshop attendees
- [ ] **Web UI** — a grpcui fork with a built-in exploit library

Interested in picking one up? Open an issue with the **Proposed
challenge** template and link to this roadmap entry.
