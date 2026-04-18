# Contributing to Damn Vulnerable gRPC

First off — thanks for considering a contribution! DVGRPC grows with the
community. Every new challenge, every doc tweak, every bug report makes
this a better place to learn.

> Heads up: this repository is **intentionally vulnerable**. We keep the
> vulnerabilities in `server/`, `proto/`, and `challenges/`. Everything
> *outside* those directories is regular code and should be secure,
> tested, and reviewed.

---

## Quick start for contributors

```bash
git clone https://github.com/jaiswalakshansh/Damn-Vulnerable-GRPC.git
cd Damn-Vulnerable-GRPC
make setup          # creates .venv with runtime + dev deps
source .venv/bin/activate
make proto          # generate stubs
make test           # run the regression suite
make lint           # ruff + black
```

Please open an issue before you start any large change — it saves us all
time.

---

## Types of contributions we love

| Type                 | Example                                                 |
|----------------------|---------------------------------------------------------|
| New challenge        | A CVE-inspired vuln (gRPC-Web, channelz, mTLS bypass)   |
| Tooling              | IDE snippets, Burp extensions, attack-range helpers     |
| Docs                 | Typo fixes, better explanations, translated READMEs     |
| Tests                | Edge cases, new fuzzer inputs, property-based tests     |
| Infra                | CI speed-ups, devcontainer polish                       |

---

## Ground rules

1. **Open an issue first for anything non-trivial.** Use the "Proposed
   challenge" issue template if you're adding a new vulnerability.
2. **Keep the intentional vulns inside `server/`.** Don't "fix" a flag —
   if you believe a challenge is broken, update the challenge README in
   the same PR.
3. **Run `make lint && make test` before pushing.** CI will too.
4. **One challenge per PR.** Small, reviewable PRs land faster.
5. **Never commit real-world secrets, PII, or other people's code.**

---

## Adding a new challenge

```
challenges/
└── 13-your-vuln/
    └── README.md        # objective, steps, vulnerable code, fix

proto/
└── your_service.proto   # if new service is needed

server/
└── services/your_service.py
└── ...                  # register in main.py

client/
└── exploits/exploit_13_your_vuln.py

tests/
└── test_challenges.py   # add a regression test
```

Minimum required for a challenge:

- [ ] Short, clear README with the four sections (Objective, Steps,
      Vulnerable code, Fix) — mirror the structure of the existing
      challenges.
- [ ] A working exploit script in `client/exploits/`.
- [ ] A regression test in `tests/test_challenges.py`.
- [ ] An entry in `server/config.py::FLAGS`.
- [ ] An entry in `scripts/scoreboard.py::CHALLENGES`.
- [ ] Updated [SOLUTIONS.md](docs/SOLUTIONS.md) and main [README](README.md).
- [ ] A *real-world CVE or blog post* link — we care about authenticity.

---

## Code style

- **Python**: ruff + black, line length 110. Pre-commit: `make format`.
- **Protobuf**: 2-space indent, file-level `package dvgrpc;`.
- **Shell**: POSIX-compatible inside `scripts/`; bash is fine inside
  `.devcontainer/`.
- **Markdown**: 100-char soft wrap. Use fenced code blocks with a language tag.

---

## Commit & PR conventions

- Write imperative commit messages: *"Add timing-attack challenge"*, not
  *"Added timing-attack challenge"*.
- Prefix with a scope: `docs:`, `feat(challenge-13):`, `ci:`, `tests:`.
- PR description should answer: **Why this change?**, **How does a
  reviewer verify it?**, **Does it add/modify a flag?**

---

## Security of the contribution workflow

Even though this app is insecure *by design*, the CI pipeline is not.
If you spot a real vulnerability in the `.github/` workflows, docker
images, or dev tooling, please follow [SECURITY.md](SECURITY.md) for
responsible disclosure.

---

## Code of conduct

Be respectful. Assume good intent. Be patient with learners — everyone
was a beginner once. The [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)
applies.
