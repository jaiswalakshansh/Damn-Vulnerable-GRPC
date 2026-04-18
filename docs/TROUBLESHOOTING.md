# Troubleshooting & FAQ

> TL;DR — 9 out of 10 issues are one of these three: wrong port, stale
> generated stubs, or the container restarting on a crash. The decision
> tree below gets you unstuck fast.

---

## Quick decision tree

```
server won't come up
├─ port 50051 already in use?                  → change DVGRPC_PORT in .env, `make down && make up`
├─ docker logs show Python traceback?          → `make logs`  → read the top of the stack
└─ healthcheck says "not ready"?               → `python scripts/healthcheck.py`

client can't connect
├─ "failed to connect" from grpcurl            → is the server running?  `make ps` / `docker ps`
├─ "unknown service" / reflection empty        → wrong port, or server still starting  (wait 5s)
└─ "Received RST_STREAM with code 2"           → TLS mismatch: must pass `-plaintext`

import errors in exploit scripts
├─ "ModuleNotFoundError: generated"            → run `make proto`
└─ "no module named server"                    → run from the repo root, not inside client/
```

---

## Common issues

### 1. `ModuleNotFoundError: No module named 'generated'`

The proto stubs haven't been compiled yet.

```bash
make proto
```

If you prefer to recompile on every startup (useful during development),
add `RUN_PROTO_ON_STARTUP=1` to your `.env` — the server already does this
automatically inside Docker.

---

### 2. "Port 50051 already in use"

```bash
# Figure out who's holding it
sudo lsof -iTCP:50051 -sTCP:LISTEN
# or on macOS / WSL
ss -tlnp | grep 50051
```

Stop the offender, or pick a different port:

```bash
echo "DVGRPC_PORT=50151" >> .env
make down && make up
```

Remember to pass `-H localhost:50151` to `grpcurl` and set
`DVGRPC_HOST_PORT=localhost:50151` for the exploit scripts.

---

### 3. `grpcurl` exits with `Received RST_STREAM with code 2`

You forgot `-plaintext`. DVGRPC doesn't serve TLS (that's intentional —
see [Challenge 01](../challenges/01-server-reflection/)):

```bash
grpcurl -plaintext localhost:50051 list
```

---

### 4. `bcrypt` build error during `pip install`

Some minimal Linux images lack `libffi-dev` / `build-essential`. On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential libffi-dev
```

Or just use the Docker path — the image ships with everything pre-installed.

---

### 5. The SQLite db got corrupted by my SQLi payload

```bash
make reset-db          # local path
# or for Docker:
docker volume rm dvgrpc_data
make up
```

---

### 6. Healthcheck keeps failing

Symptom: `make ps` shows container status **unhealthy**.

```bash
make logs          # look for a Python traceback
python scripts/healthcheck.py --timeout 10
```

If reflection is reachable but the healthcheck still fails inside Docker,
the container likely hasn't finished proto generation. Give it a few more
seconds — the healthcheck `start_period` is 10s.

---

### 7. JWT confusion challenge isn't working

Common reasons:

- You didn't include the **full PEM**, including `-----BEGIN PUBLIC KEY-----`
  and the trailing newline, as the HMAC secret.
- You forged the token with a public key from a *previous* server run
  (keys persist in `dvgrpc_keys` volume) — use the *current* key.

See [SOLUTIONS.md#challenge-04](./SOLUTIONS.md#challenge-04--jwt-algorithm-confusion)
for a reference exploit.

---

### 8. Exploit scripts fail inside Docker

The exploit scripts are meant to run on the **host**, not inside the
server container. Run them from your venv:

```bash
source .venv/bin/activate
python client/exploits/exploit_04_jwt_confusion.py
```

Or override the host:

```bash
DVGRPC_HOST_PORT=localhost:50051 python client/exploits/exploit_04_jwt_confusion.py
```

---

### 9. "Docker daemon not running" on WSL

```bash
# inside WSL
sudo service docker start
# or, if you're using Docker Desktop: just open the app on Windows.
```

---

### 10. I fixed a real bug and tests fail

If you just patched a *challenge* (e.g. parameterised the SQL query), the
regression test in `tests/test_challenges.py` is designed to catch that —
update the challenge README and delete/skip the matching test in the same PR.

---

## FAQ

### Is this safe to run?

Only on **localhost** or an **isolated VM**. It contains remote command
execution, SQL injection, file read/write — do **not** expose 50051 to
the internet.

### Why is there no TLS?

Skipping TLS is intentional: it lowers the barrier to the first exploit
and keeps the focus on the application layer. In real-world deployments,
mTLS would (and should) be enabled — see *"Bonus: TLS downgrade"* in the
[roadmap](./ROADMAP.md).

### Can I use this in a classroom / workshop?

Please do. A suggested outline is in [docs/WORKSHOP.md](./WORKSHOP.md) if
you'd like a 4-hour curriculum.

### How do I contribute a new challenge?

See [CONTRIBUTING.md](../CONTRIBUTING.md). TL;DR: open an issue using the
"Proposed challenge" template first so we can discuss scope.

### Where do I report a *framework* bug (not an intentional vuln)?

Open a GitHub issue using the *bug_report* template. Please specify your
OS, Docker/Python version, and paste the last 30 lines of `make logs`.

### Can I submit flags anywhere?

The scoreboard (`make scoreboard`) stores progress locally. There is no
central server — DVGRPC is fully offline by design.
