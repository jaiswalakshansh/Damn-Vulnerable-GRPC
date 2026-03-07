# Bonus Challenges — Cryptographic Failures

**Category:** Cryptographic Failures
**Difficulty:** 🔴 Hard
**Service:** `CryptoService`

---

## Bonus 1 — AES-ECB Mode

**Flag:** `FLAG{3cb_m0d3_l3aks_p4tt3rns_b4d}`

ECB (Electronic Codebook) mode encrypts each 16-byte block independently using the same key. Identical plaintext blocks produce identical ciphertext blocks, leaking data patterns.

```bash
TOKEN=$(grpcurl -plaintext localhost:50051 dvgrpc.AuthService/Login \
  -d '{"username":"alice","password":"alice123"}' | jq -r .token)

# Encrypt identical blocks — notice the pattern
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.CryptoService/Encrypt \
  -d '{"plaintext":"AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA","algorithm":"AES-ECB"}'
# Blocks 1 and 2 will be identical in the ciphertext
```

---

## Bonus 2 — HMAC Forgery

**Flag:** `FLAG{s1gn4tur3_f0rg3d_w34k_hmac}`

The `CryptoService.VerifySignature` RPC checks an HMAC-SHA256 signature. The secret is stored in `server/config.py` as `HMAC_SECRET_PREFIX`. Read it via path traversal or SQLi, then forge a valid signature.

```python
import hmac, hashlib

# Secret from config.py
secret = b"dvgrpc_secret_1337"
data = b"forge_me"
sig = hmac.new(secret, data, hashlib.sha256).hexdigest()
print(sig)
```

```bash
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.CryptoService/VerifySignature \
  -d "{\"data\":\"forge_me\",\"signature\":\"$SIG\",\"algorithm\":\"sha256\"}"
```
