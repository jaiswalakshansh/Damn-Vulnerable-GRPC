# DVGRPC Challenges

10 main challenges + 2 bonus crypto challenges, covering the most common gRPC security vulnerabilities.

## Difficulty Scale

| Symbol | Difficulty |
|--------|-----------|
| 🟢 | Easy |
| 🟡 | Medium |
| 🔴 | Hard |

## Challenge Index

| # | Name | Category | Difficulty | Flag |
|---|------|----------|------------|------|
| 01 | [Server Reflection](01-server-reflection/) | Information Disclosure | 🟢 | `FLAG{r3fl3ct10n_3xp0s3s_4ll_s3rv1c3s}` |
| 02 | [Unauthenticated Admin](02-unauthenticated-admin/) | Broken Access Control | 🟢 | `FLAG{unauth_4dm1n_n0_t0k3n_n33d3d}` |
| 03 | [SQL Injection](03-sql-injection/) | Injection | 🟡 | `FLAG{sql_1nj3ct10n_1n_grpc_4p1_f13ld}` |
| 04 | [JWT Algorithm Confusion](04-jwt-confusion/) | Broken Authentication | 🔴 | `FLAG{jwt_4lg0r1thm_c0nfus10n_pwn3d}` |
| 05 | [IDOR](05-idor/) | Broken Access Control | 🟢 | `FLAG{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}` |
| 06 | [Path Traversal](06-path-traversal/) | Injection | 🟡 | `FLAG{p4th_tr4v3rs4l_gr0und_z3r0_4pp}` |
| 07 | [Command Injection](07-command-injection/) | Injection | 🟡 | `FLAG{c0mm4nd_1nj3ct10n_v14_grpc_p1ng}` |
| 08 | [Mass Assignment](08-mass-assignment/) | Security Misconfiguration | 🟡 | `FLAG{m4ss_4ss1gnm3nt_r0l3_3sc4l4t10n}` |
| 09 | [Metadata Bypass](09-metadata-bypass/) | Broken Authentication | 🟡 | `FLAG{m3t4d4t4_byp4ss_l1k3_4_pr0}` |
| 10 | [Hardcoded Credentials](10-hardcoded-credentials/) | Security Misconfiguration | 🟢 | `FLAG{h4rdc0d3d_s3cr3ts_4r3_b4d_pr4ct1c3}` |
| B1 | [Weak Crypto (ECB)](bonus-crypto/) | Cryptographic Failures | 🔴 | `FLAG{3cb_m0d3_l3aks_p4tt3rns_b4d}` |
| B2 | [HMAC Forgery](bonus-crypto/) | Cryptographic Failures | 🔴 | `FLAG{s1gn4tur3_f0rg3d_w34k_hmac}` |

## Recommended Order

If you're new to gRPC pentesting, follow this learning path:

```
01 (Recon) → 02 (Easy win) → 10 (Creds) → 05 (IDOR) → 08 (Mass Assignment)
           → 03 (SQLi) → 06 (Traversal) → 07 (RCE) → 09 (Bypass) → 04 (JWT)
```

## Tools You'll Need

```bash
# gRPC CLI tools
pip install grpcurl  # or brew install grpcurl

# Python gRPC
pip install grpcio grpcio-tools grpcio-reflection PyJWT cryptography bcrypt

# Optional but useful
pip install grpc-interceptor
apt-get install grpcurl  # Kali Linux
```

## Quick Start

```bash
# Start the server
docker-compose up -d

# Verify it's running
grpcurl -plaintext localhost:50051 list

# Begin with Challenge 01
python client/exploits/exploit_01_reflection.py
```
