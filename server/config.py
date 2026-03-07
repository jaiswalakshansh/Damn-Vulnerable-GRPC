"""
DVGRPC Server Configuration
============================
VULNERABILITY [VULN-10]: Hardcoded credentials and secrets.
These values are intentionally insecure for CTF purposes.
"""
import os

# ----------------------------------------------------------------
# VULNERABILITY: Hardcoded JWT secret — trivially bruteforceable
# ----------------------------------------------------------------
JWT_SECRET = "supersecretkey123"

# ----------------------------------------------------------------
# VULNERABILITY: Hardcoded admin credentials
# Flag: FLAG{h4rdc0d3d_s3cr3ts_4r3_b4d}
# ----------------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
ADMIN_EMAIL = "admin@dvgrpc.local"

# ----------------------------------------------------------------
# VULNERABILITY: Internal bypass header — security through obscurity
# Any client that sends this metadata header bypasses authentication.
# Flag: FLAG{m3t4d4t4_byp4ss_l1k3_4_pr0}
# ----------------------------------------------------------------
INTERNAL_SERVICE_HEADER = "x-internal-service"
INTERNAL_SERVICE_VALUE = "dvgrpc-internal-v1"

# Server
SERVER_PORT = int(os.getenv("PORT", "50051"))
SERVER_HOST = "0.0.0.0"

# Database
DB_PATH = os.getenv("DB_PATH", "/app/data/dvgrpc.db")

# RSA key paths (used for JWT RS256 — public key exposed via GetPublicKey RPC)
RSA_PRIVATE_KEY_PATH = "/app/keys/private.pem"
RSA_PUBLIC_KEY_PATH = "/app/keys/public.pem"

# File service upload directory (path traversal starts here)
FILE_BASE_DIR = "/app/uploads"
SECRET_FILE_DIR = "/app/secret"

# Crypto service (weak, hardcoded)
CRYPTO_KEY = b"1234567890abcdef"  # 16-byte AES key — hardcoded
CRYPTO_IV = b"0000000000000000"   # Hardcoded IV — never changes
HMAC_SECRET_PREFIX = "dvgrpc_secret_1337"

# CTF Flags — one per challenge
FLAGS = {
    "reflection":            "FLAG{r3fl3ct10n_3xp0s3s_4ll_s3rv1c3s}",
    "unauthenticated_admin": "FLAG{unauth_4dm1n_n0_t0k3n_n33d3d}",
    "sql_injection":         "FLAG{sql_1nj3ct10n_1n_grpc_4p1_f13ld}",
    "jwt_confusion":         "FLAG{jwt_4lg0r1thm_c0nfus10n_pwn3d}",
    "idor":                  "FLAG{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}",
    "path_traversal":        "FLAG{p4th_tr4v3rs4l_gr0und_z3r0_4pp}",
    "command_injection":     "FLAG{c0mm4nd_1nj3ct10n_v14_grpc_p1ng}",
    "mass_assignment":       "FLAG{m4ss_4ss1gnm3nt_r0l3_3sc4l4t10n}",
    "metadata_bypass":       "FLAG{m3t4d4t4_byp4ss_l1k3_4_pr0}",
    "hardcoded_creds":       "FLAG{h4rdc0d3d_s3cr3ts_4r3_b4d_pr4ct1c3}",
    "crypto_ecb":            "FLAG{3cb_m0d3_l3aks_p4tt3rns_b4d}",
    "crypto_forge":          "FLAG{s1gn4tur3_f0rg3d_w34k_hmac}",
}
