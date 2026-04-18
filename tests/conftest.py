"""
Pytest fixtures for DVGRPC integration tests.

These tests spin up the real gRPC server in-process on an ephemeral port and
exercise each intentional vulnerability end-to-end. They guard against
regressions: if a refactor accidentally PATCHES a challenge, CI will fail
loudly, because the CTF flags stop being reachable.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent import futures
from pathlib import Path

import grpc
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GEN_DIR = REPO_ROOT / "generated"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _compile_protos() -> None:
    """Compile .proto files into ./generated once per session."""
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    (GEN_DIR / "__init__.py").touch()

    proto_files = sorted((REPO_ROOT / "proto").glob("*.proto"))
    assert proto_files, "no .proto files found"

    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"--proto_path={REPO_ROOT / 'proto'}",
        f"--python_out={GEN_DIR}",
        f"--grpc_python_out={GEN_DIR}",
        *[str(p) for p in proto_files],
    ]
    subprocess.check_call(cmd)

    # Fix relative imports inside generated _pb2_grpc files
    import re

    for grpc_file in GEN_DIR.glob("*_pb2_grpc.py"):
        t = grpc_file.read_text()
        t = re.sub(r"^import (\w+_pb2)", r"from generated import \1", t, flags=re.M)
        grpc_file.write_text(t)


@pytest.fixture(scope="session", autouse=True)
def _ensure_generated() -> None:
    if not any(GEN_DIR.glob("*_pb2.py")):
        _compile_protos()
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def server_port() -> int:
    return _free_port()


@pytest.fixture(scope="session")
def runtime_root(tmp_path_factory) -> Path:
    """Isolated DVGRPC_ROOT for the test session (fresh db, keys, uploads)."""
    root = tmp_path_factory.mktemp("dvgrpc-test-root")
    (root / "data").mkdir()
    (root / "keys").mkdir()
    (root / "uploads").mkdir()
    (root / "secret").mkdir()
    return root


@pytest.fixture(scope="session")
def grpc_server(server_port: int, runtime_root: Path):
    """Boot the DVGRPC server in-process on an ephemeral port."""
    os.environ["DVGRPC_ROOT"] = str(runtime_root)
    os.environ["PORT"] = str(server_port)
    os.environ["DB_PATH"] = str(runtime_root / "data" / "dvgrpc.db")

    # Import after env is set so config.py picks up the overrides
    from server.database import init_db
    from server.interceptors.auth_interceptor import AuthInterceptor
    from server.main import create_flag_files, generate_rsa_keys  # noqa: WPS433

    generate_rsa_keys()
    init_db()
    create_flag_files()

    from generated import (
        admin_pb2_grpc,
        auth_pb2_grpc,
        command_pb2_grpc,
        crypto_pb2_grpc,
        file_pb2_grpc,
        product_pb2_grpc,
        user_pb2_grpc,
    )

    from server.services.admin_service import AdminServiceServicer
    from server.services.auth_service import AuthServiceServicer
    from server.services.command_service import CommandServiceServicer
    from server.services.crypto_service import CryptoServiceServicer
    from server.services.file_service import FileServiceServicer
    from server.services.product_service import ProductServiceServicer
    from server.services.user_service import UserServiceServicer

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        interceptors=[AuthInterceptor()],
    )
    auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthServiceServicer(), server)
    user_pb2_grpc.add_UserServiceServicer_to_server(UserServiceServicer(), server)
    admin_pb2_grpc.add_AdminServiceServicer_to_server(AdminServiceServicer(), server)
    product_pb2_grpc.add_ProductServiceServicer_to_server(ProductServiceServicer(), server)
    file_pb2_grpc.add_FileServiceServicer_to_server(FileServiceServicer(), server)
    command_pb2_grpc.add_CommandServiceServicer_to_server(CommandServiceServicer(), server)
    crypto_pb2_grpc.add_CryptoServiceServicer_to_server(CryptoServiceServicer(), server)

    server.add_insecure_port(f"127.0.0.1:{server_port}")
    server.start()

    # Wait until accepting connections
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", server_port), timeout=0.3):
                break
        except OSError:
            time.sleep(0.05)

    yield server
    server.stop(1)


@pytest.fixture()
def channel(grpc_server, server_port: int):
    ch = grpc.insecure_channel(f"127.0.0.1:{server_port}")
    yield ch
    ch.close()
