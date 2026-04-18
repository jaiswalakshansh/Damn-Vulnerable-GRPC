"""
DVGRPC — Damn Vulnerable gRPC Server
=====================================
Starts all services on a single insecure (no TLS) port.
Server reflection is enabled — this is intentional (Challenge 1).
"""

import logging
import os
import subprocess
import sys
import time
from concurrent import futures
from pathlib import Path

import grpc
from grpc_reflection.v1alpha import reflection

from server.config import (
    FILE_BASE_DIR,
    FLAGS,
    RSA_PRIVATE_KEY_PATH,
    RSA_PUBLIC_KEY_PATH,
    SECRET_FILE_DIR,
    SERVER_HOST,
    SERVER_PORT,
)
from server.database import init_db
from server.interceptors.auth_interceptor import AuthInterceptor

logging.basicConfig(
    level=os.getenv("DVGRPC_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("dvgrpc.main")

# Proto/generated live next to the server tree in Docker (/app/proto, /app/generated)
# or at the repo root when running locally.
_REPO_ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = Path(os.getenv("DVGRPC_PROTO_DIR", _REPO_ROOT / "proto"))
GEN_DIR = Path(os.getenv("DVGRPC_GEN_DIR", _REPO_ROOT / "generated"))
if str(GEN_DIR.parent) not in sys.path:
    sys.path.insert(0, str(GEN_DIR.parent))


# ---------------------------------------------------------------------------
# Proto generation
# ---------------------------------------------------------------------------


def generate_protos() -> None:
    """Compile .proto files into Python stubs if not already done."""
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    (GEN_DIR / "__init__.py").touch()

    proto_files = list(PROTO_DIR.glob("*.proto"))
    if not proto_files:
        log.error("No .proto files found in %s", PROTO_DIR)
        sys.exit(1)

    log.info("Generating gRPC stubs from %d proto files…", len(proto_files))
    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"--proto_path={PROTO_DIR}",
        f"--python_out={GEN_DIR}",
        f"--grpc_python_out={GEN_DIR}",
    ] + [str(p) for p in proto_files]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("protoc failed:\n%s", result.stderr)
        sys.exit(1)

    # Fix relative imports in generated grpc files
    for grpc_file in GEN_DIR.glob("*_pb2_grpc.py"):
        content = grpc_file.read_text()
        content = content.replace("import auth_pb2", "from generated import auth_pb2")
        content = content.replace("import user_pb2", "from generated import user_pb2")
        content = content.replace("import admin_pb2", "from generated import admin_pb2")
        content = content.replace("import product_pb2", "from generated import product_pb2")
        content = content.replace("import file_pb2", "from generated import file_pb2")
        content = content.replace("import command_pb2", "from generated import command_pb2")
        content = content.replace("import crypto_pb2", "from generated import crypto_pb2")
        content = content.replace("import note_pb2", "from generated import note_pb2")
        grpc_file.write_text(content)

    log.info("Proto generation complete.")


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_rsa_keys() -> None:
    """Generate RSA key pair for JWT RS256 support if not already present."""
    key_dir = Path(RSA_PRIVATE_KEY_PATH).parent
    key_dir.mkdir(parents=True, exist_ok=True)

    if Path(RSA_PRIVATE_KEY_PATH).exists() and Path(RSA_PUBLIC_KEY_PATH).exists():
        return

    log.info("Generating RSA key pair…")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        Path(RSA_PRIVATE_KEY_PATH).write_bytes(private_pem)
        Path(RSA_PUBLIC_KEY_PATH).write_bytes(public_pem)
        log.info("RSA keys written to %s", key_dir)
    except Exception as exc:
        log.error("RSA key generation failed: %s", exc)


# ---------------------------------------------------------------------------
# Flag files
# ---------------------------------------------------------------------------


def create_flag_files() -> None:
    """Write flag files used by path traversal and command injection challenges."""
    os.makedirs(SECRET_FILE_DIR, exist_ok=True)
    os.makedirs(FILE_BASE_DIR, exist_ok=True)

    # Path traversal flag
    path_flag_file = Path(SECRET_FILE_DIR) / "path_flag.txt"
    path_flag_file.write_text(
        f"{FLAGS['path_traversal']}\n" "Congratulations! You exploited a path traversal vulnerability.\n"
    )

    # Command injection flag
    cmd_flag_file = Path(SECRET_FILE_DIR) / "cmd_flag.txt"
    cmd_flag_file.write_text(
        f"{FLAGS['command_injection']}\n" "Congratulations! You exploited OS command injection via gRPC.\n"
    )

    # Metadata bypass flag file (accessible after bypassing auth)
    meta_flag_file = Path(SECRET_FILE_DIR) / "meta_flag.txt"
    meta_flag_file.write_text(
        f"{FLAGS['metadata_bypass']}\n" "Congratulations! You used the internal service bypass header.\n"
    )

    # Sample files in the uploads directory
    (Path(FILE_BASE_DIR) / "readme.txt").write_text(
        "Welcome to DVGRPC file storage.\n" "Available files: readme.txt, sample.json\n"
    )
    (Path(FILE_BASE_DIR) / "sample.json").write_text(
        '{"message": "This is a public file. Try reading other paths..."}\n'
    )

    log.info("Flag files created in %s", SECRET_FILE_DIR)


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------


def serve() -> None:
    generate_rsa_keys()
    generate_protos()

    # Import generated modules + servicers AFTER proto generation
    import generated.admin_pb2 as admin_pb2
    import generated.admin_pb2_grpc as admin_pb2_grpc
    import generated.auth_pb2 as auth_pb2
    import generated.auth_pb2_grpc as auth_pb2_grpc
    import generated.command_pb2 as command_pb2
    import generated.command_pb2_grpc as command_pb2_grpc
    import generated.crypto_pb2 as crypto_pb2
    import generated.crypto_pb2_grpc as crypto_pb2_grpc
    import generated.file_pb2 as file_pb2
    import generated.file_pb2_grpc as file_pb2_grpc
    import generated.product_pb2 as product_pb2
    import generated.product_pb2_grpc as product_pb2_grpc
    import generated.user_pb2 as user_pb2
    import generated.user_pb2_grpc as user_pb2_grpc

    from server.services.admin_service import AdminServiceServicer
    from server.services.auth_service import AuthServiceServicer
    from server.services.command_service import CommandServiceServicer
    from server.services.crypto_service import CryptoServiceServicer
    from server.services.file_service import FileServiceServicer
    from server.services.product_service import ProductServiceServicer
    from server.services.user_service import UserServiceServicer

    init_db()
    create_flag_files()

    interceptor = AuthInterceptor()
    interceptors = [interceptor]

    # Opt-in metrics. Set DVGRPC_METRICS_PORT=9090 to enable.
    metrics_port = int(os.getenv("DVGRPC_METRICS_PORT", "0"))
    metrics = None
    if metrics_port:
        from server.interceptors.metrics_interceptor import (
            MetricsInterceptor,
            start_metrics_http_server,
        )

        metrics = MetricsInterceptor()
        interceptors.append(metrics)
        start_metrics_http_server(metrics, metrics_port)
        log.info("Metrics sidecar listening on :%d/metrics", metrics_port)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=interceptors,
    )

    # Register all services
    auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthServiceServicer(), server)
    user_pb2_grpc.add_UserServiceServicer_to_server(UserServiceServicer(), server)
    admin_pb2_grpc.add_AdminServiceServicer_to_server(AdminServiceServicer(), server)
    product_pb2_grpc.add_ProductServiceServicer_to_server(ProductServiceServicer(), server)
    file_pb2_grpc.add_FileServiceServicer_to_server(FileServiceServicer(), server)
    command_pb2_grpc.add_CommandServiceServicer_to_server(CommandServiceServicer(), server)
    crypto_pb2_grpc.add_CryptoServiceServicer_to_server(CryptoServiceServicer(), server)

    # VULNERABILITY [VULN-1]: Server reflection is enabled.
    # Attackers can enumerate every service, RPC, and message type without any credentials.
    # This is the starting point for all other challenges.
    service_names = [
        auth_pb2.DESCRIPTOR.services_by_name["AuthService"].full_name,
        user_pb2.DESCRIPTOR.services_by_name["UserService"].full_name,
        admin_pb2.DESCRIPTOR.services_by_name["AdminService"].full_name,
        product_pb2.DESCRIPTOR.services_by_name["ProductService"].full_name,
        file_pb2.DESCRIPTOR.services_by_name["FileService"].full_name,
        command_pb2.DESCRIPTOR.services_by_name["CommandService"].full_name,
        crypto_pb2.DESCRIPTOR.services_by_name["CryptoService"].full_name,
        reflection.SERVICE_NAME,
    ]
    reflection.enable_server_reflection(service_names, server)

    listen_addr = f"{SERVER_HOST}:{SERVER_PORT}"
    server.add_insecure_port(listen_addr)  # No TLS — intentional
    server.start()

    log.info("=" * 60)
    log.info("  DVGRPC Server started on %s (NO TLS)", listen_addr)
    log.info("  Services: Auth, User, Admin, Product, File, Command, Crypto")
    log.info("  Reflection: ENABLED")
    log.info("  Challenges: 10 (+2 bonus crypto)")
    log.info("=" * 60)
    log.info("  Try: grpcurl -plaintext localhost:%d list", SERVER_PORT)
    log.info("=" * 60)

    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(5)


if __name__ == "__main__":
    serve()
