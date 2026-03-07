"""
DVGRPC Generic Client
======================
A general-purpose interactive client for exploring the Damn Vulnerable gRPC server.
Works without proto stubs by using server reflection + grpcurl-style calls.

Usage:
  pip install grpcio grpcio-tools grpcio-reflection PyJWT cryptography bcrypt
  python client/client.py

Or use grpcurl directly:
  grpcurl -plaintext localhost:50051 list
  grpcurl -plaintext localhost:50051 describe dvgrpc.AuthService
  grpcurl -plaintext -d '{"username":"admin","password":"admin123"}' \\
    localhost:50051 dvgrpc.AuthService/Login
"""

import sys
import json
import grpc

# Add project root to path so we can import generated stubs
sys.path.insert(0, "/app")  # inside Docker
sys.path.insert(0, ".")     # local development

HOST = "localhost"
PORT = 50051


def get_channel() -> grpc.Channel:
    return grpc.insecure_channel(f"{HOST}:{PORT}")


def get_metadata(token: str | None = None, internal: bool = False) -> list[tuple[str, str]]:
    meta = []
    if token:
        meta.append(("authorization", f"Bearer {token}"))
    if internal:
        meta.append(("x-internal-service", "dvgrpc-internal-v1"))
    return meta


def login(username: str, password: str) -> str | None:
    """Login and return JWT token."""
    from generated import auth_pb2, auth_pb2_grpc
    channel = get_channel()
    stub = auth_pb2_grpc.AuthServiceStub(channel)
    try:
        resp = stub.Login(auth_pb2.LoginRequest(username=username, password=password))
        if resp.success:
            print(f"[+] Logged in as {username} (role={resp.role})")
            return resp.token
        print(f"[-] Login failed: {resp.message}")
    except grpc.RpcError as e:
        print(f"[-] RPC error: {e.code()} — {e.details()}")
    return None


def print_banner():
    print("""
╔══════════════════════════════════════════════════════╗
║         DAMN VULNERABLE gRPC — CTF Client           ║
╠══════════════════════════════════════════════════════╣
║  Server: localhost:50051  (no TLS)                  ║
║  Challenges: 10 main + 2 bonus                      ║
║                                                      ║
║  Quick start:                                        ║
║    grpcurl -plaintext localhost:50051 list           ║
║    python client/exploits/exploit_01_reflection.py  ║
╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    print_banner()
    print("Run individual exploit scripts in client/exploits/ to solve each challenge.")
    print("Run 'grpcurl -plaintext localhost:50051 list' to start enumerating.")
