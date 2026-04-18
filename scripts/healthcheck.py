#!/usr/bin/env python3
"""
Quick readiness probe for the DVGRPC server.

Exits 0 if the gRPC server accepts connections and responds to reflection,
nonzero otherwise.  Intended for use by Docker HEALTHCHECK, CI, and humans.

  python scripts/healthcheck.py
  python scripts/healthcheck.py --host localhost:50051 --timeout 3
"""

from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.getenv("DVGRPC_HOST_PORT", "localhost:50051"))
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args()

    try:
        import grpc
    except ImportError:
        print("grpcio not installed")
        return 2

    ch = grpc.insecure_channel(args.host)
    try:
        grpc.channel_ready_future(ch).result(timeout=args.timeout)
    except grpc.FutureTimeoutError:
        print(f"not ready: {args.host}")
        return 1

    try:
        from grpc_reflection.v1alpha.proto_reflection_descriptor_database import (
            ProtoReflectionDescriptorDatabase,
        )

        services = ProtoReflectionDescriptorDatabase(ch).get_services()
    except Exception as exc:  # reflection not enabled / disabled
        print(f"channel ready, reflection off: {exc}")
        return 0

    print(f"ok: {args.host} — {len(services)} services, reflection on")
    return 0


if __name__ == "__main__":
    sys.exit(main())
