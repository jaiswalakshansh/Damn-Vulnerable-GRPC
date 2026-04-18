#!/usr/bin/env python3
"""
Rewrite the ``import <name>_pb2`` lines emitted by ``grpc_tools.protoc``
into ``from generated import <name>_pb2`` so callers can import the stubs
as part of the ``generated`` package.

Usage:  python scripts/fix_proto_imports.py <generated_dir>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    gen_dir = Path(argv[1] if len(argv) > 1 else "generated")
    pattern = re.compile(r"^import (\w+_pb2)", re.M)
    changed = 0
    for grpc_file in gen_dir.glob("*_pb2_grpc.py"):
        text = grpc_file.read_text()
        new_text = pattern.sub(r"from generated import \1", text)
        if new_text != text:
            grpc_file.write_text(new_text)
            changed += 1
    print(f"  fixed imports in {changed} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
