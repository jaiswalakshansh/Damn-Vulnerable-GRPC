#!/usr/bin/env python3
"""
Reset the local DVGRPC SQLite database to its seeded state.

  python scripts/reset_db.py          # wipe and re-seed
  python scripts/reset_db.py --keep-users  # only rebuild flags/products/notes

Useful when a challenge (e.g. SQL injection) has written junk into the db
or when the schema has changed between commits.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow running without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.config import DB_PATH
from server.database import init_db


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--yes", action="store_true", help="skip interactive confirmation")
    args = p.parse_args()

    db = Path(DB_PATH)
    if db.exists():
        if not args.yes:
            reply = input(f"  About to delete {db}. Continue? [y/N] ").strip().lower()
            if reply != "y":
                print("  Aborted.")
                return
        db.unlink()
        print(f"  Removed {db}")

    init_db()
    print(f"  Re-initialised db at {db}")


if __name__ == "__main__":
    main()
