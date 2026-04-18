#!/usr/bin/env python3
"""
DVGRPC Scoreboard
==================
Interactive CTF progress tracker.

  python scripts/scoreboard.py           # view & update progress
  python scripts/scoreboard.py --verify  # re-verify flags against a running server
  python scripts/scoreboard.py --reset   # wipe local progress

Progress is stored in `~/.dvgrpc-progress.json` so a learner can resume across
sessions without relying on any external service.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

PROGRESS_FILE = Path(os.getenv("DVGRPC_PROGRESS_FILE",
                               str(Path.home() / ".dvgrpc-progress.json")))


# ----------------------------------------------------------------------
# Challenge catalogue
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Challenge:
    key: str
    num: str
    title: str
    category: str
    difficulty: str
    flag: str

CHALLENGES: list[Challenge] = [
    Challenge("reflection",            "01", "Server Reflection",      "Info Disclosure",       "easy",
              "FLAG{r3fl3ct10n_3xp0s3s_4ll_s3rv1c3s}"),
    Challenge("unauthenticated_admin", "02", "Unauthenticated Admin",  "Access Control",        "easy",
              "FLAG{unauth_4dm1n_n0_t0k3n_n33d3d}"),
    Challenge("sql_injection",         "03", "SQL Injection",          "Injection",             "medium",
              "FLAG{sql_1nj3ct10n_1n_grpc_4p1_f13ld}"),
    Challenge("jwt_confusion",         "04", "JWT Algorithm Confusion","Broken Auth",           "hard",
              "FLAG{jwt_4lg0r1thm_c0nfus10n_pwn3d}"),
    Challenge("idor",                  "05", "IDOR",                   "Access Control",        "easy",
              "FLAG{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}"),
    Challenge("path_traversal",        "06", "Path Traversal",         "Injection",             "medium",
              "FLAG{p4th_tr4v3rs4l_gr0und_z3r0_4pp}"),
    Challenge("command_injection",     "07", "Command Injection",      "Injection",             "medium",
              "FLAG{c0mm4nd_1nj3ct10n_v14_grpc_p1ng}"),
    Challenge("mass_assignment",       "08", "Mass Assignment",        "Misconfiguration",      "medium",
              "FLAG{m4ss_4ss1gnm3nt_r0l3_3sc4l4t10n}"),
    Challenge("metadata_bypass",       "09", "Metadata Bypass",        "Broken Auth",           "medium",
              "FLAG{m3t4d4t4_byp4ss_l1k3_4_pr0}"),
    Challenge("hardcoded_creds",       "10", "Hardcoded Credentials",  "Misconfiguration",      "easy",
              "FLAG{h4rdc0d3d_s3cr3ts_4r3_b4d_pr4ct1c3}"),
    Challenge("crypto_ecb",            "B1", "ECB Block Leakage",      "Crypto Failures",       "hard",
              "FLAG{3cb_m0d3_l3aks_p4tt3rns_b4d}"),
    Challenge("crypto_forge",          "B2", "HMAC Forgery",           "Crypto Failures",       "hard",
              "FLAG{s1gn4tur3_f0rg3d_w34k_hmac}"),
    Challenge("timing_attack",         "11", "Timing Attack",          "Info Disclosure",       "hard",
              "FLAG{t1m1ng_4tt4ck_us3r_3num3r4t10n}"),
    Challenge("streaming_dos",         "12", "Streaming DoS",          "Availability / DoS",    "medium",
              "FLAG{unb0und3d_str34m_3xh4usts_th3_s3rv3r}"),
]

VALID_FLAGS = {c.flag: c.key for c in CHALLENGES}
BY_KEY      = {c.key: c for c in CHALLENGES}

# ANSI colour helpers (graceful on Windows via colorama-free terminals)
def _supports_color() -> bool:
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None

def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _supports_color() else s

GREEN  = lambda s: _c("32", s)
YELLOW = lambda s: _c("33", s)
RED    = lambda s: _c("31", s)
BOLD   = lambda s: _c("1",  s)
DIM    = lambda s: _c("2",  s)
CYAN   = lambda s: _c("36", s)


# ----------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------
def load_progress() -> dict:
    if PROGRESS_FILE.exists():
        try:
            return json.loads(PROGRESS_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return {"solved": {}, "created": datetime.utcnow().isoformat()}


def save_progress(progress: dict) -> None:
    PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PROGRESS_FILE.write_text(json.dumps(progress, indent=2, sort_keys=True))


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------
DIFFICULTY_EMOJI = {"easy": GREEN("●"), "medium": YELLOW("●"), "hard": RED("●")}


def render(progress: dict) -> None:
    solved = progress.get("solved", {})
    print()
    print(BOLD("  ╔══════════════════════════════════════════════════════════════╗"))
    print(BOLD("  ║              DAMN VULNERABLE gRPC — SCOREBOARD               ║"))
    print(BOLD("  ╚══════════════════════════════════════════════════════════════╝"))

    total = len(CHALLENGES)
    count = sum(1 for c in CHALLENGES if c.key in solved)
    bar = "█" * count + "░" * (total - count)
    pct = int((count / total) * 100)
    print(f"\n  Progress: {GREEN(bar)}  {count}/{total}  ({pct}%)\n")

    headers = ["#", "D", "Title", "Category", "Status"]
    widths  = [4, 2, 26, 20, 10]

    def row(fields):
        return "  " + "  ".join(str(f).ljust(w) for f, w in zip(fields, widths))

    print(DIM(row(headers)))
    print(DIM("  " + "-" * (sum(widths) + (len(widths) - 1) * 2)))
    for c in CHALLENGES:
        badge = DIFFICULTY_EMOJI.get(c.difficulty, "○")
        status = GREEN("✓ solved") if c.key in solved else DIM("· pending")
        print(row([c.num, badge, c.title, c.category, status]))
    print()


# ----------------------------------------------------------------------
# Interactive loop
# ----------------------------------------------------------------------
def interactive(progress: dict) -> None:
    render(progress)
    print(DIM("  Paste a captured flag to record it, or press Enter to quit."))
    while True:
        try:
            flag = input(BOLD("  FLAG> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not flag:
            break
        key = VALID_FLAGS.get(flag)
        if key is None:
            print(RED("  ✗ Not a valid DVGRPC flag.\n"))
            continue
        if key in progress["solved"]:
            print(YELLOW(f"  • Already recorded: {BY_KEY[key].title}\n"))
            continue
        progress["solved"][key] = datetime.utcnow().isoformat()
        save_progress(progress)
        print(GREEN(f"  ✓ Unlocked: {BY_KEY[key].title}\n"))
    render(progress)


# ----------------------------------------------------------------------
# --verify: run a quick probe against a running server
# ----------------------------------------------------------------------
def verify_against_server() -> None:
    host = os.getenv("DVGRPC_HOST_PORT", "localhost:50051")
    print(BOLD(f"\n  Probing {host} …\n"))
    try:
        import grpc
        from grpc_reflection.v1alpha.proto_reflection_descriptor_database import (
            ProtoReflectionDescriptorDatabase,
        )
        channel = grpc.insecure_channel(host)
        db = ProtoReflectionDescriptorDatabase(channel)
        services = db.get_services()
    except Exception as exc:
        print(RED(f"  ✗ Could not reach server: {exc}"))
        return
    print(GREEN(f"  ✓ Reflection works — {len(services)} services exposed."))
    for svc in services:
        print(f"      · {svc}")
    print()


# ----------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="DVGRPC interactive CTF scoreboard")
    p.add_argument("--verify", action="store_true", help="probe a running DVGRPC server")
    p.add_argument("--reset",  action="store_true", help="wipe recorded progress")
    p.add_argument("--json",   action="store_true", help="dump progress as JSON and exit")
    args = p.parse_args()

    if args.reset:
        if PROGRESS_FILE.exists():
            PROGRESS_FILE.unlink()
        print(GREEN("  Progress wiped."))
        return

    progress = load_progress()

    if args.json:
        print(json.dumps(progress, indent=2))
        return

    if args.verify:
        verify_against_server()
        return

    interactive(progress)


if __name__ == "__main__":
    main()
