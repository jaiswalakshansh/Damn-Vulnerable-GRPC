"""
Feature tests — exercise the *non-vulnerability* pieces of DVGRPC:

- scoreboard (load / --json / --reset)
- healthcheck (up/down behaviour)
- selfcheck (runs against the in-process server fixture)
- metrics interceptor (counts RPCs, exposes /metrics)
- env overrides (DVGRPC_ROOT, DVGRPC_PORT) take effect
- every exploit script imports cleanly (catches broken sys.path/refactors)
"""
from __future__ import annotations

import http.client
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
EXPLOITS = sorted((REPO / "client" / "exploits").glob("exploit_*.py"))


# -------------------- scoreboard --------------------
def test_scoreboard_json_mode(tmp_path, monkeypatch):
    progress = tmp_path / "prog.json"
    monkeypatch.setenv("DVGRPC_PROGRESS_FILE", str(progress))
    out = subprocess.check_output(
        [sys.executable, str(REPO / "scripts/scoreboard.py"), "--json"],
        text=True, timeout=10,
    )
    data = json.loads(out)
    assert "solved" in data and isinstance(data["solved"], dict)


def test_scoreboard_reset_clears_file(tmp_path, monkeypatch):
    progress = tmp_path / "prog.json"
    progress.write_text(json.dumps({"solved": {"x": "y"}}))
    monkeypatch.setenv("DVGRPC_PROGRESS_FILE", str(progress))
    subprocess.check_call(
        [sys.executable, str(REPO / "scripts/scoreboard.py"), "--reset"],
        timeout=10,
    )
    assert not progress.exists()


def test_scoreboard_catalogue_matches_flags():
    """Every FLAG in server/config.py must appear in the scoreboard catalogue
    — so new challenges can never be silently missed by the UI."""
    sys.path.insert(0, str(REPO))
    from scripts.scoreboard import CHALLENGES
    from server.config import FLAGS
    scoreboard_keys = {c.key for c in CHALLENGES}
    missing = set(FLAGS) - scoreboard_keys
    assert not missing, f"Flags not in scoreboard: {missing}"


# -------------------- healthcheck --------------------
def test_healthcheck_fails_when_server_down(tmp_path):
    """Healthcheck exits non-zero when nothing is listening."""
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/healthcheck.py"),
         "--host", "127.0.0.1:1", "--timeout", "0.5"],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode != 0


def test_healthcheck_passes_against_fixture(channel, server_port):
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/healthcheck.py"),
         "--host", f"127.0.0.1:{server_port}", "--timeout", "3"],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ok" in r.stdout


# -------------------- selfcheck --------------------
def test_selfcheck_reports_all_challenges(channel, server_port):
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/selfcheck.py"),
         "--host", f"127.0.0.1:{server_port}", "--json"],
        capture_output=True, text=True, timeout=60,
    )
    # Extract the JSON payload (the script prints both a table and JSON)
    tail = r.stdout.rsplit("}", 1)[0].split("{", 1)
    assert tail  # guard
    blob = "{" + tail[1] + "}"
    data = json.loads(blob)
    assert set(data) >= {
        "reflection", "unauthenticated_admin", "sql_injection",
        "idor", "hardcoded_creds", "mass_assignment",
        "metadata_bypass", "integer_overflow",
    }


# -------------------- env overrides --------------------
def test_env_overrides_paths(monkeypatch, tmp_path):
    """Setting DVGRPC_ROOT must redirect every derived path."""
    monkeypatch.setenv("DVGRPC_ROOT", str(tmp_path))
    # Force a fresh import of the config module
    for m in [k for k in list(sys.modules) if k.startswith("server.config")]:
        del sys.modules[m]
    sys.path.insert(0, str(REPO))
    import server.config as cfg
    importlib.reload(cfg)
    assert cfg.DVGRPC_ROOT == tmp_path.resolve()
    assert str(tmp_path) in cfg.DB_PATH
    assert str(tmp_path) in cfg.FILE_BASE_DIR
    assert str(tmp_path) in cfg.SECRET_FILE_DIR


# -------------------- metrics interceptor --------------------
def test_metrics_interceptor_counts_and_renders():
    from server.interceptors.metrics_interceptor import MetricsInterceptor
    m = MetricsInterceptor()
    # Simulate 3 calls + 1 error
    with m._lock:
        m._calls[("/dvgrpc.AuthService/Login", "OK")] = 3
        m._errors[("/dvgrpc.AuthService/Login", "UNAUTHENTICATED")] = 1
        m._calls[("/dvgrpc.AuthService/Login", "UNAUTHENTICATED")] = 1
        m._latency_ms_sum["/dvgrpc.AuthService/Login"] = 300.0
        m._latency_ms_count["/dvgrpc.AuthService/Login"] = 4
    out = m.render_prometheus()
    assert "dvgrpc_rpc_calls_total" in out
    assert 'method="/dvgrpc.AuthService/Login"' in out
    assert "dvgrpc_rpc_latency_ms_avg" in out
    assert "dvgrpc_uptime_seconds" in out


def test_metrics_http_server_serves_metrics(tmp_path):
    """Start a real HTTP metrics sidecar on a free port and scrape it."""
    import socket
    from server.interceptors.metrics_interceptor import (
        MetricsInterceptor, start_metrics_http_server,
    )
    with socket.socket() as s:
        s.bind(("", 0))
        port = s.getsockname()[1]
    m = MetricsInterceptor()
    srv = start_metrics_http_server(m, port)
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/metrics")
        r = c.getresponse()
        assert r.status == 200
        body = r.read().decode()
        assert "dvgrpc_uptime_seconds" in body

        c.request("GET", "/healthz")
        r = c.getresponse()
        assert r.status == 200

        c.request("GET", "/nope")
        r = c.getresponse()
        assert r.status == 404
    finally:
        srv.shutdown()


# -------------------- exploit scripts compile & import --------------------
@pytest.mark.parametrize("exploit", EXPLOITS, ids=lambda p: p.stem)
def test_exploit_script_compiles(exploit: Path):
    # Compile-only test; actually invoking main() would attack the fixture.
    subprocess.check_call(
        [sys.executable, "-m", "py_compile", str(exploit)], timeout=10,
    )


def test_every_exploit_has_a_matching_challenge_dir():
    challenges = {p.name for p in (REPO / "challenges").iterdir() if p.is_dir()}
    for exp in EXPLOITS:
        num = exp.stem.split("_")[1]
        if num == "00":  # skip placeholders if any
            continue
        prefix = num + "-"
        matches = [c for c in challenges if c.startswith(prefix)]
        assert matches, f"{exp.name} has no challenges/{prefix}* directory"


# -------------------- Makefile sanity --------------------
def test_makefile_help_lists_key_targets():
    r = subprocess.run(["make", "-s", "help"], cwd=REPO, capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, r.stderr
    for target in ("run", "up", "down", "test", "proto", "scoreboard",
                   "selfcheck", "solve-all", "healthcheck"):
        assert target in r.stdout, f"missing target: {target}"
