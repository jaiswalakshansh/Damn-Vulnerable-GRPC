"""
Opt-in metrics interceptor.

Tracks per-RPC call counts, error counts, and latencies. Exposed as a
Prometheus-style text table via the ``/metrics`` endpoint of a tiny HTTP
sidecar started by ``server.main`` when ``DVGRPC_METRICS_PORT`` is set.

Why "opt-in"? DVGRPC intentionally mirrors real-world services that ship
without observability. Learners flip the env var to *see* what good looks
like, compare the attack visibility before/after, and write mitigation
playbooks off the resulting dashboards.

This module has no third-party dependencies — it renders the text
format that Prometheus scrapes directly.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import grpc


class MetricsInterceptor(grpc.ServerInterceptor):
    """Record counts + latencies per (method, grpc_status)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[tuple[str, str], int] = defaultdict(int)
        self._errors: dict[tuple[str, str], int] = defaultdict(int)
        self._latency_ms_sum: dict[str, float] = defaultdict(float)
        self._latency_ms_count: dict[str, int] = defaultdict(int)
        self.started_at = time.time()

    # ---- gRPC hook ----
    def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        handler = continuation(handler_call_details)
        if handler is None or not handler.unary_unary:
            return handler

        inner = handler.unary_unary

        def wrapped(request, context):
            t0 = time.perf_counter()
            status = "OK"
            try:
                return inner(request, context)
            except grpc.RpcError as exc:  # pragma: no cover
                status = getattr(exc, "code", lambda: "UNKNOWN")().name
                raise
            except Exception:
                status = "INTERNAL"
                raise
            finally:
                dt_ms = (time.perf_counter() - t0) * 1000
                with self._lock:
                    self._calls[(method, status)] += 1
                    if status != "OK":
                        self._errors[(method, status)] += 1
                    self._latency_ms_sum[method] += dt_ms
                    self._latency_ms_count[method] += 1

        return grpc.unary_unary_rpc_method_handler(
            wrapped,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    # ---- snapshot / text rendering ----
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "calls": dict(self._calls),
                "errors": dict(self._errors),
                "lat_sum": dict(self._latency_ms_sum),
                "lat_cnt": dict(self._latency_ms_count),
                "uptime": time.time() - self.started_at,
            }

    def render_prometheus(self) -> str:
        snap = self.snapshot()
        out: list[str] = []
        out.append("# HELP dvgrpc_uptime_seconds Seconds since server start.")
        out.append("# TYPE dvgrpc_uptime_seconds gauge")
        out.append(f"dvgrpc_uptime_seconds {snap['uptime']:.3f}")

        out.append("# HELP dvgrpc_rpc_calls_total Total RPC count per method + status.")
        out.append("# TYPE dvgrpc_rpc_calls_total counter")
        for (method, status), n in snap["calls"].items():
            out.append(f'dvgrpc_rpc_calls_total{{method="{method}",status="{status}"}} {n}')

        out.append("# HELP dvgrpc_rpc_errors_total Total non-OK RPCs per method + code.")
        out.append("# TYPE dvgrpc_rpc_errors_total counter")
        for (method, status), n in snap["errors"].items():
            out.append(f'dvgrpc_rpc_errors_total{{method="{method}",status="{status}"}} {n}')

        out.append("# HELP dvgrpc_rpc_latency_ms_avg Average RPC latency per method (ms).")
        out.append("# TYPE dvgrpc_rpc_latency_ms_avg gauge")
        for method, s in snap["lat_sum"].items():
            c = snap["lat_cnt"].get(method, 0) or 1
            out.append(f'dvgrpc_rpc_latency_ms_avg{{method="{method}"}} {s / c:.3f}')
        out.append("")
        return "\n".join(out)


def start_metrics_http_server(interceptor: MetricsInterceptor, port: int) -> ThreadingHTTPServer:
    """Serve /metrics and /healthz on a separate HTTP port."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args, **kwargs):  # silence access log
            pass

        def do_GET(self):
            if self.path in ("/metrics", "/metrics/"):
                body = interceptor.render_prometheus().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path in ("/healthz", "/healthz/"):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok\n")
                return
            self.send_response(404)
            self.end_headers()

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="dvgrpc-metrics")
    thread.start()
    return server
