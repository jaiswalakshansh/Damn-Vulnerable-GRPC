"""
ProductService implementation.

Vulnerabilities:
  [VULN-3] SQL Injection — search query uses string formatting, not parameterization
  [VULN-3] debug_query field leaks the raw SQL to the client
"""
import grpc

from server.database import get_db

import generated.product_pb2 as product_pb2
import generated.product_pb2_grpc as product_pb2_grpc


class ProductServiceServicer(product_pb2_grpc.ProductServiceServicer):

    def SearchProducts(self, request, context):
        """
        VULNERABILITY [VULN-3]: SQL Injection via string formatting.

        The 'query' field is directly interpolated into the SQL string.
        An attacker can perform UNION-based injection to dump the flags table.

        Proof-of-concept payload for 'query' field:
          ' UNION SELECT id,flag,challenge,1.0,'' FROM flags--

        The 'category' field is also injectable (less obvious):
          ' OR '1'='1

        Additionally, debug_query returns the raw SQL to the caller,
        making it trivial to confirm injection and craft payloads.

        Flag: FLAG{sql_1nj3ct10n_1n_grpc_4p1_f13ld}
        """
        limit = max(1, min(request.limit or 20, 100))

        # VULNERABILITY: String formatting instead of parameterized query
        if request.category:
            sql = (
                f"SELECT id, name, description, price, category "
                f"FROM products "
                f"WHERE name LIKE '%{request.query}%' "
                f"AND category = '{request.category}' "
                f"LIMIT {limit}"
            )
        else:
            sql = (
                f"SELECT id, name, description, price, category "
                f"FROM products "
                f"WHERE name LIKE '%{request.query}%' "
                f"LIMIT {limit}"
            )

        conn = get_db()
        try:
            cursor = conn.cursor()
            try:
                cursor.execute(sql)
                rows = cursor.fetchall()
            except Exception as exc:
                # VULNERABILITY: Verbose SQL errors leak schema information
                context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Database error: {exc}\nQuery was: {sql}",
                )
                return
        finally:
            conn.close()

        products = [
            product_pb2.Product(
                id=row["id"],
                name=row["name"],
                description=row["description"],
                price=float(row["price"] or 0),
                category=row["category"] or "",
            )
            for row in rows
        ]

        return product_pb2.SearchResponse(
            products=products,
            debug_query=sql,  # VULNERABILITY: Leaks raw SQL to client
            count=len(products),
        )

    def GetProduct(self, request, context):
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, description, price, category FROM products WHERE id = ?",
                (request.product_id,),
            )
            row = cursor.fetchone()
        finally:
            conn.close()

        if row is None:
            return product_pb2.GetProductResponse(found=False)

        product = product_pb2.Product(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            price=float(row["price"] or 0),
            category=row["category"] or "",
        )
        return product_pb2.GetProductResponse(product=product, found=True)

    def PaginatedSearch(self, request, context):
        """
        VULNERABILITY [VULN-13]: Unvalidated integer pagination.

        SQLite interprets ``LIMIT -1`` as "no limit" and ignores negative
        ``OFFSET``. The server trusts the client-supplied ``per_page`` and
        ``page`` fields verbatim, so an attacker can dump the entire table —
        including items the UI intended to hide behind later pages
        (e.g. the unreleased "premium" product whose name contains the flag).

        Exploit: PaginatedSearchRequest(query="", page=0, per_page=-1)

        Flag: FLAG{int3g3r_b0unds_n0t_v4l1d4t3d}
        """
        q        = request.query or ""
        page     = request.page               # NOT validated
        per_page = request.per_page if request.per_page else 5   # default

        # VULNERABILITY: no bounds check; negative per_page → LIMIT -1 → dump all
        offset = page * per_page
        sql = (
            "SELECT id, name, description, price, category "
            "FROM products "
            "WHERE name LIKE ? "
            "LIMIT ? OFFSET ?"
        )

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(sql, (f"%{q}%", per_page, offset))
            rows = cursor.fetchall()
        finally:
            conn.close()

        products = [
            product_pb2.Product(
                id=row["id"],
                name=row["name"],
                description=row["description"],
                price=float(row["price"] or 0),
                category=row["category"] or "",
            )
            for row in rows
        ]
        return product_pb2.PaginatedSearchResponse(
            products=products,
            total_returned=len(products),
            page=page,
            per_page=per_page,
        )

    def AddProduct(self, request, context):
        if not request.name:
            return product_pb2.AddProductResponse(success=False, message="Name is required.")

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO products (name, description, price, category) VALUES (?,?,?,?)",
                (request.name, request.description, request.price, request.category),
            )
            product_id = cursor.lastrowid
            conn.commit()
        except Exception as exc:
            return product_pb2.AddProductResponse(success=False, message=str(exc))
        finally:
            conn.close()

        return product_pb2.AddProductResponse(
            success=True, product_id=product_id, message="Product added."
        )
