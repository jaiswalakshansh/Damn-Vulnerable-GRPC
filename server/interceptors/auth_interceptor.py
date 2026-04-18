"""
Authentication interceptor for DVGRPC.

Vulnerabilities embedded:
  [VULN-4]  JWT Algorithm Confusion — server accepts HS256 signed with RSA public key
  [VULN-9]  Metadata Bypass — x-internal-service header skips all auth
  [VULN-2]  AdminService is explicitly excluded from auth checks
"""

import grpc
import jwt as pyjwt

from server.config import (
    INTERNAL_SERVICE_HEADER,
    INTERNAL_SERVICE_VALUE,
    JWT_SECRET,
    RSA_PUBLIC_KEY_PATH,
)

# Methods that are always accessible without a token
PUBLIC_METHODS = frozenset(
    [
        "/dvgrpc.AuthService/Login",
        "/dvgrpc.AuthService/Register",
        "/dvgrpc.AuthService/GetPublicKey",
        # Reflection endpoints
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    ]
)


def _load_public_key() -> str | None:
    try:
        with open(RSA_PUBLIC_KEY_PATH, "r") as f:
            return f.read()
    except OSError:
        return None


def verify_token(token: str) -> dict | None:
    """
    VULNERABILITY [VULN-4]: JWT Algorithm Confusion

    The server tries three verification strategies in order:
      1. HS256 with the application secret (correct usage)
      2. RS256 with the RSA public key (correct usage)
      3. HS256 with the RSA PUBLIC KEY as the HMAC secret  <-- VULNERABLE

    Strategy 3 allows an attacker to:
      a) Fetch the public key via GetPublicKey RPC
      b) Craft a token with any claims (e.g., role=admin)
      c) Sign with HS256 using the public key bytes as the secret
      d) Server accepts the token as valid
    """
    if not token:
        return None

    # Strategy 1: HS256 with JWT_SECRET
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except pyjwt.InvalidTokenError:
        pass

    pub_key = _load_public_key()

    # Strategy 2: RS256 with RSA public key
    if pub_key:
        try:
            return pyjwt.decode(token, pub_key, algorithms=["RS256"])
        except pyjwt.InvalidTokenError:
            pass

    # Strategy 3 (VULNERABLE): HS256 with RSA public key as HMAC secret
    if pub_key:
        try:
            return pyjwt.decode(token, pub_key, algorithms=["HS256"])
        except pyjwt.InvalidTokenError:
            pass

    return None


class AuthInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        metadata = dict(handler_call_details.invocation_metadata)

        # VULNERABILITY [VULN-9]: Metadata bypass
        # Any client that sends this header gets full admin access with no token.
        # The header value is hardcoded in config.py — discoverable via source review.
        if metadata.get(INTERNAL_SERVICE_HEADER) == INTERNAL_SERVICE_VALUE:
            return continuation(handler_call_details)

        # Public methods — no token required
        if method in PUBLIC_METHODS:
            return continuation(handler_call_details)

        # VULNERABILITY [VULN-2]: AdminService has no authentication check.
        # Every RPC under AdminService is reachable without a token.
        if "/dvgrpc.AdminService/" in method:
            return continuation(handler_call_details)

        # All other methods — require a valid token
        auth_header = metadata.get("authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()

        payload = verify_token(token)
        if payload is None:

            def _deny(request, context):
                context.abort(
                    grpc.StatusCode.UNAUTHENTICATED,
                    "Missing or invalid authentication token.",
                )

            return grpc.unary_unary_rpc_method_handler(_deny)

        return continuation(handler_call_details)
