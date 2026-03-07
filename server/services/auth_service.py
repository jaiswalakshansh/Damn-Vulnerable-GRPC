"""
AuthService implementation.

Vulnerabilities:
  [VULN-8]  Mass Assignment — 'role' field accepted without validation
  [VULN-4]  JWT Algorithm Confusion — public key exposed via GetPublicKey
  [VULN-10] Hardcoded credentials — admin:admin123 in config.py
"""
import datetime

import bcrypt
import grpc
import jwt as pyjwt

from server.config import JWT_SECRET, RSA_PRIVATE_KEY_PATH, RSA_PUBLIC_KEY_PATH, FLAGS
from server.database import get_db
from server.interceptors.auth_interceptor import verify_token

# These are imported after proto generation in main.py and injected here
import generated.auth_pb2 as auth_pb2
import generated.auth_pb2_grpc as auth_pb2_grpc


class AuthServiceServicer(auth_pb2_grpc.AuthServiceServicer):

    def Login(self, request, context):
        if not request.username or not request.password:
            return auth_pb2.LoginResponse(
                success=False, message="Username and password are required."
            )

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password, role FROM users WHERE username = ?",
                (request.username,),
            )
            user = cursor.fetchone()
        finally:
            conn.close()

        if user is None or not bcrypt.checkpw(
            request.password.encode(), user["password"].encode()
        ):
            return auth_pb2.LoginResponse(success=False, message="Invalid credentials.")

        payload = {
            "user_id":  user["id"],
            "username": user["username"],
            "role":     user["role"],
            "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

        return auth_pb2.LoginResponse(
            success=True,
            token=token,
            message="Login successful.",
            role=user["role"],
        )

    def Register(self, request, context):
        if not request.username or not request.password:
            return auth_pb2.RegisterResponse(
                success=False, message="Username and password are required."
            )

        # VULNERABILITY [VULN-8]: Mass Assignment
        # The 'role' field is taken directly from the client request.
        # An attacker can send role="admin" to gain elevated privileges.
        # Flag: FLAG{m4ss_4ss1gnm3nt_r0l3_3sc4l4t10n}
        role = request.role.strip() if request.role else "user"

        conn = get_db()
        try:
            cursor = conn.cursor()
            pw_hash = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt()).decode()
            cursor.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)",
                (request.username, pw_hash, request.email, role),
            )
            user_id = cursor.lastrowid
            conn.commit()
        except Exception as exc:
            return auth_pb2.RegisterResponse(success=False, message=str(exc))
        finally:
            conn.close()

        # Leak the assigned role — helpful for the attacker to confirm exploitation
        return auth_pb2.RegisterResponse(
            success=True,
            user_id=user_id,
            message=f"Registered successfully. Assigned role: {role}",
        )

    def GetPublicKey(self, request, context):
        """
        VULNERABILITY [VULN-4]: Exposes the RSA public key used to verify RS256 JWTs.
        An attacker can use this key as the HMAC secret to forge HS256 tokens with
        arbitrary claims (e.g., role=admin).
        """
        try:
            with open(RSA_PUBLIC_KEY_PATH, "r") as f:
                public_key = f.read()
        except OSError:
            public_key = ""

        return auth_pb2.GetPublicKeyResponse(
            public_key=public_key,
            algorithm="RS256",
            hint=(
                "This key is also used for HS256 verification. "
                "Think about what that means for token forgery."
            ),
        )

    def WhoAmI(self, request, context):
        payload = verify_token(request.token)
        if payload is None:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or expired token.")
            return

        return auth_pb2.WhoAmIResponse(
            username=payload.get("username", ""),
            role=payload.get("role", ""),
            user_id=payload.get("user_id", 0),
        )
