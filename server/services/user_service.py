"""
UserService implementation.

Vulnerabilities:
  [VULN-5] IDOR — GetProfile and GetNote do not verify ownership
"""

import generated.user_pb2 as user_pb2
import generated.user_pb2_grpc as user_pb2_grpc
import grpc

from server.database import get_db
from server.interceptors.auth_interceptor import verify_token


def _get_caller(context) -> dict | None:
    """Extract JWT claims from request metadata."""
    metadata = dict(context.invocation_metadata())
    token = metadata.get("authorization", "").removeprefix("Bearer ").strip()
    return verify_token(token)


class UserServiceServicer(user_pb2_grpc.UserServiceServicer):

    def GetProfile(self, request, context):
        """
        VULNERABILITY [VULN-5]: IDOR — Insecure Direct Object Reference.

        The server fetches the profile for whatever user_id is in the request.
        It does NOT check whether the authenticated user owns that profile.

        user_id = 1 is always the admin account.
        The admin's 'secret' field contains FLAG{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}.

        Exploit:
          1. Login as any user (or use mass assignment to create one)
          2. Call GetProfile(user_id=1)
          3. Read the 'secret' field
        """
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, role, bio, secret FROM users WHERE id = ?",
                (request.user_id,),
            )
            user = cursor.fetchone()
        finally:
            conn.close()

        if user is None:
            context.abort(grpc.StatusCode.NOT_FOUND, f"User {request.user_id} not found.")
            return

        return user_pb2.GetProfileResponse(
            user_id=user["id"],
            username=user["username"],
            email=user["email"],
            role=user["role"],
            bio=user["bio"],
            secret=user["secret"],  # No masking — full secret returned
        )

    def UpdateProfile(self, request, context):
        caller = _get_caller(context)
        if caller is None:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Not authenticated.")
            return

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET bio = ? WHERE id = ?",
                (request.bio, caller["user_id"]),
            )
            conn.commit()
        finally:
            conn.close()

        return user_pb2.UpdateProfileResponse(success=True, message="Profile updated.")

    def ListUsers(self, request, context):
        limit = max(1, min(request.limit or 20, 100))
        offset = max(0, (request.page or 0) * limit)

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, role FROM users LIMIT ? OFFSET ?",
                (limit, offset),
            )
            rows = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM users")
            total = cursor.fetchone()[0]
        finally:
            conn.close()

        users = [user_pb2.UserSummary(user_id=r["id"], username=r["username"], role=r["role"]) for r in rows]
        return user_pb2.ListUsersResponse(users=users, total=total)

    def GetNote(self, request, context):
        """
        VULNERABILITY [VULN-5b]: Note IDOR.

        Any authenticated user can read any note by ID, including private ones.
        Note id=1 belongs to admin and contains the IDOR flag.
        """
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT n.id, n.title, n.content, n.is_private, u.username
                FROM notes n
                JOIN users u ON u.id = n.owner_id
                WHERE n.id = ?
                """,
                (request.note_id,),
            )
            note = cursor.fetchone()
        finally:
            conn.close()

        if note is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "Note not found.")
            return

        # No ownership check — returns private notes to anyone
        return user_pb2.GetNoteResponse(
            note_id=note["id"],
            title=note["title"],
            content=note["content"],
            owner=note["username"],
            is_private=bool(note["is_private"]),
        )

    def CreateNote(self, request, context):
        caller = _get_caller(context)
        if caller is None:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Not authenticated.")
            return

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO notes (title, content, owner_id, is_private) VALUES (?,?,?,1)",
                (request.title, request.content, caller["user_id"]),
            )
            note_id = cursor.lastrowid
            conn.commit()
        finally:
            conn.close()

        return user_pb2.CreateNoteResponse(success=True, note_id=note_id)
