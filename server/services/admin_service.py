"""
AdminService implementation.

Vulnerabilities:
  [VULN-2] Missing authentication — all RPCs are publicly accessible
  [VULN-2] Information disclosure — GetSystemInfo leaks JWT secret and DB path
"""
import os
import platform
import sqlite3
import sys

import grpc

from server.config import FLAGS, JWT_SECRET, DB_PATH
from server.database import get_db

import generated.admin_pb2 as admin_pb2
import generated.admin_pb2_grpc as admin_pb2_grpc


class AdminServiceServicer(admin_pb2_grpc.AdminServiceServicer):
    """
    VULNERABILITY [VULN-2]: This entire service has NO authentication.
    The interceptor explicitly skips auth for /dvgrpc.AdminService/* routes.
    Any unauthenticated client can call every RPC here.
    """

    def GetFlag(self, request, context):
        """Return the flag for a given challenge name. No auth required."""
        challenge = request.challenge.strip().lower()
        flag = FLAGS.get(challenge)

        if flag:
            return admin_pb2.GetFlagResponse(
                flag=flag,
                message=f"Congratulations! You solved the '{challenge}' challenge.",
            )

        available = ", ".join(sorted(FLAGS.keys()))
        return admin_pb2.GetFlagResponse(
            flag="",
            message=f"Unknown challenge. Available: {available}",
        )

    def GetSystemInfo(self, request, context):
        """
        VULNERABILITY [VULN-2b]: Information disclosure.
        Returns internal config including the JWT signing secret.
        This alone is enough to forge tokens without the algorithm confusion attack.
        """
        return admin_pb2.GetSystemInfoResponse(
            hostname=os.uname().nodename,
            os_info=f"{platform.system()} {platform.release()}",
            python_version=sys.version,
            db_path=DB_PATH,
            jwt_secret=JWT_SECRET,  # Leaks HS256 signing key!
            server_version="DVGRPC v1.0.0-vulnerable",
        )

    def ListAllFlags(self, request, context):
        """Returns every flag in the database. No auth required."""
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT challenge, flag, hint FROM flags ORDER BY challenge")
            rows = cursor.fetchall()
        finally:
            conn.close()

        entries = [
            admin_pb2.FlagEntry(
                challenge=row["challenge"],
                flag=row["flag"],
                hint=row["hint"],
            )
            for row in rows
        ]
        return admin_pb2.ListAllFlagsResponse(flags=entries)

    def ExecuteRawQuery(self, request, context):
        """
        Raw SQL execution with no authentication and no sanitization.
        Combined with the missing auth, this is a direct path to all data.
        """
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(request.sql)
            rows = cursor.fetchall()
            result = [str(dict(row)) for row in rows]
            conn.commit()
        except sqlite3.Error as exc:
            return admin_pb2.ExecuteRawQueryResponse(rows=[], error=str(exc))
        finally:
            conn.close()

        return admin_pb2.ExecuteRawQueryResponse(rows=result, error="")
