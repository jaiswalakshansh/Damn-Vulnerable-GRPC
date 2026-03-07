"""
FileService implementation.

Vulnerabilities:
  [VULN-6] Path Traversal — filename is joined with base dir but never normalized
  [VULN-6] resolved_path field leaks the full server-side path to the client
"""
import os

import grpc

from server.config import FILE_BASE_DIR, SECRET_FILE_DIR

import generated.file_pb2 as file_pb2
import generated.file_pb2_grpc as file_pb2_grpc


class FileServiceServicer(file_pb2_grpc.FileServiceServicer):

    def ReadFile(self, request, context):
        """
        VULNERABILITY [VULN-6]: Path Traversal.

        The filename from the client is joined with FILE_BASE_DIR using os.path.join,
        but the result is NEVER normalized or validated.

        Malicious payloads:
          filename = "../../../../etc/passwd"
          filename = "../../../../app/secret/path_flag.txt"
          filename = "../../../../app/server/config.py"   <-- reveals all secrets

        The response also returns resolved_path, confirming the traversal.

        Flag stored at: /app/secret/path_flag.txt
        FLAG{p4th_tr4v3rs4l_gr0und_z3r0_4pp}
        """
        filename = request.filename

        # VULNERABILITY: os.path.join does not prevent traversal
        # os.path.join("/app/uploads", "../../etc/passwd") == "/app/uploads/../../etc/passwd"
        # which open() will happily resolve to /etc/passwd
        file_path = os.path.join(FILE_BASE_DIR, filename)

        # No normalization, no prefix check — just open whatever path resolves to
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
            size = os.path.getsize(file_path)
        except FileNotFoundError:
            context.abort(grpc.StatusCode.NOT_FOUND, f"File not found: {file_path}")
            return
        except PermissionError:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, f"Permission denied: {file_path}")
            return
        except Exception as exc:
            context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return

        return file_pb2.ReadFileResponse(
            content=content,
            resolved_path=file_path,  # VULNERABILITY: leaks server-side path
            size=size,
        )

    def ListFiles(self, request, context):
        """
        VULNERABILITY [VULN-6b]: Directory listing with path traversal.

        directory = "../../secret"  reveals /app/secret/
        directory = "../../"        reveals /app/
        """
        directory = request.directory or "."
        dir_path = os.path.join(FILE_BASE_DIR, directory)

        try:
            entries = os.listdir(dir_path)
        except FileNotFoundError:
            context.abort(grpc.StatusCode.NOT_FOUND, f"Directory not found: {dir_path}")
            return
        except Exception as exc:
            context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return

        return file_pb2.ListFilesResponse(
            files=sorted(entries),
            base_dir=dir_path,  # VULNERABILITY: leaks resolved path
        )

    def WriteFile(self, request, context):
        """Also path-traversal vulnerable — attacker can write to arbitrary locations."""
        if not request.filename:
            return file_pb2.WriteFileResponse(success=False, message="Filename required.")

        file_path = os.path.join(FILE_BASE_DIR, request.filename)

        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as f:
                f.write(request.content)
        except Exception as exc:
            return file_pb2.WriteFileResponse(success=False, message=str(exc))

        return file_pb2.WriteFileResponse(success=True, message=f"Written to {file_path}.")
