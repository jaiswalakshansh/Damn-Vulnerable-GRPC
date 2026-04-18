"""
CommandService implementation.

Vulnerabilities:
  [VULN-7] Command Injection — user input passed directly to subprocess shell
"""

import subprocess

import generated.command_pb2 as command_pb2
import generated.command_pb2_grpc as command_pb2_grpc
import grpc


def _run(cmd: str) -> tuple[str, int]:
    """Execute a shell command and return (stdout+stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,  # VULNERABILITY: shell=True enables injection
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        return output, result.returncode
    except subprocess.TimeoutExpired:
        return "Command timed out.", 1
    except Exception as exc:
        return str(exc), 1


class CommandServiceServicer(command_pb2_grpc.CommandServiceServicer):

    def Ping(self, request, context):
        """
        VULNERABILITY [VULN-7]: OS Command Injection.

        The 'host' parameter is directly embedded in a shell command string.
        An attacker can inject arbitrary commands using shell metacharacters.

        Payloads:
          host = "127.0.0.1; cat /app/secret/cmd_flag.txt"
          host = "127.0.0.1 && id"
          host = "$(cat /app/secret/cmd_flag.txt)"
          host = "`cat /app/secret/cmd_flag.txt`"

        The 'command' field in the response also leaks the full command string,
        making it easy to confirm injection and adjust payloads.

        Flag stored at: /app/secret/cmd_flag.txt
        FLAG{c0mm4nd_1nj3ct10n_v14_grpc_p1ng}
        """
        count = max(1, min(request.count or 1, 5))
        host = request.host  # Unsanitized

        # VULNERABILITY: f-string directly injects user input into shell command
        cmd = f"ping -c {count} {host}"

        output, rc = _run(cmd)
        return command_pb2.PingResponse(
            output=output,
            return_code=rc,
            command=cmd,  # VULNERABILITY: leaks the full command
        )

    def Nslookup(self, request, context):
        """
        VULNERABILITY [VULN-7b]: Command injection in nslookup.

        Payload: domain = "google.com; id"
        """
        domain = request.domain  # Unsanitized
        cmd = f"nslookup {domain}"
        output, rc = _run(cmd)
        return command_pb2.NslookupResponse(output=output, return_code=rc)

    def Traceroute(self, request, context):
        """
        VULNERABILITY [VULN-7c]: Command injection in traceroute.

        Payload: host = "127.0.0.1; cat /etc/passwd"
        """
        host = request.host  # Unsanitized
        cmd = f"traceroute -m 5 {host}"
        output, rc = _run(cmd)
        return command_pb2.TracerouteResponse(output=output, return_code=rc)

    def Whois(self, request, context):
        """
        VULNERABILITY [VULN-7d]: Command injection in whois.
        """
        domain = request.domain  # Unsanitized
        cmd = f"whois {domain}"
        output, _ = _run(cmd)
        return command_pb2.WhoisResponse(output=output)
