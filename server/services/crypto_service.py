"""
CryptoService implementation.

Vulnerabilities:
  [BONUS-1] AES-ECB mode — no IV, identical blocks produce identical ciphertext
  [BONUS-2] Hardcoded AES key and IV — key = "1234567890abcdef", IV = "0000000000000000"
  [BONUS-3] Padding oracle — error messages distinguish padding vs MAC failures
  [BONUS-4] Weak HMAC — predictable secret prefix, forgeable
"""

import hashlib
import hmac
import os

import generated.crypto_pb2 as crypto_pb2
import generated.crypto_pb2_grpc as crypto_pb2_grpc
import grpc
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from server.config import CRYPTO_IV, CRYPTO_KEY, FLAGS, HMAC_SECRET_PREFIX


class CryptoServiceServicer(crypto_pb2_grpc.CryptoServiceServicer):

    def Encrypt(self, request, context):
        """
        VULNERABILITY [BONUS-1 & BONUS-2]:
          - AES-ECB mode reveals repeating plaintext patterns
          - Key is hardcoded: b"1234567890abcdef"
          - IV (CBC mode) is hardcoded: b"0000000000000000"
        """
        algorithm = request.algorithm.upper() if request.algorithm else "AES-ECB"
        plaintext = request.plaintext.encode()

        try:
            if algorithm == "AES-ECB":
                # VULNERABILITY: ECB mode — no IV, deterministic per block
                cipher = AES.new(CRYPTO_KEY, AES.MODE_ECB)
                ct = cipher.encrypt(pad(plaintext, AES.block_size))
                return crypto_pb2.EncryptResponse(
                    ciphertext_hex=ct.hex(),
                    algorithm="AES-ECB",
                    iv_hex="",
                )
            elif algorithm == "AES-CBC":
                # VULNERABILITY: IV is hardcoded — never changes
                cipher = AES.new(CRYPTO_KEY, AES.MODE_CBC, iv=CRYPTO_IV)
                ct = cipher.encrypt(pad(plaintext, AES.block_size))
                return crypto_pb2.EncryptResponse(
                    ciphertext_hex=ct.hex(),
                    algorithm="AES-CBC",
                    iv_hex=CRYPTO_IV.hex(),  # Leaks the hardcoded IV
                )
            else:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Unsupported algorithm.")
        except Exception as exc:
            context.abort(grpc.StatusCode.INTERNAL, str(exc))

    def Decrypt(self, request, context):
        """
        VULNERABILITY [BONUS-3]: Padding oracle.
        Different error messages for:
          - Bad padding       → "Invalid padding"
          - Correct padding   → (returns plaintext or MAC error)
        Classic CBC padding oracle attack surface.
        """
        algorithm = request.algorithm.upper() if request.algorithm else "AES-ECB"
        try:
            ct = bytes.fromhex(request.ciphertext_hex)
        except ValueError:
            return crypto_pb2.DecryptResponse(success=False, error="Invalid hex encoding.")

        try:
            if algorithm == "AES-ECB":
                cipher = AES.new(CRYPTO_KEY, AES.MODE_ECB)
                try:
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    return crypto_pb2.DecryptResponse(plaintext=pt.decode(errors="replace"), success=True)
                except ValueError:
                    # VULNERABILITY: Distinguishable padding error
                    return crypto_pb2.DecryptResponse(success=False, error="Invalid padding.")
            elif algorithm == "AES-CBC":
                iv = bytes.fromhex(request.iv_hex) if request.iv_hex else CRYPTO_IV
                cipher = AES.new(CRYPTO_KEY, AES.MODE_CBC, iv=iv)
                try:
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    return crypto_pb2.DecryptResponse(plaintext=pt.decode(errors="replace"), success=True)
                except ValueError:
                    # VULNERABILITY: Distinguishable padding error
                    return crypto_pb2.DecryptResponse(success=False, error="Invalid padding.")
            else:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Unsupported algorithm.")
        except Exception as exc:
            context.abort(grpc.StatusCode.INTERNAL, str(exc))

    def HashData(self, request, context):
        algorithm = (request.algorithm or "sha256").lower()
        data = request.data.encode()

        if algorithm == "md5":
            digest = hashlib.md5(data).hexdigest()
        elif algorithm == "sha1":
            digest = hashlib.sha1(data).hexdigest()
        elif algorithm == "sha256":
            digest = hashlib.sha256(data).hexdigest()
        else:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Unsupported algorithm.")
            return

        return crypto_pb2.HashResponse(hash=digest, algorithm=algorithm)

    def VerifySignature(self, request, context):
        """
        VULNERABILITY [BONUS-4]: Weak HMAC with predictable secret.
        Secret = HMAC_SECRET_PREFIX (hardcoded in config.py).
        If an attacker reads config.py (via path traversal or SQLi),
        they can forge valid signatures.

        The flag is returned when a valid signature is submitted.
        """
        algorithm = (request.algorithm or "sha256").lower()
        secret = HMAC_SECRET_PREFIX.encode()
        data = request.data.encode()

        expected = hmac.new(secret, data, algorithm).hexdigest()
        is_valid = hmac.compare_digest(expected, request.signature)

        flag = FLAGS["crypto_forge"] if is_valid else ""
        return crypto_pb2.VerifySignatureResponse(valid=is_valid, flag=flag)
