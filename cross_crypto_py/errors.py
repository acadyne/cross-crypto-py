from __future__ import annotations

from typing import Literal, Optional


CrossCryptoErrorCode = Literal[
    "invalid_format",
    "invalid_encoding",
    "unsupported_algorithm",
    "unsupported_version",
    "invalid_key",
    "key_mismatch",
    "authentication_failed",
    "signature_invalid",
    "expired",
    "not_yet_valid",
    "payload_too_large",
    "runtime_unavailable",
]


class CrossCryptoError(Exception):
    """Error controlado de Cross-Crypto v3."""

    code: CrossCryptoErrorCode
    cause: Optional[BaseException]

    def __init__(
        self,
        code: CrossCryptoErrorCode,
        message: str,
        *,
        cause: Optional[BaseException] = None,
    ):
        super().__init__(message)
        self.code = code
        self.cause = cause


def wrap_error(
    error: BaseException,
    code: CrossCryptoErrorCode,
    message: str,
) -> CrossCryptoError:
    if isinstance(error, CrossCryptoError):
        return error
    return CrossCryptoError(code, message, cause=error)
