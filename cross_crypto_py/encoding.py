from __future__ import annotations

import base64
import json
import re
from typing import Any, Mapping

from .errors import CrossCryptoError

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value) or "=" in value:
        raise CrossCryptoError(
            "invalid_encoding", "Base64URL debe ser canónico y sin padding."
        )
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    try:
        decoded = base64.b64decode(
            value.replace("-", "+").replace("_", "/") + padding,
            validate=True,
        )
    except Exception as exc:
        raise CrossCryptoError("invalid_encoding", "Base64URL inválido.", cause=exc) from exc
    if b64url_encode(decoded) != value:
        raise CrossCryptoError(
            "invalid_encoding", "Base64URL no está en representación canónica."
        )
    return decoded



def assert_key_id(value: Any, field_name: str = "kid") -> str:
    if not isinstance(value, str):
        raise CrossCryptoError("invalid_format", f"{field_name} inválido.")
    try:
        decoded = b64url_decode(value)
    except CrossCryptoError as exc:
        raise CrossCryptoError(
            "invalid_format", f"{field_name} inválido.", cause=exc
        ) from exc
    if len(decoded) != 32:
        raise CrossCryptoError("invalid_format", f"{field_name} inválido.")
    return value

def encode_protected_header(header: Mapping[str, Any]) -> str:
    try:
        raw = json.dumps(
            dict(header),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CrossCryptoError(
            "invalid_format", "Protected header no es JSON válido.", cause=exc
        ) from exc
    if len(raw) > 8192:
        raise CrossCryptoError("invalid_format", "Protected header excede 8 KiB.")
    return b64url_encode(raw)


def decode_protected_header(value: str) -> dict[str, Any]:
    raw = b64url_decode(value)
    if len(raw) > 8192:
        raise CrossCryptoError("invalid_format", "Protected header excede 8 KiB.")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrossCryptoError(
            "invalid_format", "Protected header no contiene JSON UTF-8 válido.", cause=exc
        ) from exc
    if not isinstance(parsed, dict):
        raise CrossCryptoError(
            "invalid_format", "Protected header debe ser un objeto JSON."
        )
    return parsed


def assert_only_keys(
    value: Mapping[str, Any], allowed: set[str], context: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise CrossCryptoError(
            "invalid_format",
            f"{context} contiene campos no soportados: {', '.join(unknown)}.",
        )


def assert_encoded_size(encoded: str, max_decoded_bytes: int, field_name: str) -> None:
    if not isinstance(max_decoded_bytes, int) or isinstance(max_decoded_bytes, bool) or max_decoded_bytes < 0:
        raise CrossCryptoError("invalid_format", "Límite de tamaño inválido.")
    max_encoded = ((max_decoded_bytes * 4 + 2) // 3) + 4
    if len(encoded) > max_encoded:
        raise CrossCryptoError(
            "payload_too_large", f"{field_name} excede el límite permitido."
        )


def normalize_bytes(value: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise CrossCryptoError("invalid_format", "Se esperaba bytes o string.")
