from __future__ import annotations

import json
import math
from typing import Any, Optional

from .errors import CrossCryptoError
from .jwe import decrypt_bytes, encrypt_bytes
from .jws import sign_bytes, verify_bytes
from .types import JweEnvelope, JwsEnvelope

_JSON_CTY = "application/json"
_TEXT_CTY = "text/plain; charset=utf-8"
_JSON_MAX_DEPTH = 64
_JSON_MAX_NODES = 100_000
_JS_SAFE_INTEGER = 9_007_199_254_740_991


def _validate_json_value(value: Any) -> None:
    """Validate the portable JSON domain shared with JavaScript.

    Cross-Crypto JSON deliberately rejects values that JSON encoders can silently
    coerce or that cannot round-trip safely through JavaScript's Number/String
    model. This keeps Python and browser semantics aligned.
    """

    nodes = 0

    def visit(current: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _JSON_MAX_NODES:
            raise CrossCryptoError(
                "payload_too_large",
                f"JSON excede {_JSON_MAX_NODES} nodos.",
            )
        if depth > _JSON_MAX_DEPTH:
            raise CrossCryptoError(
                "invalid_format",
                f"JSON excede profundidad máxima {_JSON_MAX_DEPTH}.",
            )

        if current is None or isinstance(current, bool):
            return

        if isinstance(current, int):
            if abs(current) > _JS_SAFE_INTEGER:
                raise CrossCryptoError(
                    "invalid_format",
                    "Entero JSON fuera del rango seguro interoperable con JavaScript.",
                )
            return

        if isinstance(current, float):
            if not math.isfinite(current):
                raise CrossCryptoError(
                    "invalid_format",
                    "JSON no permite NaN ni Infinity.",
                )
            if current.is_integer() and abs(current) > _JS_SAFE_INTEGER:
                raise CrossCryptoError(
                    "invalid_format",
                    "Número JSON entero fuera del rango seguro interoperable con JavaScript.",
                )
            return

        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise CrossCryptoError(
                    "invalid_format",
                    "String JSON contiene un surrogate Unicode aislado.",
                    cause=exc,
                ) from exc
            return

        if type(current) is list:
            for item in current:
                visit(item, depth + 1)
            return

        if type(current) is dict:
            for key, item in current.items():
                if not isinstance(key, str):
                    raise CrossCryptoError(
                        "invalid_format",
                        "Todas las claves de objetos JSON deben ser strings.",
                    )
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise CrossCryptoError(
                        "invalid_format",
                        "Clave JSON contiene un surrogate Unicode aislado.",
                        cause=exc,
                    ) from exc
                visit(item, depth + 1)
            return

        raise CrossCryptoError(
            "invalid_format",
            f"Tipo no permitido en JSON interoperable: {type(current).__name__}.",
        )

    visit(value, 0)


def _json_bytes(value: Any) -> bytes:
    _validate_json_value(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CrossCryptoError("invalid_format", "Valor JSON inválido.", cause=exc) from exc


def _parse_json(data: bytes) -> Any:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrossCryptoError("invalid_format", "Payload JSON inválido.", cause=exc) from exc
    _validate_json_value(value)
    return value


def encrypt_json(
    value: Any,
    public_key_pem: str | bytes,
    *,
    key_id: Optional[str] = None,
    aad: Optional[bytes | str] = None,
) -> JweEnvelope:
    return encrypt_bytes(
        _json_bytes(value),
        public_key_pem,
        key_id=key_id,
        content_type=_JSON_CTY,
        aad=aad,
    )


def decrypt_json(
    envelope: JweEnvelope | dict[str, Any],
    private_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    expected_aad: Optional[bytes | str] = None,
    max_payload_bytes: int = 64 * 1024 * 1024,
) -> Any:
    return _parse_json(
        decrypt_bytes(
            envelope,
            private_key_pem,
            expected_key_id=expected_key_id,
            expected_content_type=_JSON_CTY,
            expected_aad=expected_aad,
            max_payload_bytes=max_payload_bytes,
        )["plaintext"]
    )


def encrypt_text(
    value: str,
    public_key_pem: str | bytes,
    *,
    key_id: Optional[str] = None,
    aad: Optional[bytes | str] = None,
) -> JweEnvelope:
    if not isinstance(value, str):
        raise CrossCryptoError("invalid_format", "value debe ser str.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CrossCryptoError(
            "invalid_format",
            "Texto contiene un surrogate Unicode aislado.",
            cause=exc,
        ) from exc
    return encrypt_bytes(
        encoded,
        public_key_pem,
        key_id=key_id,
        content_type=_TEXT_CTY,
        aad=aad,
    )


def decrypt_text(
    envelope: JweEnvelope | dict[str, Any],
    private_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    expected_aad: Optional[bytes | str] = None,
    max_payload_bytes: int = 64 * 1024 * 1024,
) -> str:
    data = decrypt_bytes(
        envelope,
        private_key_pem,
        expected_key_id=expected_key_id,
        expected_content_type=_TEXT_CTY,
        expected_aad=expected_aad,
        max_payload_bytes=max_payload_bytes,
    )["plaintext"]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CrossCryptoError("invalid_encoding", "Payload de texto no es UTF-8.", cause=exc) from exc


def sign_json(
    value: Any,
    private_key_pem: str | bytes,
    *,
    key_id: str,
    signed_at: Optional[int] = None,
    expires_at: Optional[int] = None,
) -> JwsEnvelope:
    return sign_bytes(
        _json_bytes(value),
        private_key_pem,
        key_id=key_id,
        signed_at=signed_at,
        expires_at=expires_at,
        content_type=_JSON_CTY,
    )


def verify_json(
    envelope: JwsEnvelope | dict[str, Any],
    public_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    max_age_seconds: Optional[int] = None,
    now: Optional[int] = None,
    future_skew_seconds: int = 30,
    max_payload_bytes: int = 64 * 1024 * 1024,
) -> Any:
    data = verify_bytes(
        envelope,
        public_key_pem,
        expected_key_id=expected_key_id,
        expected_content_type=_JSON_CTY,
        max_age_seconds=max_age_seconds,
        now=now,
        future_skew_seconds=future_skew_seconds,
        max_payload_bytes=max_payload_bytes,
    )["payload"]
    return _parse_json(data)


def sign_text(
    value: str,
    private_key_pem: str | bytes,
    *,
    key_id: str,
    signed_at: Optional[int] = None,
    expires_at: Optional[int] = None,
) -> JwsEnvelope:
    if not isinstance(value, str):
        raise CrossCryptoError("invalid_format", "value debe ser str.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CrossCryptoError(
            "invalid_format",
            "Texto contiene un surrogate Unicode aislado.",
            cause=exc,
        ) from exc
    return sign_bytes(
        encoded,
        private_key_pem,
        key_id=key_id,
        signed_at=signed_at,
        expires_at=expires_at,
        content_type=_TEXT_CTY,
    )


def verify_text(
    envelope: JwsEnvelope | dict[str, Any],
    public_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    max_age_seconds: Optional[int] = None,
    now: Optional[int] = None,
    future_skew_seconds: int = 30,
    max_payload_bytes: int = 64 * 1024 * 1024,
) -> str:
    data = verify_bytes(
        envelope,
        public_key_pem,
        expected_key_id=expected_key_id,
        expected_content_type=_TEXT_CTY,
        max_age_seconds=max_age_seconds,
        now=now,
        future_skew_seconds=future_skew_seconds,
        max_payload_bytes=max_payload_bytes,
    )["payload"]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CrossCryptoError("invalid_encoding", "Payload de texto no es UTF-8.", cause=exc) from exc
