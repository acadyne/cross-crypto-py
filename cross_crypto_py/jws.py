from __future__ import annotations

import time
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature

from .encoding import (
    assert_encoded_size,
    assert_key_id,
    assert_only_keys,
    b64url_decode,
    b64url_encode,
    decode_protected_header,
    encode_protected_header,
)
from .errors import CrossCryptoError, wrap_error
from .keys import key_id_from_public_key, load_ed25519_private_key, load_ed25519_public_key
from .types import (
    JWS_ALG,
    JWS_TYP,
    PROTOCOL_VERSION,
    JwsEnvelope,
    JwsProtectedHeader,
    VerifyResult,
)

_DEFAULT_MAX_PAYLOAD = 64 * 1024 * 1024
_SIGNATURE_BYTES = 64
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _signing_input(protected_value: str, payload_value: str) -> bytes:
    return f"{protected_value}.{payload_value}".encode("ascii")


def _assert_envelope(envelope: Any) -> JwsEnvelope:
    if not isinstance(envelope, dict):
        raise CrossCryptoError("invalid_format", "JWS debe ser un objeto.")
    assert_only_keys(envelope, {"protected", "payload", "signature"}, "JWS")
    for name in ("protected", "payload", "signature"):
        if not isinstance(envelope.get(name), str):
            raise CrossCryptoError("invalid_format", f"JWS.{name} debe ser string.")
    return envelope  # type: ignore[return-value]


def _parse_protected(value: str) -> JwsProtectedHeader:
    parsed = decode_protected_header(value)
    assert_only_keys(parsed, {"alg", "ccv", "typ", "kid", "iat", "exp", "cty"}, "JWS protected header")
    if parsed.get("alg") != JWS_ALG:
        raise CrossCryptoError("unsupported_algorithm", "JWS debe usar EdDSA.")
    if parsed.get("ccv") != PROTOCOL_VERSION:
        raise CrossCryptoError(
            "unsupported_version",
            f"Versión Cross-Crypto no soportada: {parsed.get('ccv')!r}.",
        )
    if parsed.get("typ") != JWS_TYP:
        raise CrossCryptoError("invalid_format", "JWS typ inválido.")

    kid = parsed.get("kid")
    iat = parsed.get("iat")
    exp = parsed.get("exp")
    cty = parsed.get("cty")

    assert_key_id(kid, "JWS kid")
    if (
        not isinstance(iat, int)
        or isinstance(iat, bool)
        or not 0 <= iat <= _MAX_SAFE_INTEGER
    ):
        raise CrossCryptoError("invalid_format", "JWS iat inválido.")
    if exp is not None and (
        not isinstance(exp, int)
        or isinstance(exp, bool)
        or exp < iat
        or exp > _MAX_SAFE_INTEGER
    ):
        raise CrossCryptoError("invalid_format", "JWS exp inválido.")
    if cty is not None and (not isinstance(cty, str) or not 1 <= len(cty) <= 256):
        raise CrossCryptoError("invalid_format", "JWS cty inválido.")

    return parsed  # type: ignore[return-value]


def sign_bytes(
    payload: bytes | bytearray | memoryview,
    private_key_pem: str | bytes,
    *,
    key_id: str,
    signed_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    content_type: Optional[str] = None,
) -> JwsEnvelope:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise CrossCryptoError("invalid_format", "payload debe ser bytes.")
    assert_key_id(key_id, "sign_bytes key_id")
    if content_type is not None and (
        not isinstance(content_type, str) or not 1 <= len(content_type) <= 256
    ):
        raise CrossCryptoError("invalid_format", "content_type inválido.")

    iat = int(time.time()) if signed_at is None else signed_at
    if (
        not isinstance(iat, int)
        or isinstance(iat, bool)
        or not 0 <= iat <= _MAX_SAFE_INTEGER
    ):
        raise CrossCryptoError("invalid_format", "signed_at inválido.")
    if expires_at is not None and (
        not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at < iat
        or expires_at > _MAX_SAFE_INTEGER
    ):
        raise CrossCryptoError("invalid_format", "expires_at inválido.")

    try:
        header: JwsProtectedHeader = {
            "alg": JWS_ALG,
            "ccv": PROTOCOL_VERSION,
            "typ": JWS_TYP,
            "kid": key_id,
            "iat": iat,
        }
        if expires_at is not None:
            header["exp"] = expires_at
        if content_type:
            header["cty"] = content_type

        protected_value = encode_protected_header(header)
        payload_value = b64url_encode(bytes(payload))
        private_key = load_ed25519_private_key(private_key_pem)
        signature = private_key.sign(_signing_input(protected_value, payload_value))

        return {
            "protected": protected_value,
            "payload": payload_value,
            "signature": b64url_encode(signature),
        }
    except Exception as exc:
        raise wrap_error(exc, "signature_invalid", "No se pudo firmar el payload.") from exc


def verify_bytes(
    envelope: JwsEnvelope | dict[str, Any],
    public_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    expected_content_type: Optional[str] = None,
    max_age_seconds: Optional[int] = None,
    now: Optional[int] = None,
    future_skew_seconds: int = 30,
    max_payload_bytes: int = _DEFAULT_MAX_PAYLOAD,
) -> VerifyResult:
    try:
        normalized = _assert_envelope(envelope)
        header = _parse_protected(normalized["protected"])

        assert_encoded_size(normalized["payload"], max_payload_bytes, "payload")
        assert_encoded_size(normalized["signature"], _SIGNATURE_BYTES, "signature")
        payload = b64url_decode(normalized["payload"])
        signature = b64url_decode(normalized["signature"])
        if len(signature) != _SIGNATURE_BYTES:
            raise CrossCryptoError("invalid_format", "Firma Ed25519 debe tener 64 bytes.")

        # El header se parsea antes por formato/algoritmo, pero sus claims
        # no se consideran confiables hasta autenticar la firma.
        public_key = load_ed25519_public_key(public_key_pem)
        try:
            public_key.verify(
                signature,
                _signing_input(normalized["protected"], normalized["payload"]),
            )
        except InvalidSignature as exc:
            raise CrossCryptoError(
                "signature_invalid", "Firma Ed25519 inválida.", cause=exc
            ) from exc

        actual_key_id = key_id_from_public_key(public_key_pem)
        if header["kid"] != actual_key_id:
            raise CrossCryptoError(
                "key_mismatch",
                "kid firmado no corresponde a la clave pública Ed25519.",
            )
        if expected_key_id is not None:
            assert_key_id(expected_key_id, "expected_key_id")
            if header["kid"] != expected_key_id:
                raise CrossCryptoError("key_mismatch", "kid no coincide con el esperado.")
        if expected_content_type is not None and header.get("cty") != expected_content_type:
            raise CrossCryptoError("invalid_format", "cty no coincide con el esperado.")

        current = int(time.time()) if now is None else now
        if (
            not isinstance(current, int)
            or isinstance(current, bool)
            or not 0 <= current <= _MAX_SAFE_INTEGER
            or not isinstance(future_skew_seconds, int)
            or isinstance(future_skew_seconds, bool)
            or not 0 <= future_skew_seconds <= _MAX_SAFE_INTEGER
        ):
            raise CrossCryptoError("invalid_format", "Política temporal inválida.")

        if max_age_seconds is not None and (
            not isinstance(max_age_seconds, int)
            or isinstance(max_age_seconds, bool)
            or not 0 <= max_age_seconds <= _MAX_SAFE_INTEGER
        ):
            raise CrossCryptoError("invalid_format", "max_age_seconds inválido.")

        if (
            header["iat"] > current
            and header["iat"] - current > future_skew_seconds
        ):
            raise CrossCryptoError("not_yet_valid", "La firma está fechada en el futuro.")
        if max_age_seconds is not None and current - header["iat"] > max_age_seconds:
            raise CrossCryptoError("expired", "La firma excede max_age_seconds.")
        if (
            "exp" in header
            and current > header["exp"]
            and current - header["exp"] > future_skew_seconds
        ):
            raise CrossCryptoError("expired", "La firma ha expirado.")

        return {
            "payload": payload,
            "protected_header": header,
        }
    except Exception as exc:
        raise wrap_error(exc, "signature_invalid", "No se pudo verificar el JWS.") from exc


def is_valid_signature(
    envelope: JwsEnvelope | dict[str, Any],
    public_key_pem: str | bytes,
    **kwargs: Any,
) -> bool:
    try:
        verify_bytes(envelope, public_key_pem, **kwargs)
        return True
    except CrossCryptoError:
        return False


def read_jws_protected_header(envelope: JwsEnvelope | dict[str, Any]) -> JwsProtectedHeader:
    normalized = _assert_envelope(envelope)
    return _parse_protected(normalized["protected"])
