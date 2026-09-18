from __future__ import annotations

import hmac
import os
from typing import Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import (
    assert_encoded_size,
    assert_key_id,
    assert_only_keys,
    b64url_decode,
    b64url_encode,
    decode_protected_header,
    encode_protected_header,
    normalize_bytes,
)
from .errors import CrossCryptoError, wrap_error
from .keys import key_id_from_public_key, load_rsa_private_key, load_rsa_public_key
from .types import (
    JWE_ALG,
    JWE_ENC,
    JWE_TYP,
    PROTOCOL_VERSION,
    DecryptResult,
    JweEnvelope,
    JweProtectedHeader,
)

_DEFAULT_MAX_PAYLOAD = 64 * 1024 * 1024
_MAX_AAD_BYTES = 64 * 1024
_IV_BYTES = 12
_TAG_BYTES = 16
_CEK_BYTES = 32


def _parse_protected(value: str) -> JweProtectedHeader:
    parsed = decode_protected_header(value)
    assert_only_keys(parsed, {"alg", "enc", "ccv", "typ", "kid", "cty"}, "JWE protected header")
    if parsed.get("alg") != JWE_ALG or parsed.get("enc") != JWE_ENC:
        raise CrossCryptoError(
            "unsupported_algorithm", "JWE debe usar RSA-OAEP-256 y A256GCM."
        )
    if parsed.get("ccv") != PROTOCOL_VERSION:
        raise CrossCryptoError(
            "unsupported_version",
            f"Versión Cross-Crypto no soportada: {parsed.get('ccv')!r}.",
        )
    if parsed.get("typ") != JWE_TYP:
        raise CrossCryptoError("invalid_format", "JWE typ inválido.")
    assert_key_id(parsed.get("kid"), "JWE kid")
    cty = parsed.get("cty")
    if cty is not None and (not isinstance(cty, str) or not 1 <= len(cty) <= 256):
        raise CrossCryptoError("invalid_format", "JWE cty inválido.")
    return parsed  # type: ignore[return-value]


def _assert_envelope(envelope: Any) -> JweEnvelope:
    if not isinstance(envelope, dict):
        raise CrossCryptoError("invalid_format", "JWE debe ser un objeto.")
    assert_only_keys(
        envelope,
        {"protected", "encrypted_key", "iv", "ciphertext", "tag", "aad"},
        "JWE",
    )
    for name in ("protected", "encrypted_key", "iv", "ciphertext", "tag"):
        if not isinstance(envelope.get(name), str):
            raise CrossCryptoError("invalid_format", f"JWE.{name} debe ser string.")
    if "aad" in envelope and not isinstance(envelope["aad"], str):
        raise CrossCryptoError("invalid_format", "JWE.aad debe ser string.")
    return envelope  # type: ignore[return-value]


def _gcm_aad(protected_value: str, encoded_aad: Optional[str]) -> bytes:
    text = protected_value if encoded_aad is None else f"{protected_value}.{encoded_aad}"
    return text.encode("ascii")


def encrypt_bytes(
    plaintext: bytes | bytearray | memoryview,
    public_key_pem: str | bytes,
    *,
    key_id: Optional[str] = None,
    content_type: Optional[str] = None,
    aad: Optional[bytes | bytearray | memoryview | str] = None,
) -> JweEnvelope:
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise CrossCryptoError("invalid_format", "plaintext debe ser bytes.")
    try:
        if content_type is not None and (
            not isinstance(content_type, str) or not 1 <= len(content_type) <= 256
        ):
            raise CrossCryptoError("invalid_format", "content_type inválido.")
        public_key = load_rsa_public_key(public_key_pem)
        derived_kid = key_id_from_public_key(public_key_pem)
        if key_id is not None and key_id != derived_kid:
            raise CrossCryptoError(
                "key_mismatch",
                "key_id no corresponde a la clave pública RSA suministrada.",
            )
        kid = derived_kid

        header: JweProtectedHeader = {
            "alg": JWE_ALG,
            "enc": JWE_ENC,
            "ccv": PROTOCOL_VERSION,
            "typ": JWE_TYP,
            "kid": kid,
        }
        if content_type:
            header["cty"] = content_type

        protected_value = encode_protected_header(header)
        external_aad = None if aad is None else normalize_bytes(aad)
        if external_aad is not None and len(external_aad) > _MAX_AAD_BYTES:
            raise CrossCryptoError("payload_too_large", "AAD excede 64 KiB.")
        encoded_aad = None if external_aad is None else b64url_encode(external_aad)

        cek = os.urandom(_CEK_BYTES)
        iv = os.urandom(_IV_BYTES)

        encrypted_key = public_key.encrypt(
            cek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        combined = AESGCM(cek).encrypt(
            iv,
            bytes(plaintext),
            _gcm_aad(protected_value, encoded_aad),
        )
        ciphertext, tag = combined[:-_TAG_BYTES], combined[-_TAG_BYTES:]

        result: JweEnvelope = {
            "protected": protected_value,
            "encrypted_key": b64url_encode(encrypted_key),
            "iv": b64url_encode(iv),
            "ciphertext": b64url_encode(ciphertext),
            "tag": b64url_encode(tag),
        }
        if encoded_aad is not None:
            result["aad"] = encoded_aad
        return result
    except Exception as exc:
        raise wrap_error(exc, "authentication_failed", "No se pudo cifrar el payload.") from exc


def decrypt_bytes(
    envelope: JweEnvelope | dict[str, Any],
    private_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    expected_content_type: Optional[str] = None,
    expected_aad: Optional[bytes | bytearray | memoryview | str] = None,
    max_payload_bytes: int = _DEFAULT_MAX_PAYLOAD,
) -> DecryptResult:
    try:
        normalized = _assert_envelope(envelope)
        header = _parse_protected(normalized["protected"])

        if expected_key_id is not None:
            assert_key_id(expected_key_id, "expected_key_id")
            if header["kid"] != expected_key_id:
                raise CrossCryptoError("key_mismatch", "kid no coincide con el esperado.")
        if expected_content_type is not None and header.get("cty") != expected_content_type:
            raise CrossCryptoError("invalid_format", "cty no coincide con el esperado.")

        assert_encoded_size(normalized["ciphertext"], max_payload_bytes, "ciphertext")
        assert_encoded_size(normalized["encrypted_key"], 1024, "encrypted_key")
        if "aad" in normalized:
            assert_encoded_size(normalized["aad"], _MAX_AAD_BYTES, "aad")

        encrypted_key = b64url_decode(normalized["encrypted_key"])
        iv = b64url_decode(normalized["iv"])
        ciphertext = b64url_decode(normalized["ciphertext"])
        tag = b64url_decode(normalized["tag"])
        aad = b64url_decode(normalized["aad"]) if "aad" in normalized else None

        if len(iv) != _IV_BYTES:
            raise CrossCryptoError("invalid_format", "JWE iv debe tener 12 bytes.")
        if len(tag) != _TAG_BYTES:
            raise CrossCryptoError("invalid_format", "JWE tag debe tener 16 bytes.")
        if not encrypted_key:
            raise CrossCryptoError("invalid_format", "JWE encrypted_key está vacío.")

        if expected_aad is not None:
            expected = normalize_bytes(expected_aad)
            if len(expected) > _MAX_AAD_BYTES:
                raise CrossCryptoError("payload_too_large", "expected_aad excede 64 KiB.")
            if aad is None or not hmac.compare_digest(expected, aad):
                raise CrossCryptoError("authentication_failed", "AAD no coincide.")

        private_key = load_rsa_private_key(private_key_pem)
        try:
            cek = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise CrossCryptoError(
                "authentication_failed", "No se pudo desenvolver la CEK.", cause=exc
            ) from exc

        if len(cek) != _CEK_BYTES:
            raise CrossCryptoError(
                "authentication_failed", "La CEK descifrada tiene longitud inválida."
            )

        try:
            plaintext = AESGCM(cek).decrypt(
                iv,
                ciphertext + tag,
                _gcm_aad(normalized["protected"], normalized.get("aad")),
            )
            result: DecryptResult = {
                "plaintext": plaintext,
                "protected_header": header,
            }
            if aad is not None:
                result["aad"] = aad
            return result
        except InvalidTag as exc:
            raise CrossCryptoError(
                "authentication_failed", "Autenticación AES-GCM fallida.", cause=exc
            ) from exc
    except Exception as exc:
        raise wrap_error(exc, "authentication_failed", "No se pudo descifrar el JWE.") from exc


def read_jwe_protected_header(envelope: JweEnvelope | dict[str, Any]) -> JweProtectedHeader:
    normalized = _assert_envelope(envelope)
    return _parse_protected(normalized["protected"])
