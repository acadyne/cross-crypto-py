from __future__ import annotations

import io
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import assert_key_id, assert_only_keys, b64url_decode, b64url_encode
from .errors import CrossCryptoError, wrap_error
from .keys import key_id_from_public_key, load_rsa_private_key, load_rsa_public_key
from .types import CcencDecryptResult, CcencHeader, JWE_ALG, JWE_ENC, PROTOCOL_VERSION

MAGIC = b"CCRYPT3\n"
TYPE_DATA = 0x01
TYPE_FINAL = 0xFF
FINAL_INDEX = 0xFFFFFFFF
TAG_BYTES = 16
CEK_BYTES = 32
NONCE_PREFIX_BYTES = 8
HEADER_MAX = 64 * 1024
MIN_CHUNK = 64 * 1024
MAX_CHUNK = 16 * 1024 * 1024
DEFAULT_CHUNK = 1024 * 1024
DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024 * 1024


def _u32(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise CrossCryptoError("invalid_format", "uint32 fuera de rango.")
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise CrossCryptoError("invalid_format", "uint64 fuera de rango.")
    return struct.pack(">Q", value)


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise CrossCryptoError("invalid_format", "CCENC truncado.")
    return data


def _validate_chunk_size(value: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < MIN_CHUNK
        or value > MAX_CHUNK
    ):
        raise CrossCryptoError(
            "invalid_format",
            f"chunk_size debe estar entre {MIN_CHUNK} y {MAX_CHUNK} bytes.",
        )
    return value


def _validate_name(value: Optional[str]) -> None:
    if value is None:
        return
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
    ):
        raise CrossCryptoError(
            "invalid_format", "CCENC name debe ser un basename seguro."
        )


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + _u32(index)


def _encode_header(header: dict[str, Any]) -> bytes:
    try:
        raw = json.dumps(
            header, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CrossCryptoError("invalid_format", "CCENC header JSON inválido.", cause=exc) from exc
    if not 1 <= len(raw) <= HEADER_MAX:
        raise CrossCryptoError("invalid_format", "CCENC header excede el límite.")
    return raw


def _decode_header(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CrossCryptoError("invalid_format", "CCENC header JSON inválido.", cause=exc) from exc
    if not isinstance(value, dict):
        raise CrossCryptoError("invalid_format", "CCENC header debe ser objeto.")
    assert_only_keys(
        value,
        {
            "format",
            "ccv",
            "typ",
            "alg",
            "enc",
            "kid",
            "chunkSize",
            "noncePrefix",
            "encryptedKey",
            "name",
            "cty",
        },
        "CCENC header",
    )
    if value.get("format") != "ccenc" or value.get("ccv") != PROTOCOL_VERSION or value.get("typ") != "cross-crypto+ccenc":
        raise CrossCryptoError("unsupported_version", "CCENC versión/tipo no soportado.")
    if value.get("alg") != JWE_ALG or value.get("enc") != JWE_ENC:
        raise CrossCryptoError(
            "unsupported_algorithm", "CCENC debe usar RSA-OAEP-256 y A256GCM."
        )
    assert_key_id(value.get("kid"), "CCENC kid")
    _validate_chunk_size(value.get("chunkSize"))
    nonce_prefix = value.get("noncePrefix")
    encrypted_key = value.get("encryptedKey")
    if not isinstance(nonce_prefix, str) or len(b64url_decode(nonce_prefix)) != NONCE_PREFIX_BYTES:
        raise CrossCryptoError("invalid_format", "CCENC noncePrefix debe tener 8 bytes.")
    if not isinstance(encrypted_key, str):
        raise CrossCryptoError("invalid_format", "CCENC encryptedKey inválido.")
    wrapped = b64url_decode(encrypted_key)
    if not wrapped or len(wrapped) > 1024:
        raise CrossCryptoError("invalid_format", "CCENC encryptedKey inválido.")
    _validate_name(value.get("name"))
    cty = value.get("cty")
    if cty is not None and (
        not isinstance(cty, str) or not 1 <= len(cty) <= 256
    ):
        raise CrossCryptoError("invalid_format", "CCENC cty inválido.")
    return value


def _build_header(
    public_key_pem: str | bytes,
    *,
    key_id: Optional[str],
    chunk_size: int,
    nonce_prefix: bytes,
    encrypted_key: bytes,
    name: Optional[str],
    content_type: Optional[str],
) -> tuple[dict[str, Any], bytes]:
    _validate_name(name)
    if content_type is not None and (
        not isinstance(content_type, str) or not 1 <= len(content_type) <= 256
    ):
        raise CrossCryptoError("invalid_format", "content_type inválido.")
    derived_kid = key_id_from_public_key(public_key_pem)
    if key_id is not None and key_id != derived_kid:
        raise CrossCryptoError(
            "key_mismatch",
            "key_id no corresponde a la clave pública RSA suministrada.",
        )
    kid = derived_kid
    header: dict[str, Any] = {
        "format": "ccenc",
        "ccv": PROTOCOL_VERSION,
        "typ": "cross-crypto+ccenc",
        "alg": JWE_ALG,
        "enc": JWE_ENC,
        "kid": kid,
        "chunkSize": chunk_size,
        "noncePrefix": b64url_encode(nonce_prefix),
        "encryptedKey": b64url_encode(encrypted_key),
    }
    if name is not None:
        header["name"] = name
    if content_type is not None:
        header["cty"] = content_type
    return header, _encode_header(header)


def _wrap_cek(public_key_pem: str | bytes, cek: bytes) -> bytes:
    key = load_rsa_public_key(public_key_pem)
    try:
        return key.encrypt(
            cek,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise CrossCryptoError(
            "authentication_failed", "No se pudo cifrar la CEK CCENC.", cause=exc
        ) from exc


def _unwrap_cek(private_key_pem: str | bytes, encrypted_key: bytes) -> bytes:
    key = load_rsa_private_key(private_key_pem)
    try:
        cek = key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise CrossCryptoError(
            "authentication_failed", "No se pudo desenvolver la CEK CCENC.", cause=exc
        ) from exc
    if len(cek) != CEK_BYTES:
        raise CrossCryptoError("authentication_failed", "CEK CCENC inválida.")
    return cek


def _encrypt_stream(
    source: BinaryIO,
    dest: BinaryIO,
    public_key_pem: str | bytes,
    *,
    key_id: Optional[str] = None,
    chunk_size: int = DEFAULT_CHUNK,
    name: Optional[str] = None,
    content_type: Optional[str] = None,
) -> dict[str, Any]:
    chunk_size = _validate_chunk_size(chunk_size)
    cek = os.urandom(CEK_BYTES)
    nonce_prefix = os.urandom(NONCE_PREFIX_BYTES)
    encrypted_key = _wrap_cek(public_key_pem, cek)
    header, header_bytes = _build_header(
        public_key_pem,
        key_id=key_id,
        chunk_size=chunk_size,
        nonce_prefix=nonce_prefix,
        encrypted_key=encrypted_key,
        name=name,
        content_type=content_type,
    )

    prefix = MAGIC + _u32(len(header_bytes)) + header_bytes
    dest.write(prefix)
    aes = AESGCM(cek)

    index = 0
    total = 0
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            break
        if index >= FINAL_INDEX:
            raise CrossCryptoError("payload_too_large", "CCENC excede el máximo de chunks.")
        meta = bytes([TYPE_DATA]) + _u32(index) + _u32(len(chunk))
        combined = aes.encrypt(_nonce(nonce_prefix, index), chunk, prefix + meta)
        ciphertext, tag = combined[:-TAG_BYTES], combined[-TAG_BYTES:]
        dest.write(meta)
        dest.write(ciphertext)
        dest.write(tag)
        total += len(chunk)
        index += 1

    final_meta = bytes([TYPE_FINAL]) + _u32(index) + _u64(total)
    final = aes.encrypt(_nonce(nonce_prefix, FINAL_INDEX), b"", prefix + final_meta)
    if len(final) != TAG_BYTES:
        raise CrossCryptoError("authentication_failed", "Final CCENC inválido.")
    dest.write(final_meta)
    dest.write(final)
    return header


def _parse_prefix(source: BinaryIO) -> tuple[dict[str, Any], bytes, bytes]:
    magic = _read_exact(source, len(MAGIC))
    if magic != MAGIC:
        raise CrossCryptoError("invalid_format", "CCENC magic inválido.")
    header_len = struct.unpack(">I", _read_exact(source, 4))[0]
    if not 1 <= header_len <= HEADER_MAX:
        raise CrossCryptoError("invalid_format", "CCENC header_len inválido.")
    header_bytes = _read_exact(source, header_len)
    header = _decode_header(header_bytes)
    prefix = MAGIC + _u32(header_len) + header_bytes
    nonce_prefix = b64url_decode(header["noncePrefix"])
    return header, prefix, nonce_prefix


def _decrypt_stream(
    source: BinaryIO,
    dest: BinaryIO,
    private_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    expected_name: Optional[str] = None,
    expected_content_type: Optional[str] = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
) -> dict[str, Any]:
    header, prefix, nonce_prefix = _parse_prefix(source)
    if expected_key_id is not None:
        assert_key_id(expected_key_id, "expected_key_id")
        if header["kid"] != expected_key_id:
            raise CrossCryptoError("key_mismatch", "CCENC kid no coincide.")
    if expected_name is not None and header.get("name") != expected_name:
        raise CrossCryptoError("invalid_format", "CCENC name no coincide.")
    if expected_content_type is not None and header.get("cty") != expected_content_type:
        raise CrossCryptoError("invalid_format", "CCENC cty no coincide.")
    if (
        not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or max_output_bytes < 0
    ):
        raise CrossCryptoError("invalid_format", "max_output_bytes inválido.")

    cek = _unwrap_cek(private_key_pem, b64url_decode(header["encryptedKey"]))
    aes = AESGCM(cek)
    expected_index = 0
    total = 0

    while True:
        raw_type = source.read(1)
        if not raw_type:
            raise CrossCryptoError(
                "authentication_failed", "CCENC no contiene marcador final."
            )
        record_type = raw_type[0]

        if record_type == TYPE_DATA:
            meta_tail = _read_exact(source, 8)
            meta = raw_type + meta_tail
            index, length = struct.unpack(">II", meta_tail)
            if index == FINAL_INDEX or index != expected_index:
                raise CrossCryptoError("invalid_format", "CCENC chunks fuera de secuencia.")
            if length > header["chunkSize"]:
                raise CrossCryptoError("invalid_format", "CCENC chunk excede chunkSize.")
            if total + length > max_output_bytes:
                raise CrossCryptoError("payload_too_large", "CCENC excede max_output_bytes.")
            ciphertext = _read_exact(source, length)
            tag = _read_exact(source, TAG_BYTES)
            try:
                plaintext = aes.decrypt(
                    _nonce(nonce_prefix, index),
                    ciphertext + tag,
                    prefix + meta,
                )
            except Exception as exc:
                raise CrossCryptoError(
                    "authentication_failed",
                    "Autenticación de chunk CCENC fallida.",
                    cause=exc,
                ) from exc
            if len(plaintext) != length:
                raise CrossCryptoError(
                    "authentication_failed", "CCENC longitud autenticada inválida."
                )
            dest.write(plaintext)
            total += length
            expected_index += 1
            continue

        if record_type == TYPE_FINAL:
            final_tail = _read_exact(source, 12)
            final_meta = raw_type + final_tail
            chunk_count, total_size = struct.unpack(">IQ", final_tail)
            tag = _read_exact(source, TAG_BYTES)
            if chunk_count != expected_index or total_size != total:
                raise CrossCryptoError(
                    "authentication_failed",
                    "CCENC marcador final no coincide con los datos.",
                )
            try:
                plaintext = aes.decrypt(
                    _nonce(nonce_prefix, FINAL_INDEX),
                    tag,
                    prefix + final_meta,
                )
            except Exception as exc:
                raise CrossCryptoError(
                    "authentication_failed",
                    "Autenticación final CCENC fallida.",
                    cause=exc,
                ) from exc
            if plaintext != b"":
                raise CrossCryptoError("authentication_failed", "Final CCENC inválido.")
            if source.read(1) != b"":
                raise CrossCryptoError(
                    "invalid_format", "CCENC contiene datos tras el final."
                )
            return header

        raise CrossCryptoError("invalid_format", "CCENC record type inválido.")


def encrypt_ccenc_bytes(
    data: bytes | bytearray | memoryview,
    public_key_pem: str | bytes,
    *,
    key_id: Optional[str] = None,
    chunk_size: int = DEFAULT_CHUNK,
    name: Optional[str] = None,
    content_type: Optional[str] = None,
) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CrossCryptoError("invalid_format", "data debe ser bytes.")
    source = io.BytesIO(bytes(data))
    dest = io.BytesIO()
    _encrypt_stream(
        source,
        dest,
        public_key_pem,
        key_id=key_id,
        chunk_size=chunk_size,
        name=name,
        content_type=content_type,
    )
    return dest.getvalue()


def decrypt_ccenc_bytes(
    data: bytes | bytearray | memoryview,
    private_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    expected_name: Optional[str] = None,
    expected_content_type: Optional[str] = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
) -> CcencDecryptResult:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CrossCryptoError("invalid_format", "data debe ser bytes.")
    source = io.BytesIO(bytes(data))
    dest = io.BytesIO()
    header = _decrypt_stream(
        source,
        dest,
        private_key_pem,
        expected_key_id=expected_key_id,
        expected_name=expected_name,
        expected_content_type=expected_content_type,
        max_output_bytes=max_output_bytes,
    )
    return {
        "plaintext": dest.getvalue(),
        "header": header,
    }


def encrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    public_key_pem: str | bytes,
    *,
    key_id: Optional[str] = None,
    chunk_size: int = DEFAULT_CHUNK,
    content_type: Optional[str] = None,
) -> CcencHeader:
    source_path = Path(input_path)
    if not source_path.is_file():
        raise CrossCryptoError("invalid_format", f"Archivo de entrada no existe: {source_path}")
    dest_path = Path(output_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path: Optional[Path] = None
    try:
        with source_path.open("rb") as source:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                delete=False,
                dir=dest_path.parent,
                prefix=f".{dest_path.name}.",
                suffix=".tmp",
            ) as temp:
                temp_path = Path(temp.name)
                header = _encrypt_stream(
                    source,
                    temp,
                    public_key_pem,
                    key_id=key_id,
                    chunk_size=chunk_size,
                    name=source_path.name,
                    content_type=content_type,
                )
                temp.flush()
                os.fsync(temp.fileno())
        os.replace(temp_path, dest_path)
        temp_path = None
        return header
    except Exception as exc:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
        raise wrap_error(exc, "authentication_failed", "No se pudo cifrar el archivo CCENC.") from exc


def decrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    private_key_pem: str | bytes,
    *,
    expected_key_id: Optional[str] = None,
    expected_name: Optional[str] = None,
    expected_content_type: Optional[str] = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
) -> CcencHeader:
    source_path = Path(input_path)
    if not source_path.is_file():
        raise CrossCryptoError("invalid_format", f"Archivo CCENC no existe: {source_path}")
    dest_path = Path(output_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path: Optional[Path] = None
    try:
        with source_path.open("rb") as source:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                delete=False,
                dir=dest_path.parent,
                prefix=f".{dest_path.name}.",
                suffix=".tmp",
            ) as temp:
                temp_path = Path(temp.name)
                header = _decrypt_stream(
                    source,
                    temp,
                    private_key_pem,
                    expected_key_id=expected_key_id,
                    expected_name=expected_name,
                    expected_content_type=expected_content_type,
                    max_output_bytes=max_output_bytes,
                )
                temp.flush()
                os.fsync(temp.fileno())
        os.replace(temp_path, dest_path)
        temp_path = None
        return header
    except Exception as exc:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
        raise wrap_error(exc, "authentication_failed", "No se pudo descifrar el archivo CCENC.") from exc


def read_ccenc_header(data: bytes | bytearray | memoryview) -> CcencHeader:
    """Lee el header no verificado de un CCENC en memoria.

    Úsalo únicamente para selección de clave/inspección. La autenticidad del
    header sólo queda establecida después de decrypt_ccenc_bytes/decrypt_file.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CrossCryptoError("invalid_format", "data debe ser bytes.")
    source = io.BytesIO(bytes(data))
    header, _, _ = _parse_prefix(source)
    return header


def read_ccenc_file_header(path: str | os.PathLike[str]) -> CcencHeader:
    """Lee el header no verificado de un archivo CCENC."""
    with Path(path).open("rb") as source:
        header, _, _ = _parse_prefix(source)
    return header
