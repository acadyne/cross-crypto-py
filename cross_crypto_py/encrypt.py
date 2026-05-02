# cross_crypto_py/encrypt.py
from __future__ import annotations

import os
import json
import base64
import logging
import time
import struct
import tempfile
from typing import Any, Dict, Union, Optional, Tuple, cast, TypedDict

import dill
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss

logger = logging.getLogger(__name__)

__all__ = [
    "AES_KEY_SIZE",
    "AES_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "STREAM_ENVELOPE_MAGIC",
    "EncryptedMemory",
    "EncryptedStream",
    "loadPublicKey",
    "sign_dill_bytes",
    "encryptHybrid",
]

AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
GCM_TAG_SIZE = 16

STREAM_ENVELOPE_MAGIC = b"CCRYPT2\n"
STREAM_ENVELOPE_VERSION = 2

_SIG_ALG = "RSA-PSS"
_HASH_ALG = "SHA-256"


class EncryptedMemory(TypedDict, total=False):
    encryptedKey: str
    encryptedData: str
    nonce: str
    tag: str
    mode: str
    aad: str
    oaepHash: str
    signature: Dict[str, Any]


class EncryptedStream(TypedDict, total=False):
    encryptedKey: str
    nonce: str
    tag: str
    encryptedPath: str
    mode: str
    contentMode: str
    streamFormat: str
    aad: str
    oaepHash: str


def _b64encode_str(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _normalize_aad(aad: Optional[Union[bytes, str, Dict[str, Any]]]) -> Optional[bytes]:
    if aad is None:
        return None
    if isinstance(aad, bytes):
        return aad
    if isinstance(aad, str):
        return aad.encode("utf-8")
    return json.dumps(
        aad,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _resolve_oaep_hash(oaep_hash: str) -> str:
    resolved = str(oaep_hash or "sha256").lower()
    if resolved not in ("sha1", "sha256"):
        raise ValueError("oaep_hash debe ser 'sha1' o 'sha256'.")
    return resolved


def loadPublicKey(PUBLIC_KEY: Union[str, bytes]) -> RSA.RsaKey:
    """Carga clave pública RSA y valida longitud mínima >=2048."""
    try:
        key = RSA.import_key(PUBLIC_KEY)
        if key.size_in_bits() < 2048:
            raise ValueError("La clave pública debe tener al menos 2048 bits por seguridad.")
        if key.has_private():
            raise ValueError("La clave provista parece contener parte privada, no pública.")
        return key
    except Exception as e:
        logger.error("Error al cargar la clave pública: %s", e)
        raise


def _serialize_data(
    data: Union[Dict[str, Any], bytes, str],
    mode: str,
) -> Tuple[bytes, str]:
    selected_mode = mode.lower()

    if selected_mode == "json":
        if not isinstance(data, dict):
            raise TypeError("En modo 'json', los datos deben ser un diccionario.")
        payload = json.dumps(
            data,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return payload, "json"

    if selected_mode == "dill":
        payload = dill.dumps(data)
        return payload, "dill"

    if selected_mode == "binary":
        if isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray, memoryview)):
            payload = bytes(data)
        else:
            raise TypeError("En modo 'binary', los datos deben ser bytes/bytearray/memoryview o str.")
        return payload, "binary"

    raise ValueError(f"Modo de serialización no soportado: {mode}")


def _canonical_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_b64(data: bytes) -> str:
    h = SHA256.new(data)
    return base64.b64encode(h.digest()).decode("ascii")


def _load_private_key(
    PRIVATE_KEY: Union[str, bytes],
    passphrase: Optional[Union[str, bytes]] = None,
) -> RSA.RsaKey:
    if isinstance(passphrase, bytes):
        passphrase = passphrase.decode()

    key = RSA.import_key(PRIVATE_KEY, passphrase=passphrase)

    if key.size_in_bits() < 2048:
        raise ValueError("La clave privada debe tener al menos 2048 bits por seguridad.")
    if not key.has_private():
        raise ValueError("La clave provista no contiene parte privada válida.")

    return key


def sign_dill_bytes(
    payload: bytes,
    PRIVATE_KEY: Union[str, bytes],
    *,
    passphrase: Optional[Union[str, bytes]] = None,
    key_id: Optional[str] = None,
    prev_hash: Optional[str] = None,
) -> Dict[str, Any]:
    sk = _load_private_key(PRIVATE_KEY, passphrase=passphrase)

    fields: Dict[str, Any] = {
        "alg": _SIG_ALG,
        "hash_alg": _HASH_ALG,
        "size": len(payload),
        "hash_b64": _sha256_b64(payload),
        "ts": int(time.time()),
    }

    if key_id is not None:
        fields["key_id"] = key_id
    if prev_hash is not None:
        fields["prev_hash"] = prev_hash

    to_sign = _canonical_bytes(fields)
    msg_hash = SHA256.new(to_sign)

    signer = pss.new(sk, mask_func=lambda x, y: pss.MGF1(x, y, SHA256))
    sig_raw = signer.sign(cast(Any, msg_hash))

    fields["sig_b64"] = base64.b64encode(sig_raw).decode("ascii")
    return fields


def _write_stream_envelope(
    *,
    output_path: str,
    encrypted_key_b64: str,
    nonce_b64: str,
    tag_b64: str,
    oaep_hash: str,
    aad_present: bool,
    content_mode: str,
    ciphertext_path: str,
) -> None:
    header: Dict[str, Any] = {
        "version": STREAM_ENVELOPE_VERSION,
        "format": "cross-crypto-stream",
        "streamFormat": "envelope",
        "cipher": "AES-256-GCM",
        "keyWrap": "RSA-OAEP",
        "encryptedKey": encrypted_key_b64,
        "nonce": nonce_b64,
        "tag": tag_b64,
        "mode": "stream",
        "contentMode": content_mode,
        "aad": "present" if aad_present else "none",
        "oaepHash": oaep_hash,
    }

    header_bytes = json.dumps(
        header,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")

    if len(header_bytes) > 0xFFFFFFFF:
        raise ValueError("Header de stream demasiado grande.")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "wb") as out, open(ciphertext_path, "rb") as cipher_in:
        out.write(STREAM_ENVELOPE_MAGIC)
        out.write(struct.pack(">I", len(header_bytes)))
        out.write(header_bytes)

        for chunk in iter(lambda: cipher_in.read(1024 * 1024), b""):
            out.write(chunk)


def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: Union[str, bytes],
    mode: str = "json",
    stream: bool = False,
    output_path: Optional[str] = None,
    chunk_size: int = 64 * 1024,
    oaep_hash: str = "sha256",
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    *,
    signature: Optional[Dict[str, Any]] = None,
) -> Union[EncryptedMemory, EncryptedStream]:
    """
    Encripta datos o archivos usando AES-256-GCM + RSA-OAEP.

    Default desde 2.0.0:
    - oaep_hash="sha256"

    Stream desde 2.0.0:
    - Produce un archivo binario portable .ccenc con header embebido.
    - No depende de encryptedPath apuntando a un ciphertext suelto.
    """
    if stream and not isinstance(data, str):
        raise TypeError("Para 'stream=True', `data` debe ser una ruta a archivo (str).")

    if chunk_size <= 0:
        raise ValueError("`chunk_size` debe ser mayor que 0.")

    resolved_oaep_hash = _resolve_oaep_hash(oaep_hash)

    aes_key = get_random_bytes(AES_KEY_SIZE)
    public_key = loadPublicKey(PUBLIC_KEY)

    hash_algo = SHA256 if resolved_oaep_hash == "sha256" else SHA1
    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=hash_algo)
    encrypted_key = rsa_cipher.encrypt(aes_key)
    encrypted_key_b64 = _b64encode_str(encrypted_key)

    aad_bytes = _normalize_aad(aad)

    if stream:
        in_path = data

        if not os.path.isfile(in_path):
            raise TypeError("Para 'stream=True', `data` debe ser una ruta válida a archivo.")

        content_mode = mode.lower()
        if content_mode not in ("binary", "json", "dill"):
            raise ValueError("Para stream, mode debe ser 'binary', 'json' o 'dill'.")

        nonce = get_random_bytes(AES_NONCE_SIZE)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)

        if aad_bytes:
            cipher.update(aad_bytes)

        out_path = output_path or (in_path + ".ccenc")

        tmp_cipher_path: Optional[str] = None
        try:
            fd, tmp_cipher_path = tempfile.mkstemp(prefix="cross_crypto_stream_", suffix=".cipher")
            os.close(fd)

            with open(in_path, "rb") as f_in, open(tmp_cipher_path, "wb") as f_out:
                for chunk in iter(lambda: f_in.read(chunk_size), b""):
                    f_out.write(cipher.encrypt(chunk))
                tag = cipher.digest()

            nonce_b64 = _b64encode_str(nonce)
            tag_b64 = _b64encode_str(tag)

            _write_stream_envelope(
                output_path=out_path,
                encrypted_key_b64=encrypted_key_b64,
                nonce_b64=nonce_b64,
                tag_b64=tag_b64,
                oaep_hash=resolved_oaep_hash,
                aad_present=aad_bytes is not None,
                content_mode=content_mode,
                ciphertext_path=tmp_cipher_path,
            )

            return {
                "encryptedKey": encrypted_key_b64,
                "nonce": nonce_b64,
                "tag": tag_b64,
                "encryptedPath": out_path,
                "mode": "stream",
                "contentMode": content_mode,
                "streamFormat": "envelope",
                "aad": "present" if aad_bytes else "none",
                "oaepHash": resolved_oaep_hash,
            }

        finally:
            if tmp_cipher_path and os.path.exists(tmp_cipher_path):
                try:
                    os.remove(tmp_cipher_path)
                except Exception:
                    pass

    serialized_data, resolved_mode = _serialize_data(data, mode)

    nonce = get_random_bytes(AES_NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)

    if aad_bytes:
        cipher.update(aad_bytes)

    ciphertext, tag = cipher.encrypt_and_digest(serialized_data)

    result: EncryptedMemory = {
        "encryptedKey": encrypted_key_b64,
        "encryptedData": _b64encode_str(ciphertext),
        "nonce": _b64encode_str(nonce),
        "tag": _b64encode_str(tag),
        "mode": resolved_mode,
        "aad": "present" if aad_bytes else "none",
        "oaepHash": resolved_oaep_hash,
    }

    if resolved_mode == "dill" and signature:
        if signature.get("alg") != _SIG_ALG or signature.get("hash_alg") != _HASH_ALG:
            raise ValueError("La firma adjunta no usa el algoritmo esperado RSA-PSS/SHA-256.")
        result["signature"] = signature

    return result