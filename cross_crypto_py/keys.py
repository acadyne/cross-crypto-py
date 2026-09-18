from __future__ import annotations

import hashlib
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from .encoding import b64url_encode
from .errors import CrossCryptoError
from .types import KeyPair


PublicKey = Union[rsa.RSAPublicKey, ed25519.Ed25519PublicKey]


def _public_spki_der(public_key: PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_id_from_public_key(public_key_pem: str | bytes) -> str:
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    try:
        public_key = serialization.load_pem_public_key(raw)
    except Exception as exc:
        raise CrossCryptoError("invalid_key", "Clave pública PEM inválida.", cause=exc) from exc
    if not isinstance(public_key, (rsa.RSAPublicKey, ed25519.Ed25519PublicKey)):
        raise CrossCryptoError("invalid_key", "Tipo de clave pública no soportado.")
    return b64url_encode(hashlib.sha256(_public_spki_der(public_key)).digest())


def load_rsa_public_key(public_key_pem: str | bytes) -> rsa.RSAPublicKey:
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    try:
        key = serialization.load_pem_public_key(raw)
    except Exception as exc:
        raise CrossCryptoError("invalid_key", "Clave pública RSA inválida.", cause=exc) from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise CrossCryptoError(
            "invalid_key", "RSA-OAEP requiere una clave RSA de al menos 2048 bits."
        )
    return key


def load_rsa_private_key(private_key_pem: str | bytes) -> rsa.RSAPrivateKey:
    raw = private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except Exception as exc:
        raise CrossCryptoError("invalid_key", "Clave privada RSA inválida.", cause=exc) from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise CrossCryptoError(
            "invalid_key", "RSA-OAEP requiere una clave RSA de al menos 2048 bits."
        )
    return key


def load_ed25519_public_key(public_key_pem: str | bytes) -> ed25519.Ed25519PublicKey:
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    try:
        key = serialization.load_pem_public_key(raw)
    except Exception as exc:
        raise CrossCryptoError("invalid_key", "Clave pública Ed25519 inválida.", cause=exc) from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise CrossCryptoError("invalid_key", "La clave pública no es Ed25519.")
    return key


def load_ed25519_private_key(private_key_pem: str | bytes) -> ed25519.Ed25519PrivateKey:
    raw = private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except Exception as exc:
        raise CrossCryptoError("invalid_key", "Clave privada Ed25519 inválida.", cause=exc) from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise CrossCryptoError("invalid_key", "La clave privada no es Ed25519.")
    return key


def generate_rsa_key_pair(bits: int = 3072) -> KeyPair:
    if not isinstance(bits, int) or isinstance(bits, bool) or bits < 2048 or bits % 256 != 0:
        raise CrossCryptoError(
            "invalid_key",
            "El tamaño RSA debe ser un múltiplo de 256 y al menos 2048 bits.",
        )
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return {
            "public_key": public_pem,
            "private_key": private_pem,
            "kid": key_id_from_public_key(public_pem),
        }
    except CrossCryptoError:
        raise
    except Exception as exc:
        raise CrossCryptoError("invalid_key", "No se pudo generar RSA.", cause=exc) from exc


def generate_ed25519_key_pair() -> KeyPair:
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return {
            "public_key": public_pem,
            "private_key": private_pem,
            "kid": key_id_from_public_key(public_pem),
        }
    except CrossCryptoError:
        raise
    except Exception as exc:
        raise CrossCryptoError(
            "invalid_key", "No se pudo generar Ed25519.", cause=exc
        ) from exc
