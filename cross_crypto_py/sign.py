# cross_crypto_py/sign.py
from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict, Optional, TypedDict, Union

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


__all__ = [
    "Ed25519KeyPair",
    "SignaturePayload",
    "canonicalJsonBytes",
    "canonical_json_bytes",
    "generateEd25519Keys",
    "fingerprintBytes",
    "fingerprintPublicKey",
    "signPayload",
    "verifyPayload",
]


class Ed25519KeyPair(TypedDict):
    privateKey: str
    publicKey: str


class SignaturePayload(TypedDict, total=False):
    alg: str
    keyId: str
    signedAt: int
    payloadHash: str
    signature: str


def canonicalJsonBytes(payload: Dict[str, Any]) -> bytes:
    """
    Serializa JSON de forma canónica para que Python y TypeScript firmen
    exactamente los mismos bytes.

    Importante:
    - sort_keys=True
    - sin espacios
    - ensure_ascii=False
    - allow_nan=False para evitar NaN/Infinity no portables
    """
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


# Alias snake_case por comodidad interna/compatibilidad.
def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return canonicalJsonBytes(payload)


def fingerprintBytes(data: Union[str, bytes], *, hash_alg: str = "sha256") -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data

    if hash_alg.lower() != "sha256":
        raise ValueError("Solo se soporta hash_alg='sha256' por ahora.")

    return hashlib.sha256(raw).hexdigest()


def fingerprintPublicKey(public_key_pem: str, *, hash_alg: str = "sha256") -> str:
    """
    Fingerprint estable de una clave pública PEM.
    Normaliza la clave a DER antes de calcular SHA-256.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return fingerprintBytes(der, hash_alg=hash_alg)


def generateEd25519Keys() -> Ed25519KeyPair:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {
        "privateKey": private_pem,
        "publicKey": public_pem,
    }


def signPayload(
    payload: Dict[str, Any],
    private_key_pem: str,
    *,
    key_id: str = "v1",
    signed_at: Optional[int] = None,
) -> SignaturePayload:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("La clave privada no es Ed25519.")

    message = canonicalJsonBytes(payload)
    signature = private_key.sign(message)

    return {
        "alg": "Ed25519",
        "keyId": key_id,
        "signedAt": int(signed_at if signed_at is not None else time.time()),
        "payloadHash": hashlib.sha256(message).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verifyPayload(
    payload: Dict[str, Any],
    signature_payload: Dict[str, Any],
    public_key_pem: str,
    *,
    max_age_seconds: Optional[int] = None,
    now: Optional[int] = None,
) -> bool:
    try:
        if signature_payload.get("alg") != "Ed25519":
            return False

        required = {"alg", "keyId", "signedAt", "payloadHash", "signature"}
        if not required.issubset(signature_payload.keys()):
            return False

        signed_at = int(signature_payload["signedAt"])

        if max_age_seconds is not None:
            current_time = int(now if now is not None else time.time())
            if signed_at > current_time + 30:
                return False
            if current_time - signed_at > max_age_seconds:
                return False

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )

        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False

        message = canonicalJsonBytes(payload)
        expected_hash = hashlib.sha256(message).hexdigest()

        if signature_payload.get("payloadHash") != expected_hash:
            return False

        signature = base64.b64decode(
            str(signature_payload["signature"]),
            validate=True,
        )

        public_key.verify(signature, message)
        return True

    except Exception:
        return False