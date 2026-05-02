from __future__ import annotations

from typing import Any, Dict, Optional, TypedDict, Union


class Ed25519KeyPair(TypedDict):
    privateKey: str
    publicKey: str


class SignaturePayload(TypedDict, total=False):
    alg: str
    keyId: str
    signedAt: int
    payloadHash: str
    signature: str


def canonicalJsonBytes(payload: Dict[str, Any]) -> bytes: ...
def canonical_json_bytes(payload: Dict[str, Any]) -> bytes: ...

def generateEd25519Keys() -> Ed25519KeyPair: ...

def fingerprintBytes(
    data: Union[str, bytes],
    *,
    hash_alg: str = ...,
) -> str: ...

def fingerprintPublicKey(
    public_key_pem: str,
    *,
    hash_alg: str = ...,
) -> str: ...

def signPayload(
    payload: Dict[str, Any],
    private_key_pem: str,
    *,
    key_id: str = ...,
    signed_at: Optional[int] = ...,
) -> SignaturePayload: ...

def verifyPayload(
    payload: Dict[str, Any],
    signature_payload: Dict[str, Any],
    public_key_pem: str,
    *,
    max_age_seconds: Optional[int] = ...,
    now: Optional[int] = ...,
) -> bool: ...