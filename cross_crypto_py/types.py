from __future__ import annotations

from typing import Literal, TypedDict


PROTOCOL_VERSION = 3
JWE_ALG = "RSA-OAEP-256"
JWE_ENC = "A256GCM"
JWS_ALG = "EdDSA"
JWE_TYP = "cross-crypto+jwe"
JWS_TYP = "cross-crypto+jws"


class _JweProtectedHeaderOptional(TypedDict, total=False):
    cty: str


class JweProtectedHeader(_JweProtectedHeaderOptional):
    alg: Literal["RSA-OAEP-256"]
    enc: Literal["A256GCM"]
    ccv: Literal[3]
    typ: Literal["cross-crypto+jwe"]
    kid: str


class _JweEnvelopeOptional(TypedDict, total=False):
    aad: str


class JweEnvelope(_JweEnvelopeOptional):
    protected: str
    encrypted_key: str
    iv: str
    ciphertext: str
    tag: str


class _JwsProtectedHeaderOptional(TypedDict, total=False):
    exp: int
    cty: str


class JwsProtectedHeader(_JwsProtectedHeaderOptional):
    alg: Literal["EdDSA"]
    ccv: Literal[3]
    typ: Literal["cross-crypto+jws"]
    kid: str
    iat: int


class JwsEnvelope(TypedDict):
    protected: str
    payload: str
    signature: str


class KeyPair(TypedDict):
    public_key: str
    private_key: str
    kid: str


# Alias explícitos para mantener la misma nomenclatura conceptual que TypeScript
# sin duplicar estructuras idénticas.
RsaKeyPair = KeyPair
Ed25519KeyPair = KeyPair


class _DecryptResultOptional(TypedDict, total=False):
    aad: bytes


class DecryptResult(_DecryptResultOptional):
    plaintext: bytes
    protected_header: JweProtectedHeader


class VerifyResult(TypedDict):
    payload: bytes
    protected_header: JwsProtectedHeader


class _CcencHeaderOptional(TypedDict, total=False):
    name: str
    cty: str


class CcencHeader(_CcencHeaderOptional):
    format: Literal["ccenc"]
    ccv: Literal[3]
    typ: Literal["cross-crypto+ccenc"]
    alg: Literal["RSA-OAEP-256"]
    enc: Literal["A256GCM"]
    kid: str
    chunkSize: int
    noncePrefix: str
    encryptedKey: str


class CcencDecryptResult(TypedDict):
    plaintext: bytes
    header: CcencHeader
