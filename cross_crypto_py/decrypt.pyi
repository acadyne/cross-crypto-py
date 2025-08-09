# cross_crypto/decrypt.pyi

from __future__ import annotations
from typing import Any, Dict, Optional, Union, TypedDict, Mapping, overload
from typing_extensions import Literal, NotRequired
from Crypto.PublicKey import RSA

class EncryptedPacket(TypedDict):
    encryptedKey: str
    encryptedData: str
    nonce: str
    tag: str
    mode: NotRequired[str]

class StreamPacket(TypedDict):
    encryptedPath: str
    encryptedKey: str
    nonce: str
    tag: str

def loadPrivateKey(
    PRIVATE_KEY: Union[str, bytes],
    passphrase: Optional[Union[str, bytes]] = ...,
) -> RSA.RsaKey: ...
"""Carga clave privada RSA desde PEM/DER (>=2048 bits)."""

# ---- Overloads para stream=True
@overload
def decryptHybrid(
    encrypted_data: Union[StreamPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    *,
    mode: Optional[str] = ...,
    stream: Literal[True],
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: Literal[True],
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    oaep_hash: str = ...,
    sidecar_extension: str = ...,
) -> bytes: ...

@overload
def decryptHybrid(
    encrypted_data: Union[StreamPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    *,
    mode: Optional[str] = ...,
    stream: Literal[True],
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: Literal[False] = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    oaep_hash: str = ...,
    sidecar_extension: str = ...,
) -> str: ...

# ---- Overloads para stream=False (paquete en memoria)
@overload
def decryptHybrid(
    encrypted_data: Union[EncryptedPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    *,
    mode: Literal["binary"],
    stream: Literal[False] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    oaep_hash: str = ...,
    sidecar_extension: str = ...,
) -> bytes: ...

@overload
def decryptHybrid(
    encrypted_data: Union[EncryptedPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    *,
    mode: Literal["json"],
    stream: Literal[False] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    oaep_hash: str = ...,
    sidecar_extension: str = ...,
) -> Any: ...

@overload
def decryptHybrid(
    encrypted_data: Union[EncryptedPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    *,
    mode: Literal["dill"],
    stream: Literal[False] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    oaep_hash: str = ...,
    sidecar_extension: str = ...,
) -> Any: ...

# ---- Fallback general
def decryptHybrid(
    encrypted_data: Union[EncryptedPacket, StreamPacket, Dict[str, str], Dict[str, Any], Mapping[str, Any], str],
    PRIVATE_KEY: Union[str, bytes],
    *,
    mode: Optional[str] = ...,
    stream: bool = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    oaep_hash: str = ...,
    sidecar_extension: str = ...,
) -> Union[Any, str, bytes]: ...
"""Descifra con AES-GCM y RSA-OAEP (SHA-1 o SHA-256). Soporta AAD y modo streaming."""
