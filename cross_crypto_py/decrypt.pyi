from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Union, TypedDict, overload
from typing_extensions import Literal
from Crypto.PublicKey import RSA


class EncryptedPacket(TypedDict, total=False):
    encryptedKey: str
    encryptedData: str
    nonce: str
    tag: str
    mode: Literal["json", "binary", "dill"]
    aad: Literal["present", "none"]
    oaepHash: Literal["sha1", "sha256"]
    signature: Dict[str, Any]


class StreamPacket(TypedDict, total=False):
    encryptedPath: str
    encryptedKey: str
    nonce: str
    tag: str
    mode: Literal["stream"]
    contentMode: Literal["json", "binary", "dill"]
    streamFormat: Literal["envelope"]
    aad: Literal["present", "none"]
    oaepHash: Literal["sha1", "sha256"]


def loadPrivateKey(
    PRIVATE_KEY: Union[str, bytes],
    passphrase: Optional[Union[str, bytes]] = ...,
) -> RSA.RsaKey: ...


@overload
def decryptHybrid(
    encrypted_data: Union[str, StreamPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    mode: Optional[str] = ...,
    stream: Literal[True] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: Literal[True] = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    *,
    oaep_hash: Optional[Literal["sha1", "sha256"]] = ...,
    sidecar_extension: str = ...,
) -> bytes: ...


@overload
def decryptHybrid(
    encrypted_data: Union[str, StreamPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    mode: Optional[str] = ...,
    stream: Literal[True] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: Literal[False] = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    *,
    oaep_hash: Optional[Literal["sha1", "sha256"]] = ...,
    sidecar_extension: str = ...,
) -> str: ...


@overload
def decryptHybrid(
    encrypted_data: Union[EncryptedPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    mode: Literal["binary"],
    stream: Literal[False] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    *,
    oaep_hash: Optional[Literal["sha1", "sha256"]] = ...,
    sidecar_extension: str = ...,
) -> bytes: ...


@overload
def decryptHybrid(
    encrypted_data: Union[EncryptedPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    mode: Literal["json"] = ...,
    stream: Literal[False] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    *,
    oaep_hash: Optional[Literal["sha1", "sha256"]] = ...,
    sidecar_extension: str = ...,
) -> Any: ...


@overload
def decryptHybrid(
    encrypted_data: Union[EncryptedPacket, Dict[str, Any], Mapping[str, Any]],
    PRIVATE_KEY: Union[str, bytes],
    mode: Literal["dill"],
    stream: Literal[False] = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    *,
    oaep_hash: Optional[Literal["sha1", "sha256"]] = ...,
    sidecar_extension: str = ...,
) -> Any: ...


def decryptHybrid(
    encrypted_data: Union[
        str,
        EncryptedPacket,
        StreamPacket,
        Dict[str, Any],
        Mapping[str, Any],
    ],
    PRIVATE_KEY: Union[str, bytes],
    mode: Optional[str] = ...,
    stream: bool = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    passphrase: Optional[Union[str, bytes]] = ...,
    *,
    oaep_hash: Optional[Literal["sha1", "sha256"]] = ...,
    sidecar_extension: str = ...,
) -> Union[Any, str, bytes]: ...