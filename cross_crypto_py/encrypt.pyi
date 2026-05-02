from __future__ import annotations

from typing import Any, Dict, Optional, Union, TypedDict, overload
from typing_extensions import Literal
from Crypto.PublicKey import RSA


class InMemoryCiphertext(TypedDict, total=False):
    encryptedKey: str
    encryptedData: str
    nonce: str
    tag: str
    mode: Literal["json", "dill", "binary"]
    aad: Literal["present", "none"]
    oaepHash: Literal["sha1", "sha256"]
    signature: Dict[str, Any]


class StreamCiphertext(TypedDict):
    encryptedKey: str
    encryptedPath: str
    nonce: str
    tag: str
    mode: Literal["stream"]
    contentMode: Literal["json", "dill", "binary"]
    streamFormat: Literal["envelope"]
    aad: Literal["present", "none"]
    oaepHash: Literal["sha1", "sha256"]


def loadPublicKey(PUBLIC_KEY: Union[str, bytes]) -> RSA.RsaKey: ...


@overload
def encryptHybrid(
    data: Union[Dict[str, Any], bytes, bytearray, memoryview, str],
    PUBLIC_KEY: Union[str, bytes],
    mode: Literal["json", "dill", "binary"] = ...,
    *,
    stream: Literal[False] = ...,
    output_path: Optional[str] = ...,
    chunk_size: int = ...,
    oaep_hash: Literal["sha1", "sha256"] = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
) -> InMemoryCiphertext: ...


@overload
def encryptHybrid(
    data: str,
    PUBLIC_KEY: Union[str, bytes],
    mode: Literal["json", "dill", "binary"] = ...,
    *,
    stream: Literal[True],
    output_path: Optional[str] = ...,
    chunk_size: int = ...,
    oaep_hash: Literal["sha1", "sha256"] = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
) -> StreamCiphertext: ...


def encryptHybrid(
    data: Union[Dict[str, Any], bytes, bytearray, memoryview, str],
    PUBLIC_KEY: Union[str, bytes],
    mode: Literal["json", "dill", "binary"] = ...,
    stream: bool = ...,
    output_path: Optional[str] = ...,
    chunk_size: int = ...,
    oaep_hash: Literal["sha1", "sha256"] = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
) -> Union[InMemoryCiphertext, StreamCiphertext]: ...


def sign_dill_bytes(
    payload: bytes,
    PRIVATE_KEY: Union[str, bytes],
    *,
    passphrase: Optional[Union[str, bytes]] = ...,
    key_id: Optional[str] = ...,
    prev_hash: Optional[str] = ...,
) -> Dict[str, Any]: ...