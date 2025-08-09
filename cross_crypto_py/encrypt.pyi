from __future__ import annotations
from typing import Any, Dict, Optional, Union, Literal, TypedDict, overload
from Crypto.PublicKey import RSA

class InMemoryCiphertext(TypedDict, total=False):
    encryptedKey: str
    encryptedData: str
    nonce: str
    tag: str
    mode: Literal["json", "dill", "binary"]
    aad: Literal["present", "none"]
    signature: Dict[str, Any] 

class StreamCiphertext(TypedDict):
    encryptedKey: str
    encryptedPath: str
    nonce: str
    tag: str
    mode: Literal["stream"]
    aad: Literal["present", "none"]

def loadPublicKey(PUBLIC_KEY: Union[str, bytes]) -> RSA.RsaKey: ...
"""Carga y valida una clave pública RSA (>=2048 bits)."""

@overload
def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: Union[str, bytes],
    mode: Literal["json", "dill", "binary"] = ...,
    *,
    stream: Literal[False] = ...,
    output_path: Optional[str] = ...,
    chunk_size: int = ...,
    oaep_hash: str = ...,
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
    oaep_hash: str = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
) -> StreamCiphertext: ...

def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: Union[str, bytes],
    mode: Literal["json", "dill", "binary"] = ...,
    stream: bool = ...,
    output_path: Optional[str] = ...,
    chunk_size: int = ...,
    oaep_hash: str = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
) -> Union[InMemoryCiphertext, StreamCiphertext]: ...
"""AES-256-GCM + RSA-OAEP (SHA-1 o SHA-256). Retorno varía según 'stream'."""
