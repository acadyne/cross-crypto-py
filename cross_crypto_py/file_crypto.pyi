from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional, Union, TypedDict, overload
from typing_extensions import Literal

__all__ = ["encryptFileHybrid", "decryptFileHybrid", "FileEncryptionError", "FileDecryptionError"]

Phase = Literal["zip", "hash", "encrypt", "write", "extract"]

class FileEncryptionError(RuntimeError): ...
class FileDecryptionError(RuntimeError): ...

class EncryptedStreamInfoBase(TypedDict, total=False):
    encryptedPath: str
    encryptedKey: str
    nonce: str
    tag: str
    mode: Literal["stream"]
    aad: Literal["present", "none"]

class EncryptedMemoryInfoBase(TypedDict, total=False):
    encryptedData: str
    encryptedKey: str
    nonce: str
    tag: str
    mode: Literal["json", "dill", "binary"]
    aad: Literal["present", "none"]

class CommonInfoFields(TypedDict, total=False):
    original_paths: List[str]
    original_paths_rel: List[str]
    zip_sha256: str
    meta: Dict[str, Any]

class EncryptedStreamInfo(EncryptedStreamInfoBase, CommonInfoFields): ...
class EncryptedMemoryInfo(EncryptedMemoryInfoBase, CommonInfoFields): ...
EncryptedInfo = Union[EncryptedStreamInfo, EncryptedMemoryInfo]

# -------- encryptFileHybrid --------
@overload
def encryptFileHybrid(
    paths: List[str],
    public_key: Union[str, bytes],
    output_enc: Optional[str] = ...,
    zip_output: Optional[str] = ...,
    attach_metadata: bool = ...,
    save_file: bool = ...,
    *,
    use_stream: Literal[True],
    stream_chunk_size: int = ...,
    overwrite: bool = ...,
    progress_callback: Optional[Callable[[Phase, int, int], None]] = ...,
    exclude: Optional[List[str]] = ...,
    follow_symlinks: bool = ...,
    deterministic_zip: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
    cleanup_zip: bool = ...,
    oaep_hash: str = ...,
) -> EncryptedStreamInfo: ...

@overload
def encryptFileHybrid(
    paths: List[str],
    public_key: Union[str, bytes],
    output_enc: Optional[str] = ...,
    zip_output: Optional[str] = ...,
    attach_metadata: bool = ...,
    save_file: bool = ...,
    *,
    use_stream: Literal[False],
    stream_chunk_size: int = ...,
    overwrite: bool = ...,
    progress_callback: Optional[Callable[[Phase, int, int], None]] = ...,
    exclude: Optional[List[str]] = ...,
    follow_symlinks: bool = ...,
    deterministic_zip: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
    cleanup_zip: bool = ...,
    oaep_hash: str = ...,
) -> EncryptedMemoryInfo: ...

def encryptFileHybrid(
    paths: List[str],
    public_key: Union[str, bytes],
    output_enc: Optional[str] = ...,
    zip_output: Optional[str] = ...,
    attach_metadata: bool = ...,
    save_file: bool = ...,
    *,
    use_stream: bool = ...,
    stream_chunk_size: int = ...,
    overwrite: bool = ...,
    progress_callback: Optional[Callable[[Phase, int, int], None]] = ...,
    exclude: Optional[List[str]] = ...,
    follow_symlinks: bool = ...,
    deterministic_zip: bool = ...,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = ...,
    signature: Optional[Dict[str, Any]] = ...,
    cleanup_zip: bool = ...,
    oaep_hash: str = ...,
) -> Dict[str, Any]: ...

# -------- decryptFileHybrid --------
def decryptFileHybrid(
    enc_path: str,
    private_key: Union[str, bytes],
    extract_to: Optional[str] = ...,
    cleanup_zip: bool = ...,
    *,
    passphrase: Optional[Union[str, bytes]] = ...,
    stream_chunk_size: int = ...,
    overwrite: bool = ...,
    progress_callback: Optional[Callable[[Phase, int, int], None]] = ...,
    cleanup_enc: bool = ...,
) -> str: ...
