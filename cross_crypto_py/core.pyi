# stubs/cross_crypto_py/core.pyi
from __future__ import annotations
from typing import TypedDict, Dict, Any, List, Optional, Callable
import zipfile

class _FileMetaRequired(TypedDict):
    filename: str
    mime: str
    size: int
    sha256: str

class FileMeta(_FileMetaRequired, total=False):
    mtime: float
    atime: float
    ctime: float
    birthtime: float
    mode: int
    is_dir: bool
    is_symlink: bool
    owner: str
    group: str
    platform: str
    entry_count: int

def create_zip_from_paths(
    paths: List[str],
    output_zip_path: str,
    *,
    follow_symlinks: bool = ...,
    exclude: Optional[List[str]] = ...,
    deterministic: bool = ...,
) -> str: ...
"""Empaqueta archivos/carpetas en un ZIP. Retorna la ruta del ZIP."""

def extract_zip_to_dir(
    zip_path: str,
    output_dir: str,
    *,
    overwrite: bool = ...,
    on_member: Optional[Callable[[zipfile.ZipInfo], None]] = ...,
    max_total_uncompressed: int = ...,
    max_ratio: float = ...,
) -> None: ...
"""Extracción segura con defensas contra zip-slip y zip bombs."""

def read_binary_file(path: str, *, chunk_size: int = ...) -> bytes: ...
def write_binary_file(path: str, data: bytes) -> None: ...
def detect_mime_type(path: str) -> str: ...
def hash_file(path: str, *, chunk_size: int = ...) -> str: ...
def collect_metadata(path: str) -> FileMeta: ...
def save_encrypted_json(output_path: str, encrypted_obj: Dict[str, Any]) -> None: ...
def load_encrypted_json(path: str) -> Dict[str, Any]: ...
