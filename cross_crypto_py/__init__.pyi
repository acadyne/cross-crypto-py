from __future__ import annotations
from typing import Any

__version__: str

from .keygen import generateRSAKeys
from .encrypt import encryptHybrid, loadPublicKey
from .decrypt import decryptHybrid, loadPrivateKey

__all__ = [
    "__version__",
    "generateRSAKeys",
    "loadPublicKey", "encryptHybrid",
    "loadPrivateKey", "decryptHybrid",
    "encryptFileHybrid", "decryptFileHybrid", # type: ignore[reportUnsupportedDunderAll]
    "create_zip_from_paths", "extract_zip_to_dir", # type: ignore[reportUnsupportedDunderAll]
    "read_binary_file", "write_binary_file", # type: ignore[reportUnsupportedDunderAll]
    "detect_mime_type", "hash_file", # type: ignore[reportUnsupportedDunderAll]
    "collect_metadata", "save_encrypted_json", # type: ignore[reportUnsupportedDunderAll]
    "load_encrypted_json", # type: ignore[reportUnsupportedDunderAll]
]

def __getattr__(name: str) -> object:
    """Carga perezosa para evitar errores de importación temprana."""
    if name in ("encryptFileHybrid", "decryptFileHybrid"):
        from .file_crypto import encryptFileHybrid, decryptFileHybrid
        return {
            "encryptFileHybrid": encryptFileHybrid,
            "decryptFileHybrid": decryptFileHybrid,
        }[name]

    if name in (
        "create_zip_from_paths", "extract_zip_to_dir",
        "read_binary_file", "write_binary_file",
        "detect_mime_type", "hash_file",
        "collect_metadata", "save_encrypted_json", "load_encrypted_json",
    ):
        from .core import (
            create_zip_from_paths, extract_zip_to_dir,
            read_binary_file, write_binary_file,
            detect_mime_type, hash_file,
            collect_metadata, save_encrypted_json, load_encrypted_json,
        )
        return {
            "create_zip_from_paths": create_zip_from_paths,
            "extract_zip_to_dir": extract_zip_to_dir,
            "read_binary_file": read_binary_file,
            "write_binary_file": write_binary_file,
            "detect_mime_type": detect_mime_type,
            "hash_file": hash_file,
            "collect_metadata": collect_metadata,
            "save_encrypted_json": save_encrypted_json,
            "load_encrypted_json": load_encrypted_json,
        }[name]

    raise AttributeError(f"module {__name__} has no attribute {name!r}")
