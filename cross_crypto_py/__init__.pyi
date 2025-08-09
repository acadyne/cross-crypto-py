# stubs/cross_crypto_py/__init__.py
from __future__ import annotations

from .core import (
    collect_metadata as collect_metadata,
    create_zip_from_paths as create_zip_from_paths,
    detect_mime_type as detect_mime_type,
    extract_zip_to_dir as extract_zip_to_dir,
    hash_file as hash_file,
    load_encrypted_json as load_encrypted_json,
    read_binary_file as read_binary_file,
    save_encrypted_json as save_encrypted_json,
    write_binary_file as write_binary_file,
)
from .decrypt import (
    decryptHybrid as decryptHybrid,
    loadPrivateKey as loadPrivateKey,
)
from .encrypt import (
    encryptHybrid as encryptHybrid,
    loadPublicKey as loadPublicKey,
)
from .file_crypto import (
    decryptFileHybrid as decryptFileHybrid,
    encryptFileHybrid as encryptFileHybrid,
)
from .keygen import generateRSAKeys as generateRSAKeys

__all__ = [
    "__version__",
    "generateRSAKeys",
    "loadPublicKey", "encryptHybrid",
    "loadPrivateKey", "decryptHybrid",
    "encryptFileHybrid", "decryptFileHybrid",
    "create_zip_from_paths", "extract_zip_to_dir",
    "read_binary_file", "write_binary_file",
    "detect_mime_type", "hash_file",
    "collect_metadata", "save_encrypted_json",
    "load_encrypted_json",
]

__version__: str
