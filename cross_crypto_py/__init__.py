# cross_crypto_py/__init__.py

"""
Cross Crypto Py
===============

Cifrado híbrido AES-GCM + RSA-OAEP con interoperabilidad Python ↔ TS ↔ Rust.
"""

__version__ = "1.1.1"

from .keygen import generateRSAKeys
from .encrypt import loadPublicKey, encryptHybrid
from .decrypt import loadPrivateKey, decryptHybrid
from .file_crypto import encryptFileHybrid, decryptFileHybrid
from .core import (
    create_zip_from_paths,
    extract_zip_to_dir,
    read_binary_file,
    write_binary_file,
    detect_mime_type,
    hash_file,
    collect_metadata,
    save_encrypted_json,
    load_encrypted_json,
)

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
