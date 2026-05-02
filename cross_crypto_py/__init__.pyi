from __future__ import annotations

__version__: str

from .keygen import generateRSAKeys
from .encrypt import encryptHybrid, loadPublicKey
from .decrypt import decryptHybrid, loadPrivateKey
from .sign import (
    canonicalJsonBytes,
    canonical_json_bytes,
    generateEd25519Keys,
    fingerprintBytes,
    fingerprintPublicKey,
    signPayload,
    verifyPayload,
)

__all__ = [
    "__version__",
    "generateRSAKeys",
    "loadPublicKey",
    "encryptHybrid",
    "loadPrivateKey",
    "decryptHybrid",
    "encryptFileHybrid",
    "decryptFileHybrid",
    "create_zip_from_paths",
    "extract_zip_to_dir",
    "read_binary_file",
    "write_binary_file",
    "detect_mime_type",
    "hash_file",
    "collect_metadata",
    "save_encrypted_json",
    "load_encrypted_json",
    "canonicalJsonBytes",
    "canonical_json_bytes",
    "generateEd25519Keys",
    "fingerprintBytes",
    "fingerprintPublicKey",
    "signPayload",
    "verifyPayload",
]

def __getattr__(name: str) -> object: ...