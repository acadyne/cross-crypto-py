from __future__ import annotations
from typing import Any, Dict, List, Optional

def encryptFileHybrid(
    paths: List[str],
    public_key: str,
    output_enc: Optional[str] = ...,
    zip_output: Optional[str] = ...,
    attach_metadata: bool = ...,
    save_file: bool = ...
) -> Dict[str, Any]: ...

def decryptFileHybrid(
    enc_path: str,
    private_key: str,
    extract_to: Optional[str] = ...,
    cleanup_zip: bool = ...
) -> str: ...
