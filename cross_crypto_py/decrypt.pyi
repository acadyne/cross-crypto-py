from __future__ import annotations
from typing import Any, Dict, Optional, Union
from Crypto.PublicKey import RSA

def loadPrivateKey(PRIVATE_KEY: str) -> RSA.RsaKey: ...

def decryptHybrid(
    encrypted_data: Union[Dict[str, str], str],
    PRIVATE_KEY: str,
    mode: Optional[str] = ...,
    stream: bool = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...
) -> Union[Any, str, bytes]: ...
