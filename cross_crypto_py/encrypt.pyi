from __future__ import annotations
from typing import Any, Dict, Optional, Union, Literal
from Crypto.PublicKey import RSA

def loadPublicKey(PUBLIC_KEY: str) -> RSA.RsaKey: ...

def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: str,
    mode: Literal["json", "dill", "binary"] = ...,
    stream: bool = ...,
    output_path: Optional[str] = ...,
    chunk_size: int = ...
) -> Dict[str, str]: ...
