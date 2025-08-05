# stubs/cross_crypto_py/encrypt.pyi

from typing import Any, Dict, Union, Optional
from Crypto.PublicKey.RSA import RsaKey

def loadPublicKey(PUBLIC_KEY: str) -> RsaKey: ...

def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: str,
    mode: str = ...,
    stream: bool = ...,
    output_path: Optional[str] = ...,
    chunk_size: int = ...
) -> Dict[str, str]: ...
