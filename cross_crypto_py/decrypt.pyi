# stubs/cross_crypto_py/decrypt.pyi

from typing import Any, Dict, Union, Optional
from Crypto.PublicKey.RSA import RsaKey

def loadPrivateKey(PRIVATE_KEY: str) -> RsaKey: ...

def decryptHybrid(
    encrypted_data: Union[Dict[str, str], str],
    PRIVATE_KEY: str,
    mode: Optional[str] = ...,
    stream: bool = ...,
    decrypted_output_path: Optional[str] = ...,
    chunk_size: int = ...,
    return_bytes: bool = ...
) -> Union[Any, str, bytes]: ...
