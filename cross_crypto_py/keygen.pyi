# stubs/cross_crypto_py/keygen.pyi

from typing import Dict, Optional

def generateRSAKeys(
    bits: int = ...,
    password: Optional[bytes] = ...,
    verbose: bool = ...
) -> Dict[str, str]: ...
