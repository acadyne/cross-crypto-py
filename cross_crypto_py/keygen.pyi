# stubs/cross_crypto_py/keygen.pyi
from typing import Dict, Optional, Union

def generateRSAKeys(
    bits: int = ...,
    password: Optional[Union[bytes, str]] = ...,
    verbose: bool = ...
) -> Dict[str, str]: ...
