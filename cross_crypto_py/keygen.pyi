# stubs/cross_crypto_py/keygen.pyi
from typing import Optional, Union, TypedDict, Literal

class KeyPair(TypedDict):
    privateKey: str
    publicKey: str

def generateRSAKeys(
    bits: int = 4096,
    password: Optional[Union[bytes, str]] = None,
    *,
    public_exponent: int = 65537,
    public_format: Literal["SubjectPublicKeyInfo", "OpenSSH"] = "SubjectPublicKeyInfo",
    verbose: bool = False
) -> KeyPair: ...
