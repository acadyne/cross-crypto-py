# cross_crypto/keygen.py
from __future__ import annotations
from typing import Optional, Union, TypedDict, Literal
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

__all__ = ["generateRSAKeys"]

logger = logging.getLogger(__name__)

class KeyPair(TypedDict):
    privateKey: str
    publicKey: str


def _to_bytes(s: Optional[Union[str, bytes]]) -> Optional[bytes]:
    if s is None:
        return None
    if isinstance(s, bytes):
        return s
    return s.encode("utf-8")


def generateRSAKeys(
    bits: int = 4096,
    password: Optional[Union[bytes, str]] = None,
    *,
    public_exponent: int = 65537,
    public_format: Literal["SubjectPublicKeyInfo", "OpenSSH"] = "SubjectPublicKeyInfo",
    verbose: bool = False,
) -> KeyPair:
    """
    Genera un par de claves RSA (privada y pública) en formato PEM (str).

    Args:
        bits: tamaño de la clave (mínimo recomendado: 2048).
        password: passphrase para cifrar la privada. `None` = sin cifrado.
                  Si es cadena vacía, se tratará como sin cifrar.
        public_exponent: normalmente 65537.
        public_format: "SubjectPublicKeyInfo" (PEM tradicional) u "OpenSSH".
        verbose: loggea un mensaje INFO al finalizar.

    Returns:
        KeyPair con `privateKey` y `publicKey` como PEM (str).
    """
    if bits < 1024:
        raise ValueError("El tamaño mínimo permitido para RSA es 1024 bits.")
    elif bits < 2048:
        logger.warning("El tamaño recomendado para RSA es 2048 bits o más.")

    try:
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=bits,
        )
        public_key = private_key.public_key()

        enc_password = _to_bytes(password)
        if enc_password is not None and len(enc_password) == 0:
            enc_password = None

        encryption_algorithm = (
            serialization.BestAvailableEncryption(enc_password)
            if enc_password is not None
            else serialization.NoEncryption()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        ).decode("utf-8")

        if public_format == "OpenSSH":
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            ).decode("utf-8")
        else:
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

        if verbose:
            logger.info("Claves RSA generadas correctamente (%d bits)", bits)

        return {"privateKey": private_pem, "publicKey": public_pem}

    except Exception as e:
        logger.error("Fallo al generar claves RSA (%d bits): %s", bits, e)
        raise RuntimeError(f"Fallo al generar claves RSA ({bits} bits).") from e
