# cross_crypto/keygen.py
from __future__ import annotations

from typing import Dict, Optional, Union
import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

def generateRSAKeys(
    bits: int = 4096,
    password: Optional[Union[bytes, str]] = None,
    verbose: bool = False,
) -> Dict[str, str]:
    """
    Genera un par de claves RSA (privada y pública) en formato PEM (str).

    Args:
        bits: tamaño de clave (mínimo recomendado: 2048). Por defecto 4096.
        password: si se proporciona, cifra la clave privada (PKCS#8) con la contraseña.
                  Acepta bytes o str (se codifica en UTF-8 si es str).
        verbose: si True, loggea información con nivel INFO.

    Returns:
        Dict con:
            - "privateKey": clave privada PEM (PKCS#8) como str (UTF-8).
            - "publicKey" : clave pública PEM (SubjectPublicKeyInfo) como str (UTF-8).

    Seguridad:
        - Al pasar `password` como str, se convierte a bytes UTF-8 para el cifrado.
          Si necesitas control total del encoding, pasa `bytes` directamente.
    """
    if bits < 2048:
        raise ValueError("El tamaño mínimo recomendado para RSA es 2048 bits.")

    try:
        # Generación del par
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        public_key = private_key.public_key()

        # Normaliza password -> bytes o None
        enc_password: Optional[bytes]
        if password is None:
            enc_password = None
        elif isinstance(password, str):
            enc_password = password.encode("utf-8")
        else:
            enc_password = password

        # Algoritmo de cifrado para la privada
        encryption_algorithm = (
            serialization.BestAvailableEncryption(enc_password)
            if enc_password
            else serialization.NoEncryption()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        ).decode("utf-8")

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        if verbose:
            logger.info("Claves RSA generadas correctamente (%d bits)", bits)

        return {"privateKey": private_pem, "publicKey": public_pem}

    except Exception as e:
        raise RuntimeError(f"Fallo al generar claves RSA ({bits} bits).") from e
