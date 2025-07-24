# cross_crypto/keygen.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Dict, Optional

def generateRSAKeys(bits: int = 4096, password: Optional[bytes] = None, verbose: bool = False) -> Dict[str, str]:
    """
    Genera un par de claves RSA (privada y pública) en formato PEM.
    - bits: tamaño de la clave en bits (mínimo recomendado: 2048).
    - password: si se proporciona, cifra la clave privada con la contraseña.
    - verbose: si es True, imprime información adicional.
    """
    if bits < 2048:
        raise ValueError("El tamaño mínimo recomendado para RSA es 2048 bits.")

    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        public_key = private_key.public_key()

        encryption_algorithm = (
            serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        if verbose:
            print(f"[+] Claves RSA generadas: {bits} bits")

        return {
            "privateKey": private_pem,
            "publicKey": public_pem
        }

    except Exception as e:
        print("Error en generateRSAKeys:", str(e))
        raise
