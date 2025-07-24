# cross_crypto/encrypt.py
import os
import json
import base64
import dill  # type: ignore
from typing import Any, Dict, Union, Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


def loadPublicKey(PUBLIC_KEY: str) -> RSA.RsaKey:
    """
    Carga la clave pública RSA desde una cadena PEM y valida su tamaño mínimo.
    """
    try:
        key = RSA.import_key(PUBLIC_KEY)
        if key.size_in_bits() < 2048:
            raise ValueError("La clave pública debe tener al menos 2048 bits por razones de seguridad.")
        return key
    except Exception as e:
        print("Error al cargar la clave pública:", str(e))
        raise


def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: str,
    mode: str = "json",
    stream: bool = False,
    output_path: Optional[str] = None,
    chunk_size: int = 64 * 1024
) -> Dict[str, str]:
    """
    Encripta datos o archivos usando cifrado híbrido AES-GCM + RSA-OAEP.
    - stream=True: `data` debe ser ruta a archivo, se cifra en modo streaming.
    - stream=False: `data` es un dict o bytes, se cifra en memoria.
    """
    aes_key = get_random_bytes(32)
    public_key = loadPublicKey(PUBLIC_KEY)
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    if stream:
        if not isinstance(data, str) or not os.path.isfile(data):
            raise TypeError("Para 'stream=True', se requiere una ruta válida a archivo.")
        nonce = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # type: ignore
        out_path = output_path or (data + ".enc")

        with open(data, 'rb') as f_in, open(out_path, 'wb') as f_out:
            while chunk := f_in.read(chunk_size):
                f_out.write(cipher.encrypt(chunk))
            tag = cipher.digest()

        return {
            "encryptedKey": base64.b64encode(encrypted_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "encryptedPath": out_path,
            "mode": "stream"
        }

    else:
        if mode == "json":
            if not isinstance(data, dict):
                raise TypeError("En modo 'json', los datos deben ser un diccionario.")
            serialized_data = json.dumps(data).encode('utf-8')
        elif mode == "dill":
            if not isinstance(data, dict):
                raise TypeError("En modo 'dill', los datos deben ser un diccionario.")
            serialized_data = dill.dumps(data)  # type: ignore
        elif mode == "binary":
            if not isinstance(data, bytes):
                raise TypeError("En modo 'binary', los datos deben ser de tipo bytes.")
            serialized_data = data
        else:
            raise ValueError(f"Modo de serialización no soportado: {mode}")

        nonce = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # type: ignore
        ciphertext, tag = cipher.encrypt_and_digest(serialized_data)   # type: ignore

        return {
            "encryptedKey": base64.b64encode(encrypted_key).decode(),
            "encryptedData": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "mode": mode
        }
