# cross_crypto/encrypt.py
from __future__ import annotations

import os
import json
import base64
import logging
import dill  
from typing import Any, Dict, Union, Optional, Literal
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

AES_KEY_SIZE = 32      # 256 bits
AES_NONCE_SIZE = 12    # Recomendado para AES-GCM

def _b64encode_str(data: bytes) -> str:
    """Codifica bytes a base64 UTF-8."""
    return base64.b64encode(data).decode("utf-8")


def loadPublicKey(PUBLIC_KEY: str) -> RSA.RsaKey:
    """
    Carga la clave pública RSA desde PEM y valida su tamaño mínimo.

    Args:
        PUBLIC_KEY: Cadena PEM con la clave pública.

    Raises:
        ValueError: Si la clave es menor a 2048 bits.
        Exception: Cualquier error de importación/parseo.

    Returns:
        Instancia `RSA.RsaKey`.
    """
    try:
        key = RSA.import_key(PUBLIC_KEY)
        if key.size_in_bits() < 2048:
            raise ValueError(
                "La clave pública debe tener al menos 2048 bits por razones de seguridad."
            )
        return key
    except Exception as e:
        logger.error("Error al cargar la clave pública: %s", e)
        raise


def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: str,
    mode: Literal["json", "dill", "binary"] = "json",
    stream: bool = False,
    output_path: Optional[str] = None,
    chunk_size: int = 64 * 1024
) -> Dict[str, str]:
    """
    Encripta datos o archivos usando AES-GCM + RSA-OAEP.

    Args:
        data: 
            - Si `stream=True`: ruta a archivo (str).
            - Si `stream=False`: datos en memoria (dict para json/dill, bytes para binary).
        PUBLIC_KEY: Clave pública PEM.
        mode: Método de serialización para datos en memoria.
        stream: Activa modo streaming para cifrar archivos grandes.
        output_path: Ruta opcional de salida para archivo cifrado.
        chunk_size: Tamaño de bloque para lectura en streaming.

    Returns:
        Dict[str, str] con campos como `encryptedKey`, `nonce`, `tag`, y según el modo:
        - `encryptedData` (modo memoria)
        - `encryptedPath` (modo streaming)
    """
    aes_key = get_random_bytes(AES_KEY_SIZE)
    public_key = loadPublicKey(PUBLIC_KEY)
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    if stream:
        if not isinstance(data, str) or not os.path.isfile(data):
            raise TypeError("Para 'stream=True', `data` debe ser una ruta válida a archivo.")

        nonce = get_random_bytes(AES_NONCE_SIZE)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce) 
        out_path = output_path or (data + ".enc")

        with open(data, "rb") as f_in, open(out_path, "wb") as f_out:
            while chunk := f_in.read(chunk_size):
                f_out.write(cipher.encrypt(chunk))
            tag = cipher.digest()

        return {
            "encryptedKey": _b64encode_str(encrypted_key),
            "nonce": _b64encode_str(nonce),
            "tag": _b64encode_str(tag),
            "encryptedPath": out_path,
            "mode": "stream",
        }

    # --- Modo en memoria ---
    if mode == "json":
        if not isinstance(data, dict):
            raise TypeError("En modo 'json', los datos deben ser un diccionario.")
        serialized_data = json.dumps(data).encode("utf-8")
    elif mode == "dill":
        if not isinstance(data, dict):
            raise TypeError("En modo 'dill', los datos deben ser un diccionario.")
        serialized_data = dill.dumps(data)  
    elif mode == "binary":
        if not isinstance(data, bytes):
            raise TypeError("En modo 'binary', los datos deben ser de tipo bytes.")
        serialized_data = data
    else:
        raise ValueError(f"Modo de serialización no soportado: {mode}")

    nonce = get_random_bytes(AES_NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  
    ciphertext, tag = cipher.encrypt_and_digest(serialized_data) 

    return {
        "encryptedKey": _b64encode_str(encrypted_key),
        "encryptedData": _b64encode_str(ciphertext),
        "nonce": _b64encode_str(nonce),
        "tag": _b64encode_str(tag),
        "mode": mode,
    }
