# cross_crypto/decrypt.py
from __future__ import annotations

import os
import json
import base64
import logging
import tempfile
import dill  
from typing import Optional, Any, Dict, Union
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

logger = logging.getLogger(__name__)

AES_NONCE_SIZE = 12 
GCM_TAG_MIN = 12     
GCM_TAG_MAX = 16

def _b64decode_strict(s: str) -> bytes:
    """Decodifica base64 con validación estricta."""
    return base64.b64decode(s, validate=True)

def _validate_lengths(nonce: bytes, tag: bytes) -> None:
    if len(nonce) != AES_NONCE_SIZE:
        logger.warning("Longitud de nonce inesperada: %d (esperado %d)", len(nonce), AES_NONCE_SIZE)
    if not (GCM_TAG_MIN <= len(tag) <= GCM_TAG_MAX):
        logger.warning("Longitud de tag fuera de rango típico: %d", len(tag))

def loadPrivateKey(PRIVATE_KEY: str) -> RSA.RsaKey:
    """
    Carga la clave privada RSA desde una cadena PEM.
    """
    try:
        key = RSA.import_key(PRIVATE_KEY)
        if key.size_in_bits() < 2048:
            raise ValueError("La clave privada debe tener al menos 2048 bits.")
        return key
    except Exception as e:
        logger.error("Error al cargar la llave privada: %s", e)
        raise

def decryptHybrid(
    encrypted_data: Union[Dict[str, str], str],
    PRIVATE_KEY: str,
    mode: Optional[str] = None,
    stream: bool = False,
    decrypted_output_path: Optional[str] = None,
    chunk_size: int = 64 * 1024,
    return_bytes: bool = False
) -> Union[Any, str, bytes]:
    """
    Desencripta datos cifrados con AES-GCM + RSA-OAEP.

    - stream=True: `encrypted_data` debe ser dict con:
        'encryptedPath', 'nonce', 'tag', 'encryptedKey'
    - stream=False: dict con 'encryptedData', 'nonce', 'tag', 'encryptedKey'
    - return_bytes=True (solo stream): devuelve bytes en memoria.
    """
    try:
        private_key = loadPrivateKey(PRIVATE_KEY)
        rsa_cipher = PKCS1_OAEP.new(private_key)

        if stream:
            if not isinstance(encrypted_data, dict):
                raise TypeError("Para 'stream=True', se espera un diccionario con metadata cifrada.")

            encrypted_path = encrypted_data.get("encryptedPath")
            encrypted_key_b64 = encrypted_data.get("encryptedKey", "")
            nonce_b64 = encrypted_data.get("nonce", "")
            tag_b64 = encrypted_data.get("tag", "")

            if not (encrypted_path and encrypted_key_b64 and nonce_b64 and tag_b64):
                raise ValueError("Faltan campos requeridos para el modo stream.")

            if not os.path.isfile(encrypted_path):
                raise FileNotFoundError(f"No existe el archivo cifrado: {encrypted_path}")

            aes_key = rsa_cipher.decrypt(_b64decode_strict(encrypted_key_b64))
            nonce = _b64decode_strict(nonce_b64)
            tag = _b64decode_strict(tag_b64)
            _validate_lengths(nonce, tag)

            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  

            if return_bytes:
                buf = bytearray()
                with open(encrypted_path, 'rb') as f_in:
                    for chunk in iter(lambda: f_in.read(chunk_size), b""):
                        buf.extend(cipher.decrypt(chunk))
                try:
                    cipher.verify(tag)
                    return bytes(buf)
                except ValueError:
                    raise ValueError("Verificación de tag fallida: archivo corrupto o clave incorrecta.")
            else:
                # Escribimos a un archivo temporal y renombramos solo si el tag verifica
                final_path = decrypted_output_path or encrypted_path.replace(".enc", ".dec")
                dirname = os.path.dirname(final_path) or "."
                os.makedirs(dirname, exist_ok=True)

                with tempfile.NamedTemporaryFile(dir=dirname, delete=False) as tmp:
                    tmp_path = tmp.name
                    try:
                        with open(encrypted_path, 'rb') as f_in:
                            for chunk in iter(lambda: f_in.read(chunk_size), b""):
                                tmp.write(cipher.decrypt(chunk))
                        cipher.verify(tag)
                        tmp.flush()
                        os.replace(tmp_path, final_path)
                        return final_path
                    except Exception:
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass
                        raise

        else:
            if not isinstance(encrypted_data, dict):
                raise TypeError("Se espera un diccionario con los campos base64 para desencriptar.")

            required_fields = {"encryptedKey", "encryptedData", "nonce", "tag"}
            if not required_fields.issubset(encrypted_data):
                missing = required_fields - set(encrypted_data.keys())
                raise ValueError(f"Faltan campos requeridos: {missing}")

            encrypted_key = _b64decode_strict(encrypted_data["encryptedKey"])
            ciphertext = _b64decode_strict(encrypted_data["encryptedData"])
            nonce = _b64decode_strict(encrypted_data["nonce"])
            tag = _b64decode_strict(encrypted_data["tag"])
            _validate_lengths(nonce, tag)

            aes_key = rsa_cipher.decrypt(encrypted_key)
            aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce) 
            decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)

            selected_mode = mode or encrypted_data.get("mode", "json")
            if selected_mode == "json":
                return json.loads(decrypted_data.decode('utf-8'))
            elif selected_mode == "dill":
                return dill.loads(decrypted_data)  
            elif selected_mode == "binary":
                return decrypted_data
            else:
                raise ValueError(f"Modo de deserialización no soportado: {selected_mode}")

    except Exception as e:
        logger.error("Error en decryptHybrid: %s", e)
        raise
