# cross_crypto/decrypt.py
import os
import json
import base64
import dill  # type: ignore
from typing import Optional, Any, Dict, Union
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

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
        print("Error al cargar la llave privada:", str(e))
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
    Desencripta datos cifrados con cifrado híbrido AES-GCM + RSA-OAEP.
    - stream=True: `encrypted_data` debe ser un dict con 'encryptedPath', 'nonce', 'tag', 'encryptedKey'.
    - stream=False: espera el formato clásico con 'encryptedData', etc.
    - return_bytes=True: en modo stream devuelve los bytes en lugar de escribir en disco.
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

            aes_key = rsa_cipher.decrypt(base64.b64decode(encrypted_key_b64))
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64)

            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce) # type: ignore
            output_path = decrypted_output_path or encrypted_path.replace(".enc", ".dec")

            if return_bytes:
                result = b""
                with open(encrypted_path, 'rb') as f_in:
                    while chunk := f_in.read(chunk_size):
                        result += cipher.decrypt(chunk)
                try:
                    cipher.verify(tag)
                    return result
                except ValueError:
                    raise ValueError("Verificación de tag fallida: archivo corrupto o clave incorrecta.")
            else:
                with open(encrypted_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                    try:
                        while chunk := f_in.read(chunk_size):
                            f_out.write(cipher.decrypt(chunk))
                        cipher.verify(tag)
                        return output_path
                    except ValueError:
                        f_out.close()
                        os.remove(output_path)
                        raise ValueError("Verificación de tag fallida: archivo corrupto o clave incorrecta.")

        else:
            if not isinstance(encrypted_data, dict):
                raise TypeError("Se espera un diccionario con los campos base64 para desencriptar.")

            required_fields = {"encryptedKey", "encryptedData", "nonce", "tag"}
            if not required_fields.issubset(encrypted_data):
                raise ValueError(f"Faltan campos requeridos: {required_fields - encrypted_data.keys()}")

            encrypted_key = base64.b64decode(encrypted_data["encryptedKey"], validate=True)
            ciphertext = base64.b64decode(encrypted_data["encryptedData"], validate=True)
            nonce = base64.b64decode(encrypted_data["nonce"], validate=True)
            tag = base64.b64decode(encrypted_data["tag"], validate=True)

            aes_key = rsa_cipher.decrypt(encrypted_key)
            aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce) # type: ignore
            decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)

            selected_mode = mode or encrypted_data.get("mode", "json")
            if selected_mode == "json":
                return json.loads(decrypted_data.decode('utf-8'))
            elif selected_mode == "dill":
                return dill.loads(decrypted_data)  # type: ignore
            elif selected_mode == "binary":
                return decrypted_data
            else:
                raise ValueError(f"Modo de deserialización no soportado: {selected_mode}")

    except Exception as e:
        print("Error en decryptHybrid:", str(e))
        raise
