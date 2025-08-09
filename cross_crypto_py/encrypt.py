# cross_crypto/encrypt.py
from __future__ import annotations

import os
import json
import base64
import logging
import time
from typing import Any, Dict, Union, Optional, Literal, Tuple, cast, TypedDict

import dill
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256,SHA1
from Crypto.Signature import pss

logger = logging.getLogger(__name__)

__all__ = [
    "AES_KEY_SIZE",
    "AES_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "EncryptedMemory",
    "EncryptedStream",
    "loadPublicKey",
    "sign_dill_bytes",
    "encryptHybrid",
]

AES_KEY_SIZE = 32       
AES_NONCE_SIZE = 12     
GCM_TAG_SIZE = 16       

_SIG_ALG = "RSA-PSS"
_HASH_ALG = "SHA-256"


# ------------------------------ Tipos de salida ------------------------------

class EncryptedMemory(TypedDict, total=False):
    encryptedKey: str
    encryptedData: str
    nonce: str
    tag: str
    mode: Literal["json", "dill", "binary"]
    aad: Literal["present", "none"]
    signature: Dict[str, Any]

class EncryptedStream(TypedDict):
    encryptedKey: str
    nonce: str
    tag: str
    encryptedPath: str
    mode: Literal["stream"]
    aad: Literal["present", "none"]


# ------------------------------ Utilidades ----------------------------------

def _b64encode_str(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _normalize_aad(aad: Optional[Union[bytes, str, Dict[str, Any]]]) -> Optional[bytes]:
    if aad is None:
        return None
    if isinstance(aad, bytes):
        return aad
    if isinstance(aad, str):
        return aad.encode("utf-8")
    return json.dumps(aad, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def loadPublicKey(PUBLIC_KEY: Union[str, bytes]) -> RSA.RsaKey:
    """Carga clave pública RSA y valida longitud mínima (>=2048)."""
    try:
        key = RSA.import_key(PUBLIC_KEY)
        if key.size_in_bits() < 2048:
            raise ValueError("La clave pública debe tener al menos 2048 bits por seguridad.")
        if key.has_private():
            raise ValueError("La clave provista parece contener parte privada, no pública.")
        return key
    except Exception as e:
        logger.error("Error al cargar la clave pública: %s", e)
        raise


def _serialize_data(
    data: Union[Dict[str, Any], bytes, str],
    mode: Literal["json", "dill", "binary"]
) -> Tuple[bytes, str]:
    if mode == "json":
        if not isinstance(data, dict):
            raise TypeError("En modo 'json', los datos deben ser un diccionario.")
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return payload, "json"
    elif mode == "dill":
        payload = dill.dumps(data)
        return payload, "dill"
    elif mode == "binary":
        if isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray, memoryview)):
            payload = bytes(data)
        else:
            raise TypeError("En modo 'binary', los datos deben ser bytes/bytearray/memoryview o str.")
        return payload, "binary"
    else:
        raise ValueError(f"Modo de serialización no soportado: {mode}")


# --------- Firma para DILL en memoria (adjunta al paquete cifrado) ----------

def _canonical_bytes(obj: Dict[str, Any]) -> bytes:
    """JSON canónico: claves ordenadas, sin espacios."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sha256_b64(data: bytes) -> str:
    """SHA-256(data) como base64 ASCII."""
    h = SHA256.new(data)
    return base64.b64encode(h.digest()).decode("ascii")


def _load_private_key(PRIVATE_KEY: Union[str, bytes], passphrase: Optional[Union[str, bytes]] = None) -> RSA.RsaKey:
    """Carga clave privada para firmar (opcional, si usas helper de firma)."""
    if isinstance(passphrase, bytes):
        passphrase = passphrase.decode()
    key = RSA.import_key(PRIVATE_KEY, passphrase=passphrase)
    if key.size_in_bits() < 2048:
        raise ValueError("La clave privada debe tener al menos 2048 bits por seguridad.")
    if not key.has_private():
        raise ValueError("La clave provista no contiene parte privada válida.")
    return key


def sign_dill_bytes(
    payload: bytes,
    PRIVATE_KEY: Union[str, bytes],
    *,
    passphrase: Optional[Union[str, bytes]] = None,
    key_id: Optional[str] = None,
    prev_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Firma un payload DILL (bytes) y devuelve un diccionario de firma
    para adjuntar en el paquete cifrado (modo memoria).

    Esquema de salida:
    {
      "alg": "RSA-PSS",
      "hash_alg": "SHA-256",
      "size": <len(payload)>,
      "hash_b64": "<base64>",
      "ts": <int>,
      "key_id": "...",      
      "prev_hash": "...",   
      "sig_b64": "<firma_base64>"
    }
    """
    sk = _load_private_key(PRIVATE_KEY, passphrase=passphrase)
    fields: Dict[str, Any] = {
        "alg": _SIG_ALG,
        "hash_alg": _HASH_ALG,
        "size": len(payload),
        "hash_b64": _sha256_b64(payload),
        "ts": int(time.time()),
    }
    if key_id is not None:
        fields["key_id"] = key_id
    if prev_hash is not None:
        fields["prev_hash"] = prev_hash

    to_sign = _canonical_bytes(fields)
    msg_hash = SHA256.new(to_sign)

    signer = pss.new(sk, mask_func=lambda x, y: pss.MGF1(x, y, SHA256))
    sig_raw = signer.sign(cast(Any, msg_hash))
    fields["sig_b64"] = base64.b64encode(sig_raw).decode("ascii")
    return fields


# ------------------------------ Cifrado híbrido ------------------------------

def encryptHybrid(
    data: Union[Dict[str, Any], bytes, str],
    PUBLIC_KEY: Union[str, bytes],
    mode: Literal["json", "dill", "binary"] = "json",
    stream: bool = False,
    output_path: Optional[str] = None,
    chunk_size: int = 64 * 1024,
    oaep_hash: str = "sha1",
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    *,
    signature: Optional[Dict[str, Any]] = None,  # firma adjunta para DILL en memoria
) -> Union[EncryptedMemory, EncryptedStream]:
    """
    Encripta datos o archivos usando AES-256-GCM + RSA-OAEP(SHA-256).

    - stream=False: cifra en memoria y devuelve 'encryptedData'.
        * Si mode='dill' y 'signature' está presente, se adjunta al paquete
          para verificación segura en decryptHybrid (memoria).
    - stream=True: cifra archivo de 'data' (ruta) en bloques y escribe 'output_path' (.enc por defecto).
        * La verificación de firma para DILL en stream se hace con archivo sidecar .sig
          al momento del desencriptado (ver decryptHybrid).
    - aad: datos autenticados (no cifrados) opcionales; si se usa, también se deben pasar en decrypt.
    """
    if stream and not isinstance(data, str):
        raise TypeError("Para 'stream=True', `data` debe ser una ruta a archivo (str).")

    if chunk_size <= 0:
        raise ValueError("`chunk_size` debe ser mayor que 0.")

    # 1) Generar clave simétrica y envolverla con RSA-OAEP(SHA-256)
    aes_key = get_random_bytes(AES_KEY_SIZE)
    public_key = loadPublicKey(PUBLIC_KEY)
    hash_algo = SHA256 if oaep_hash.lower() == "sha256" else SHA1
    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=hash_algo)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    aad_bytes = _normalize_aad(aad)

    # 2) Modo streaming (archivo -> archivo .enc, cabecera fuera)
    if stream:
        if not isinstance(data, str):
            raise TypeError("Para 'stream=True', `data` debe ser una ruta a archivo (str).")
        in_path: str = data

        if not os.path.isfile(in_path):
            raise TypeError("Para 'stream=True', `data` debe ser una ruta válida a archivo.")

        nonce = get_random_bytes(AES_NONCE_SIZE)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)
        if aad_bytes:
            cipher.update(aad_bytes)

        out_path = output_path or (in_path + ".enc")
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

        with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
            for chunk in iter(lambda: f_in.read(chunk_size), b""):
                f_out.write(cipher.encrypt(chunk))
            tag = cipher.digest()

        return {
            "encryptedKey": _b64encode_str(encrypted_key),
            "nonce": _b64encode_str(nonce),
            "tag": _b64encode_str(tag),
            "encryptedPath": out_path,
            "mode": "stream",
            "aad": "present" if aad_bytes else "none",
        }
    # 3) Modo en memoria (objeto/bytes/str -> blob cifrado base64)
    serialized_data, resolved_mode = _serialize_data(data, mode)

    nonce = get_random_bytes(AES_NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)
    if aad_bytes:
        cipher.update(aad_bytes)

    ciphertext, tag = cipher.encrypt_and_digest(serialized_data)

    result: EncryptedMemory = {
        "encryptedKey": _b64encode_str(encrypted_key),
        "encryptedData": _b64encode_str(ciphertext),
        "nonce": _b64encode_str(nonce),
        "tag": _b64encode_str(tag),
        "mode": cast(Literal["json", "dill", "binary"], resolved_mode),
        "aad": "present" if aad_bytes else "none",
    }

    # Adjuntar firma solo si es DILL y nos la pasan explícitamente
    if resolved_mode == "dill" and signature:
        # Validaciones mínimas del sobre de firma
        if signature.get("alg") != _SIG_ALG or signature.get("hash_alg") != _HASH_ALG:
            raise ValueError("La firma adjunta no usa el algoritmo esperado (RSA-PSS/SHA-256).")
        result["signature"] = signature  

    return result
