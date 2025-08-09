# cross_crypto/decrypt.py
from __future__ import annotations

import os
import json
import base64
import logging
import tempfile
import stat
import dill
from typing import Optional, Any, Dict, Union, cast

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA1, SHA256

logger = logging.getLogger(__name__)

AES_NONCE_SIZE = 12
GCM_TAG_MIN = 12
GCM_TAG_MAX = 16

_SIG_ALG = "RSA-PSS"
_HASH_ALG = "SHA-256"


def _b64decode_strict(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _b64encode_ascii(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _validate_lengths(nonce: bytes, tag: bytes) -> None:
    if len(nonce) != AES_NONCE_SIZE:
        logger.warning("Longitud de nonce inesperada: %d (esperado %d)", len(nonce), AES_NONCE_SIZE)
    if not (GCM_TAG_MIN <= len(tag) <= GCM_TAG_MAX):
        logger.warning("Longitud de tag fuera de rango típico: %d", len(tag))


def _canonical_bytes(obj: Dict[str, Any]) -> bytes:
    """JSON canónico: claves ordenadas, sin espacios."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sha256_b64(data: bytes) -> str:
    """SHA-256(data) en base64 ASCII."""
    h = SHA256.new(data)
    return _b64encode_ascii(h.digest())


def loadPrivateKey(PRIVATE_KEY: Union[str, bytes], passphrase: Optional[Union[str, bytes]] = None) -> RSA.RsaKey:
    """Carga clave privada RSA (>=2048). Acepta passphrase str o bytes."""
    try:
        if isinstance(passphrase, bytes):
            passphrase = passphrase.decode()

        key = RSA.import_key(PRIVATE_KEY, passphrase=passphrase)
        if key.size_in_bits() < 2048:
            raise ValueError("La clave privada debe tener al menos 2048 bits.")
        if not key.has_private():
            raise ValueError("La clave provista no contiene parte privada válida.")
        return key
    except Exception as e:
        logger.error("Error al cargar la llave privada: %s", e)
        raise


def _verify_signature_sidecar(file_path: str, sig_path: str, public_key: RSA.RsaKey) -> bool:
    """Verifica la firma sidecar .sig del archivo desencriptado."""
    if not os.path.exists(sig_path):
        logger.error("No existe archivo de firma: %s", sig_path)
        return False

    try:
        with open(sig_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        logger.error("Firma .sig no es JSON válido: %s", e)
        return False

    try:
        if payload.get("alg") != _SIG_ALG or payload.get("hash_alg") != _HASH_ALG:
            logger.error("Algoritmo de firma/hash no soportado")
            return False

        file_name = os.path.basename(file_path)
        if payload.get("file") != file_name:
            logger.error("El nombre de archivo en la firma no coincide: %s != %s", payload.get("file"), file_name)
            return False

        with open(file_path, "rb") as f:
            data = f.read()
            st = os.fstat(f.fileno())

        fields_now: Dict[str, Any] = {
            "alg": _SIG_ALG,
            "hash_alg": _HASH_ALG,
            "file": file_name,
            "size": st.st_size,
            "mtime_ns": int(st.st_mtime_ns),
            "hash_b64": _sha256_b64(data),
            "ts": payload.get("ts"),
        }
        if payload.get("key_id") is not None:
            fields_now["key_id"] = payload.get("key_id")
        if payload.get("prev_hash") is not None:
            fields_now["prev_hash"] = payload.get("prev_hash")

        # Comprobaciones rápidas
        if payload.get("size") != fields_now["size"]:
            logger.error("Tamaño del archivo difiere del firmado")
            return False
        if payload.get("mtime_ns") != fields_now["mtime_ns"]:
            logger.debug("mtime_ns difiere del firmado (continuando)")

        # Preparar verificación
        try:
            sig_raw = base64.b64decode(payload["sig_b64"], validate=True)
        except Exception:
            logger.error("sig_b64 no es Base64 válido en firma")
            return False

        to_verify = _canonical_bytes(fields_now)
        msg_hash = SHA256.new(to_verify)

        # Obtener pública si nos pasan la privada
        if public_key.has_private():
            public_key = public_key.publickey()

        verifier = pss.new(public_key, mask_func=lambda x, y: pss.MGF1(x, y, SHA256))
        verifier.verify(cast(Any, msg_hash), sig_raw)

        logger.debug("Validación de firma OK: file=%s size=%s", file_name, fields_now["size"])
        return True

    except Exception as e:
        logger.error("Validación de firma FALLÓ: %s", e)
        return False


def _aad_bytes(a: Optional[Union[bytes, str, Dict[str, Any]]]) -> Optional[bytes]:
    if a is None:
        return None
    if isinstance(a, bytes):
        return a
    if isinstance(a, str):
        return a.encode("utf-8")
    return json.dumps(a, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decryptHybrid(
    encrypted_data: Union[Dict[str, Any], str],
    PRIVATE_KEY: Union[str, bytes],
    mode: Optional[str] = None,
    stream: bool = False,
    decrypted_output_path: Optional[str] = None,
    chunk_size: int = 64 * 1024,
    return_bytes: bool = False,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    passphrase: Optional[Union[str, bytes]] = None,
    *,
    oaep_hash: str = "sha1", 
    sidecar_extension: str = ".sig",
) -> Union[Any, str, bytes]:
    """Desencripta datos cifrados con AES-GCM + RSA-OAEP(SHA-256 o SHA-1)."""
    try:
        private_key = loadPrivateKey(PRIVATE_KEY, passphrase=passphrase)
        hash_algo = SHA256 if oaep_hash.lower() == "sha256" else SHA1
        rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=hash_algo)

        aad_bytes = _aad_bytes(aad)

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
            if aad_bytes:
                cipher.update(aad_bytes)

            if return_bytes:
                buf = bytearray()
                with open(encrypted_path, 'rb') as f_in:
                    for chunk in iter(lambda: f_in.read(chunk_size), b""):
                        buf.extend(cipher.decrypt(chunk))
                cipher.verify(tag) 
                selected_mode = (mode or encrypted_data.get("mode") or "json").lower()
                if selected_mode == "dill":
                    raise ValueError("Para DILL en stream, use salida a archivo (no return_bytes).")
                return bytes(buf)
            else:
                final_path = decrypted_output_path or encrypted_path.replace(".enc", ".dec")
                dirname = os.path.dirname(final_path) or "."
                os.makedirs(dirname, exist_ok=True)

                with tempfile.NamedTemporaryFile(dir=dirname, delete=False) as tmp:
                    tmp_path = tmp.name
                    try:
                        try:
                            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
                        except Exception:
                            pass
                        with open(encrypted_path, 'rb') as f_in:
                            for chunk in iter(lambda: f_in.read(chunk_size), b""):
                                tmp.write(cipher.decrypt(chunk))
                        cipher.verify(tag)
                        tmp.flush()
                        os.replace(tmp_path, final_path)
                    except Exception:
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass
                        raise

                if (mode or encrypted_data.get("mode") or "json").lower() == "dill":
                    sig_path = final_path + sidecar_extension
                    if not _verify_signature_sidecar(final_path, sig_path, private_key.publickey()):
                        try:
                            os.remove(final_path)
                        except Exception:
                            pass
                        raise ValueError("Firma sidecar inválida o ausente para archivo DILL.")

                return final_path

        # ----------- modo en memoria -----------
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
        if aad_bytes:
            aes_cipher.update(aad_bytes)
        decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)

        selected_mode = (mode or encrypted_data.get("mode") or "json").lower()
        if selected_mode == "json":
            return json.loads(decrypted_data.decode('utf-8'))

        elif selected_mode == "dill":
            sig = encrypted_data.get("signature")
            if not isinstance(sig, dict):
                raise ValueError("Se requiere 'signature' embebida para DILL en memoria.")
            pubkey = private_key.publickey()
            try:
                if sig.get("alg") != _SIG_ALG or sig.get("hash_alg") != _HASH_ALG:
                    raise ValueError("Algoritmo de firma/hash no soportado en 'signature'.")

                fields = {
                    "alg": _SIG_ALG,
                    "hash_alg": _HASH_ALG,
                    "size": len(decrypted_data),
                    "hash_b64": _sha256_b64(decrypted_data),
                    "ts": sig.get("ts"),
                }
                if sig.get("key_id") is not None:
                    fields["key_id"] = sig["key_id"]
                if sig.get("prev_hash") is not None:
                    fields["prev_hash"] = sig["prev_hash"]

                to_verify = _canonical_bytes(fields)
                sig_raw = base64.b64decode(sig["sig_b64"], validate=True)
                msg_hash = SHA256.new(to_verify)

                verifier = pss.new(pubkey, mask_func=lambda x, y: pss.MGF1(x, y, SHA256))
                verifier.verify(cast(Any, msg_hash), sig_raw)
            except Exception as e:
                raise ValueError(f"Firma embebida inválida para DILL: {e}") from e

            return dill.loads(decrypted_data)

        elif selected_mode == "binary":
            return decrypted_data
        else:
            raise ValueError(f"Modo de deserialización no soportado: {selected_mode}")

    except Exception as e:
        logger.error("Error en decryptHybrid: %s", e)
        raise
