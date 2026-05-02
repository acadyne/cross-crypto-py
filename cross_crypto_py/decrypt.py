# cross_crypto_py/decrypt.py
from __future__ import annotations

import os
import json
import base64
import logging
import tempfile
import stat
import struct
import dill
from typing import Optional, Any, Dict, Union, cast, Tuple

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA1, SHA256

logger = logging.getLogger(__name__)

AES_NONCE_SIZE = 12
GCM_TAG_MIN = 12
GCM_TAG_MAX = 16

STREAM_ENVELOPE_MAGIC = b"CCRYPT2\n"
STREAM_ENVELOPE_VERSION = 2

_SIG_ALG = "RSA-PSS"
_HASH_ALG = "SHA-256"


def _b64decode_strict(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _b64encode_ascii(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _validate_lengths(nonce: bytes, tag: bytes) -> None:
    if len(nonce) != AES_NONCE_SIZE:
        logger.warning(
            "Longitud de nonce inesperada: %d (esperado %d)",
            len(nonce),
            AES_NONCE_SIZE,
        )
    if not (GCM_TAG_MIN <= len(tag) <= GCM_TAG_MAX):
        logger.warning("Longitud de tag fuera de rango típico: %d", len(tag))


def _canonical_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_b64(data: bytes) -> str:
    h = SHA256.new(data)
    return _b64encode_ascii(h.digest())


def _aad_bytes(a: Optional[Union[bytes, str, Dict[str, Any]]]) -> Optional[bytes]:
    if a is None:
        return None
    if isinstance(a, bytes):
        return a
    if isinstance(a, str):
        return a.encode("utf-8")
    return json.dumps(
        a,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _resolve_oaep_hash(
    encrypted_data: Any,
    explicit_oaep_hash: Optional[str],
) -> str:
    value = explicit_oaep_hash

    if value is None and isinstance(encrypted_data, dict):
        value = encrypted_data.get("oaepHash") or encrypted_data.get("oaep_hash")

    value = value or "sha256"
    resolved = str(value).lower()

    if resolved not in ("sha1", "sha256"):
        raise ValueError("oaep_hash debe ser 'sha1' o 'sha256'.")

    return resolved


def loadPrivateKey(
    PRIVATE_KEY: Union[str, bytes],
    passphrase: Optional[Union[str, bytes]] = None,
) -> RSA.RsaKey:
    """Carga clave privada RSA >=2048."""
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


def _build_rsa_cipher(
    private_key: RSA.RsaKey,
    encrypted_data: Any,
    oaep_hash: Optional[str],
) -> PKCS1_OAEP.PKCS1OAEP_Cipher:
    resolved_oaep_hash = _resolve_oaep_hash(encrypted_data, oaep_hash)
    hash_algo = SHA256 if resolved_oaep_hash == "sha256" else SHA1
    return PKCS1_OAEP.new(private_key, hashAlgo=hash_algo)


def _verify_signature_sidecar(
    file_path: str,
    sig_path: str,
    public_key: RSA.RsaKey,
) -> bool:
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
            logger.error(
                "El nombre de archivo en la firma no coincide: %s != %s",
                payload.get("file"),
                file_name,
            )
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

        if payload.get("size") != fields_now["size"]:
            logger.error("Tamaño del archivo difiere del firmado")
            return False

        if payload.get("mtime_ns") != fields_now["mtime_ns"]:
            logger.debug("mtime_ns difiere del firmado (continuando)")

        sig_raw = base64.b64decode(payload["sig_b64"], validate=True)
        to_verify = _canonical_bytes(fields_now)
        msg_hash = SHA256.new(to_verify)

        if public_key.has_private():
            public_key = public_key.publickey()

        verifier = pss.new(public_key, mask_func=lambda x, y: pss.MGF1(x, y, SHA256))
        verifier.verify(cast(Any, msg_hash), sig_raw)

        return True

    except Exception as e:
        logger.error("Validación de firma FALLÓ: %s", e)
        return False


def _is_stream_envelope_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(len(STREAM_ENVELOPE_MAGIC)) == STREAM_ENVELOPE_MAGIC
    except Exception:
        return False


def _read_stream_envelope_header(path: str) -> Tuple[Dict[str, Any], int]:
    with open(path, "rb") as f:
        magic = f.read(len(STREAM_ENVELOPE_MAGIC))
        if magic != STREAM_ENVELOPE_MAGIC:
            raise ValueError("Archivo stream inválido: magic no coincide.")

        raw_len = f.read(4)
        if len(raw_len) != 4:
            raise ValueError("Archivo stream inválido: header length incompleto.")

        header_len = struct.unpack(">I", raw_len)[0]
        if header_len <= 0:
            raise ValueError("Archivo stream inválido: header vacío.")

        header_bytes = f.read(header_len)
        if len(header_bytes) != header_len:
            raise ValueError("Archivo stream inválido: header incompleto.")

        header = json.loads(header_bytes.decode("utf-8"))
        if not isinstance(header, dict):
            raise ValueError("Archivo stream inválido: header no es objeto JSON.")

        if header.get("version") != STREAM_ENVELOPE_VERSION:
            raise ValueError(f"Versión de stream no soportada: {header.get('version')}")

        if header.get("format") != "cross-crypto-stream":
            raise ValueError("Formato de stream no soportado.")

        offset = len(STREAM_ENVELOPE_MAGIC) + 4 + header_len
        return header, offset


def _decrypt_stream_envelope(
    *,
    envelope_path: str,
    private_key: RSA.RsaKey,
    decrypted_output_path: Optional[str],
    chunk_size: int,
    return_bytes: bool,
    aad_bytes: Optional[bytes],
    oaep_hash: Optional[str],
    mode: Optional[str],
    sidecar_extension: str,
) -> Union[str, bytes]:
    header, ciphertext_offset = _read_stream_envelope_header(envelope_path)

    required = {"encryptedKey", "nonce", "tag", "oaepHash"}
    missing = required - set(header.keys())
    if missing:
        raise ValueError(f"Header stream incompleto. Faltan campos: {missing}")

    rsa_cipher = _build_rsa_cipher(private_key, header, oaep_hash)

    encrypted_key = _b64decode_strict(str(header["encryptedKey"]))
    nonce = _b64decode_strict(str(header["nonce"]))
    tag = _b64decode_strict(str(header["tag"]))

    _validate_lengths(nonce, tag)

    aes_key = rsa_cipher.decrypt(encrypted_key)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    if aad_bytes:
        cipher.update(aad_bytes)

    selected_mode = (mode or header.get("contentMode") or "binary").lower()

    if return_bytes:
        if selected_mode == "dill":
            raise ValueError("Para DILL en stream, use salida a archivo, no return_bytes.")

        buf = bytearray()
        with open(envelope_path, "rb") as f_in:
            f_in.seek(ciphertext_offset)
            for chunk in iter(lambda: f_in.read(chunk_size), b""):
                buf.extend(cipher.decrypt(chunk))

        cipher.verify(tag)
        return bytes(buf)

    final_path = decrypted_output_path or envelope_path + ".dec"
    dirname = os.path.dirname(final_path) or "."
    os.makedirs(dirname, exist_ok=True)

    with tempfile.NamedTemporaryFile(dir=dirname, delete=False) as tmp:
        tmp_path = tmp.name

        try:
            try:
                os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

            with open(envelope_path, "rb") as f_in:
                f_in.seek(ciphertext_offset)
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

    if selected_mode == "dill":
        sig_path = final_path + sidecar_extension
        if not _verify_signature_sidecar(final_path, sig_path, private_key.publickey()):
            try:
                os.remove(final_path)
            except Exception:
                pass
            raise ValueError("Firma sidecar inválida o ausente para archivo DILL.")

    return final_path


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
    oaep_hash: Optional[str] = None,
    sidecar_extension: str = ".sig",
) -> Union[Any, str, bytes]:
    """
    Desencripta datos cifrados con AES-GCM + RSA-OAEP.

    Default desde 2.0.0:
    - Si el paquete trae oaepHash, usa ese valor.
    - Si no trae oaepHash y no se pasa oaep_hash, usa sha256.

    Stream desde 2.0.0:
    - Espera archivo .ccenc con header embebido.
    - encrypted_data puede ser una ruta str o un dict con encryptedPath.
    """
    try:
        private_key = loadPrivateKey(PRIVATE_KEY, passphrase=passphrase)
        aad_bytes = _aad_bytes(aad)

        if stream:
            if isinstance(encrypted_data, str):
                envelope_path = encrypted_data
            elif isinstance(encrypted_data, dict):
                encrypted_path = encrypted_data.get("encryptedPath")
                if not encrypted_path:
                    raise ValueError("Falta encryptedPath para modo stream.")
                envelope_path = str(encrypted_path)
            else:
                raise TypeError("Para stream=True se espera ruta str o dict con encryptedPath.")

            if not os.path.isfile(envelope_path):
                raise FileNotFoundError(f"No existe el archivo cifrado: {envelope_path}")

            if not _is_stream_envelope_file(envelope_path):
                raise ValueError("El modo stream v2 requiere un archivo envelope .ccenc válido.")

            return _decrypt_stream_envelope(
                envelope_path=envelope_path,
                private_key=private_key,
                decrypted_output_path=decrypted_output_path,
                chunk_size=chunk_size,
                return_bytes=return_bytes,
                aad_bytes=aad_bytes,
                oaep_hash=oaep_hash,
                mode=mode,
                sidecar_extension=sidecar_extension,
            )

        if not isinstance(encrypted_data, dict):
            raise TypeError("Se espera un diccionario con los campos base64 para desencriptar.")

        required_fields = {"encryptedKey", "encryptedData", "nonce", "tag"}
        if not required_fields.issubset(encrypted_data):
            missing = required_fields - set(encrypted_data.keys())
            raise ValueError(f"Faltan campos requeridos: {missing}")

        rsa_cipher = _build_rsa_cipher(private_key, encrypted_data, oaep_hash)

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
            return json.loads(decrypted_data.decode("utf-8"))

        if selected_mode == "binary":
            return decrypted_data

        if selected_mode == "dill":
            sig = encrypted_data.get("signature")

            if not isinstance(sig, dict):
                raise ValueError("Se requiere 'signature' embebida para DILL en memoria.")

            pubkey = private_key.publickey()

            try:
                if sig.get("alg") != _SIG_ALG or sig.get("hash_alg") != _HASH_ALG:
                    raise ValueError("Algoritmo de firma/hash no soportado en 'signature'.")

                fields: Dict[str, Any] = {
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

        raise ValueError(f"Modo de deserialización no soportado: {selected_mode}")

    except Exception as e:
        logger.error("Error en decryptHybrid: %s", e)
        raise