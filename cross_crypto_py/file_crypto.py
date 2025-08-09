# cross_crypto/file_crypto.py
from __future__ import annotations

import os
import uuid
import logging
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any, Union, Callable,Literal

from cross_crypto_py.encrypt import encryptHybrid
from cross_crypto_py.decrypt import decryptHybrid
from cross_crypto_py.core import (
    create_zip_from_paths,
    read_binary_file,
    write_binary_file,
    collect_metadata,
    save_encrypted_json,
    load_encrypted_json,
    extract_zip_to_dir,
)

logger = logging.getLogger(__name__)

Phase = Literal["zip", "hash", "encrypt", "write", "extract"]

class FileEncryptionError(RuntimeError):
    """Error durante el cifrado de archivos."""
    pass

class FileDecryptionError(RuntimeError):
    """Error durante el descifrado de archivos."""
    pass


def encryptFileHybrid(
    paths: List[str],
    public_key: Union[str, bytes],
    output_enc: Optional[str] = None,
    zip_output: Optional[str] = None,
    attach_metadata: bool = True,
    save_file: bool = False,
    *,
    use_stream: bool = False,
    stream_chunk_size: int = 64 * 1024,
    overwrite: bool = True,
    progress_callback: Optional[Callable[[Phase, int, int], None]] = None,
    exclude: Optional[List[str]] = None,
    follow_symlinks: bool = False,
    deterministic_zip: bool = True,
    aad: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    signature: Optional[Dict[str, Any]] = None,
    cleanup_zip: bool = True,
) -> Dict[str, Any]:
    """
    Empaqueta y cifra archivos/carpetas con cifrado híbrido AES-GCM + RSA-OAEP.
    Retorna un dict que coincide con EncryptedStreamInfo o EncryptedMemoryInfo según use_stream.
    """
    zip_path: Optional[str] = None
    try:
        if not paths or not all(os.path.exists(p) for p in paths):
            raise FileNotFoundError("Una o más rutas no existen o la lista está vacía.")

        tmp_dir = tempfile.gettempdir()
        zip_name = zip_output or f"temp_{uuid.uuid4().hex}.zip"
        zip_path = str(Path(tmp_dir) / zip_name) if not os.path.isabs(zip_name) else zip_name

        # 1) Crear ZIP
        if progress_callback:
            progress_callback("zip", 0, 0)
        created_zip_path = create_zip_from_paths(
            paths,
            zip_path,
            follow_symlinks=follow_symlinks,
            exclude=exclude,
            deterministic=deterministic_zip,
        )

        # 2) Calcular hash si hay callback
        if progress_callback:
            try:
                from cross_crypto_py.core import hash_file
                zip_hash = hash_file(created_zip_path)
                progress_callback("hash", 1, 1)
            except Exception:
                zip_hash = None
        else:
            zip_hash = None

        # 3) Cifrar
        if progress_callback:
            progress_callback("encrypt", 0, 0)

        if use_stream:
            encrypted = encryptHybrid(
                created_zip_path,
                public_key,
                mode="binary",
                stream=True,
                chunk_size=stream_chunk_size,
                aad=aad,
                signature=signature,
            )
        else:
            binary_data = read_binary_file(created_zip_path)
            encrypted = encryptHybrid(
                binary_data,
                public_key,
                mode="binary",
                stream=False,
                aad=aad,
                signature=signature,
            )

        encrypted["original_paths"] = paths
        encrypted["original_paths_rel"] = [os.path.basename(p) for p in paths]
        if zip_hash:
            encrypted["zip_sha256"] = zip_hash

        if attach_metadata:
            try:
                encrypted["meta"] = collect_metadata(created_zip_path)
            except Exception as m_err:
                logger.warning("No se pudieron adjuntar metadatos: %s", m_err)

        # 4) Guardar en disco
        if save_file:
            out_path = output_enc or (created_zip_path + ".enc")
            if not overwrite and os.path.exists(out_path):
                raise FileExistsError(f"El archivo de salida ya existe: {out_path}")
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            save_encrypted_json(out_path, encrypted)
            if progress_callback:
                progress_callback("write", 1, 1)

        return encrypted

    except Exception as e:
        raise FileEncryptionError(f"Error en encryptFileHybrid: {e}") from e

    finally:
        if cleanup_zip and zip_path and os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception as e:
                logger.warning("No se pudo eliminar el zip temporal '%s': %s", zip_path, e)


def decryptFileHybrid(
    enc_path: str,
    private_key: Union[str, bytes],
    extract_to: Optional[str] = None,
    cleanup_zip: bool = True,
    *,
    passphrase: Optional[Union[str, bytes]] = None,
    stream_chunk_size: int = 64 * 1024,
    overwrite: bool = True,
    progress_callback: Optional[Callable[[Phase, int, int], None]] = None,
    cleanup_enc: bool = False,
) -> str:
    """
    Descifra un archivo .enc y extrae su contenido.
    """
    temp_zip_path: Optional[str] = None  
    try:
        if not os.path.exists(enc_path):
            raise FileNotFoundError(f"Archivo cifrado no encontrado: {enc_path}")

        if progress_callback:
            progress_callback("hash", 0, 0)

        encrypted_obj = load_encrypted_json(enc_path)

        if progress_callback:
            progress_callback("encrypt", 0, 0)

        decrypted_binary = decryptHybrid(
            encrypted_obj,
            private_key,
            mode="binary",
            passphrase=passphrase,
            stream=False,
            chunk_size=stream_chunk_size,
        )
        if not isinstance(decrypted_binary, (bytes, bytearray)):
            raise TypeError("El contenido desencriptado no es binario ('bytes').")

        base = enc_path[:-4] if enc_path.endswith(".enc") else enc_path
        temp_zip_path = base + ".zip"
        write_binary_file(temp_zip_path, bytes(decrypted_binary))

        if progress_callback:
            progress_callback("write", 1, 1)

        output_dir = extract_to or (base + "_output")
        os.makedirs(output_dir, exist_ok=True)
        extract_zip_to_dir(temp_zip_path, output_dir, overwrite=overwrite)
        if progress_callback:
            progress_callback("extract", 1, 1)

        return output_dir

    except Exception as e:
        raise FileDecryptionError(f"Error en decryptFileHybrid: {e}") from e

    finally:
        if cleanup_zip and temp_zip_path and os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except Exception as e:
                logger.warning("No se pudo eliminar el zip temporal '%s': %s", temp_zip_path, e)

        if cleanup_enc and os.path.exists(enc_path):
            try:
                os.remove(enc_path)
            except Exception as e:
                logger.warning("No se pudo eliminar el archivo .enc '%s': %s", enc_path, e)
