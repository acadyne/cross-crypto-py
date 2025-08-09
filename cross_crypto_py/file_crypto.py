# cross_crypto/file_crypto.py
from __future__ import annotations

import os
import uuid
import logging
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any

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

def encryptFileHybrid(
    paths: List[str],
    public_key: str,
    output_enc: Optional[str] = None,
    zip_output: Optional[str] = None,
    attach_metadata: bool = True,
    save_file: bool = False,
) -> Dict[str, Any]:
    """
    Encripta uno o varios archivos/carpeta como binario usando cifrado híbrido.

    Args:
        paths: Rutas a archivos o carpetas a cifrar.
        public_key: Clave pública PEM.
        output_enc: Ruta de salida del .enc (si save_file=True).
        zip_output: Nombre del zip temporal a generar (opcional).
        attach_metadata: Adjuntar metadatos del zip original.
        save_file: Guardar el resultado en disco (.enc).

    Returns:
        Objeto dict con campos de encryptHybrid. Si attach_metadata=True incluye 'meta'.
    """
    if not paths or not all(os.path.exists(p) for p in paths):
        raise FileNotFoundError("Una o más rutas no existen o la lista está vacía.")

    # Crea zip temporal en un directorio temporal seguro si no se especifica nombre
    tmp_dir = tempfile.gettempdir()
    zip_name = zip_output or f"temp_{uuid.uuid4().hex}.zip"
    zip_path = str(Path(tmp_dir) / zip_name) if not os.path.isabs(zip_name) else zip_name

    try:
        # 1) Empaquetar
        created_zip_path = create_zip_from_paths(paths, zip_path)

        # 2) Leer binario y cifrar
        binary_data = read_binary_file(created_zip_path)
        encrypted: Dict[str, Any] = encryptHybrid(binary_data, public_key, mode="binary")

        # 3) Metadatos (opcional)
        if attach_metadata:
            try:
                encrypted["meta"] = collect_metadata(created_zip_path)  
            except Exception as m_err:
                logger.warning("No se pudieron adjuntar metadatos: %s", m_err)

        # 4) Persistir (opcional)
        if save_file:
            out_path = output_enc or (created_zip_path + ".enc")
            out_dir = os.path.dirname(out_path) or "."
            os.makedirs(out_dir, exist_ok=True)
            save_encrypted_json(out_path, encrypted)

        return encrypted

    finally:
        # 5) Limpieza del zip temporal si existe
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
        except Exception as e:
            logger.warning("No se pudo eliminar el zip temporal '%s': %s", zip_path, e)


def decryptFileHybrid(
    enc_path: str,
    private_key: str,
    extract_to: Optional[str] = None,
    cleanup_zip: bool = True,
) -> str:
    """
    Desencripta un archivo .enc generado con encryptFileHybrid y extrae su contenido.

    Args:
        enc_path: Ruta al archivo .enc.
        private_key: Clave privada PEM.
        extract_to: Directorio de extracción (por defecto, '<enc_path>_output').
        cleanup_zip: Eliminar el zip temporal después de extraer.

    Returns:
        Ruta del directorio de salida con los archivos extraídos.
    """
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Archivo cifrado no encontrado: {enc_path}")

    encrypted_obj = load_encrypted_json(enc_path)

    # 1) Desencriptar
    decrypted_binary = decryptHybrid(encrypted_obj, private_key, mode="binary")
    if not isinstance(decrypted_binary, (bytes, bytearray)):
        raise TypeError("El contenido desencriptado no es binario ('bytes').")

    # 2) Guardar zip temporal en el mismo directorio del .enc para minimizar I/O cruzado
    base = enc_path[:-4] if enc_path.endswith(".enc") else enc_path
    temp_zip_path = base + ".zip"

    # 3) Escribir zip y extraer
    write_binary_file(temp_zip_path, bytes(decrypted_binary))  
    output_dir = extract_to or (base + "_output")
    os.makedirs(output_dir, exist_ok=True)
    try:
        extract_zip_to_dir(temp_zip_path, output_dir)
    finally:
        # 4) Limpieza del zip temporal
        if cleanup_zip:
            try:
                if os.path.exists(temp_zip_path):
                    os.remove(temp_zip_path)
            except Exception as e:
                logger.warning("No se pudo eliminar el zip temporal '%s': %s", temp_zip_path, e)

    return output_dir
