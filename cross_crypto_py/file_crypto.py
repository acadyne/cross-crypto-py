# cross_crypto/file_crypto.py
import os
import uuid
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
    extract_zip_to_dir
)

def encryptFileHybrid(
    paths: List[str],
    public_key: str,
    output_enc: Optional[str] = None,
    zip_output: Optional[str] = None,
    attach_metadata: bool = True,
    save_file: bool = False
) -> Dict[str, Any]:
    """
    Encripta uno o varios archivos/carpeta como binario usando cifrado híbrido.

    paths: Lista de rutas a archivos o carpetas a cifrar.
    public_key: Clave pública en formato PEM.
    output_enc: Ruta donde guardar el archivo .enc (opcional).
    zip_output: Nombre del zip temporal a generar.
    attach_metadata: Adjunta metadatos como nombre, tipo y tamaño.
    save_file: Si True, guarda el resultado en output_enc.
    """
    if not paths or not all(os.path.exists(p) for p in paths):
        raise FileNotFoundError("Una o más rutas no existen o la lista está vacía.")

    zip_name = zip_output or f"temp_{uuid.uuid4().hex}.zip"
    zip_path = create_zip_from_paths(paths, zip_name)
    binary_data = read_binary_file(zip_path)
    encrypted = encryptHybrid(binary_data, public_key, mode="binary")

    if attach_metadata:
        encrypted["meta"] = collect_metadata(zip_path)  # type: ignore

    if save_file:
        output_path = output_enc or zip_path + ".enc"
        save_encrypted_json(output_path, encrypted)

    os.remove(zip_path)
    return encrypted


def decryptFileHybrid(
    enc_path: str,
    private_key: str,
    extract_to: Optional[str] = None,
    cleanup_zip: bool = True
) -> str:
    """
    Desencripta un archivo .enc generado con encryptFileHybrid y extrae su contenido.

    enc_path: Ruta al archivo .enc cifrado.
    private_key: Clave privada en formato PEM.
    extract_to: Directorio donde extraer los archivos (opcional).
    cleanup_zip: Si True, elimina el archivo zip temporal después de extraerlo.
    """
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Archivo cifrado no encontrado: {enc_path}")

    encrypted_obj = load_encrypted_json(enc_path)
    decrypted_binary = decryptHybrid(encrypted_obj, private_key, mode="binary")

    temp_zip_path = enc_path.replace(".enc", ".zip")
    write_binary_file(temp_zip_path, decrypted_binary)  # type: ignore

    output_dir = extract_to or enc_path.replace(".enc", "_output")
    extract_zip_to_dir(temp_zip_path, output_dir)

    if cleanup_zip:
        os.remove(temp_zip_path)

    return output_dir
