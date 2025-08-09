# cross_crypto/core.py

import os
import mimetypes
import json
import zipfile
import hashlib
from typing import List, Dict, Any

def create_zip_from_paths(paths: List[str], output_zip_path: str) -> str:
    """
    Reglas de empaquetado:
      - Si hay UN solo path y es DIRECTORIO: sus contenidos se guardan relativos al propio dir (sin prefijo).
      - En cualquier otro caso:
          * Archivos sueltos -> <basename>
          * Directorios -> <basename>/<estructura_relativa_interna>
      - Se preservan directorios vacíos.
    """
    if not paths:
        raise FileNotFoundError("La lista de rutas está vacía.")

    # Normaliza y valida
    abs_paths = []
    for p in paths:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Path does not exist: {p}")
        abs_paths.append(os.path.abspath(p))

    single_dir_flat = (len(abs_paths) == 1 and os.path.isdir(abs_paths[0]))

    with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for abs_path in abs_paths:
            if os.path.isdir(abs_path):
                top_name = os.path.basename(abs_path)
                for root, dirs, files in os.walk(abs_path):
                    rel_dir = os.path.relpath(root, start=abs_path)
                    if not files and not dirs:
                        dir_arc = (
                            rel_dir if single_dir_flat and rel_dir != "."
                            else (top_name if rel_dir == "." else os.path.join(top_name, rel_dir))
                        )
                        if dir_arc != ".":
                            zi = zipfile.ZipInfo(dir_arc.rstrip("/") + "/")
                            zipf.writestr(zi, "")
                    # Archivos
                    for fname in files:
                        full = os.path.join(root, fname)
                        rel = os.path.relpath(full, start=abs_path)
                        if single_dir_flat:
                            arcname = rel  
                        else:
                            arcname = os.path.join(top_name, rel)  
                        zipf.write(full, arcname=arcname)
            else:
                # Archivo suelto → nivel superior con su basename
                zipf.write(abs_path, arcname=os.path.basename(abs_path))

    return output_zip_path

def extract_zip_to_dir(zip_path: str, output_dir: str) -> None:
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")
    os.makedirs(output_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(path=output_dir)


def read_binary_file(path: str) -> bytes:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, 'rb') as f:
        return f.read()


def write_binary_file(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)


def detect_mime_type(path: str) -> str:
    mime_type, _ = mimetypes.guess_type(path)
    return mime_type or 'application/octet-stream'


def hash_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def collect_metadata(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Metadata collection failed, path not found: {path}")
    return {
        "filename": os.path.basename(path),
        "mime": detect_mime_type(path),
        "size": os.path.getsize(path),
        "sha256": hash_file(path)
    }


def save_encrypted_json(output_path: str, encrypted_obj: Dict[str, Any]) -> None:
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(encrypted_obj, f, indent=2, ensure_ascii=False)


def load_encrypted_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Encrypted JSON not found: {path}")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
