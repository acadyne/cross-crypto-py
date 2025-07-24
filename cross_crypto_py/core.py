# cross_crypto/core.py
import os
import mimetypes
import json
import zipfile
import hashlib
from typing import List, Dict, Any

def create_zip_from_paths(paths: List[str], output_zip_path: str) -> str:
    with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for path in paths:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Path does not exist: {path}")
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, start=os.path.dirname(path))
                        zipf.write(file_path, arcname=arcname)
            else:
                zipf.write(path, arcname=os.path.basename(path))
    return output_zip_path


def extract_zip_to_dir(zip_path: str, output_dir: str) -> None:
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")
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
    with open(output_path, 'w') as f:
        json.dump(encrypted_obj, f, indent=2)


def load_encrypted_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Encrypted JSON not found: {path}")
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
