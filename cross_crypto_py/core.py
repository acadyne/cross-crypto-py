# cross_crypto/core.py
from __future__ import annotations

import os
import sys
import json
import fnmatch
import hashlib
import mimetypes
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Callable, TypedDict


# =========================
# Tipos
# =========================

class FileMeta(TypedDict, total=False):
    filename: str
    mime: str
    size: int
    sha256: str
    mtime: float
    ctime: float          
    birthtime: float      
    atime: float
    mode: int
    is_dir: bool
    is_symlink: bool
    owner: str
    group: str
    platform: str
    entry_count: int     


# =========================
# ZIP helpers
# =========================

def _open_zip_write(path: str) -> zipfile.ZipFile:
    """
    Abre un ZipFile en modo escritura, usando compresión y haciendo fallback
    si el intérprete no soporta 'compresslevel'.
    """
    try:
        # type: ignore[call-arg] por implementaciones que no aceptan compresslevel
        return zipfile.ZipFile(
            path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            allowZip64=True,
            compresslevel=6, 
        )
    except TypeError:
        return zipfile.ZipFile(
            path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            allowZip64=True,
        )


def _sanitize_arcname(name: str) -> str:
    """
    Normaliza separadores a '/', elimina prefijos absolutos y '..' para el arcname.
    (Solo para escribir ZIP; la extracción segura hace validación aparte.)
    """
    name = name.replace("\\", "/")
    while name.startswith("/"):
        name = name[1:]
    parts: List[str] = []
    for p in name.split("/"):
        if p in ("", ".", ".."):
            continue
        parts.append(p)
    return "/".join(parts)


def _should_exclude(rel_path: str, patterns: Iterable[str]) -> bool:
    """
    Devuelve True si rel_path (estilo POSIX) coincide con alguno de los patrones.
    Coincidimos contra basename y contra ruta completa.
    """
    if not patterns:
        return False
    base = Path(rel_path).name
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(base, pat):
            return True
    return False


# =========================
# Empaquetado
# =========================

def create_zip_from_paths(
    paths: List[str],
    output_zip_path: str,
    *,
    follow_symlinks: bool = False,
    exclude: Optional[List[str]] = None,
    deterministic: bool = True,
) -> str:
    """
    Empaqueta archivos y/o carpetas en un ZIP.

    Reglas:
      - Si hay UN solo path y es DIRECTORIO: sus contenidos quedan relativos al propio dir (sin prefijo).
      - En otro caso:
          * Archivos sueltos -> <basename>
          * Directorios -> <basename>/<estructura_relativa_interna>
      - Se preservan directorios vacíos.
      - `exclude`: lista de patrones tipo glob aplicados a la ruta relativa dentro del zip.
      - `follow_symlinks`: seguir symlinks. Si False, se ignoran (y se registran como omitidos).
      - `deterministic`: fija tiempos de entrada a 1980-01-01 para reproducibilidad.

    Retorna: ruta al ZIP creado.
    """
    if not paths:
        raise FileNotFoundError("La lista de rutas está vacía.")

    abs_paths: List[Path] = []
    for p in paths:
        ap = Path(p).resolve()
        if not ap.exists():
            raise FileNotFoundError(f"Path does not exist: {p}")
        abs_paths.append(ap)

    single_dir_flat = (len(abs_paths) == 1 and abs_paths[0].is_dir())

    output_zip_path = str(Path(output_zip_path).resolve())
    out_parent = Path(output_zip_path).parent
    out_parent.mkdir(parents=True, exist_ok=True)

    with _open_zip_write(output_zip_path) as zipf:
        for ap in abs_paths:
            if ap.is_dir():
                top_name = ap.name
                for root, dirs, files in os.walk(ap, followlinks=follow_symlinks):
                    dirs.sort()
                    files.sort()

                    rel_dir_arc = Path(root).relative_to(ap).as_posix()

                    if not single_dir_flat:
                        rel_prefix = top_name if rel_dir_arc == "." else f"{top_name}/{rel_dir_arc}"
                    else:
                        rel_prefix = "" if rel_dir_arc == "." else rel_dir_arc

                    if not files and not dirs:
                        arc = _sanitize_arcname(rel_prefix)
                        if arc and not _should_exclude(arc, exclude or []):
                            zi = zipfile.ZipInfo(arc.rstrip("/") + "/")
                            if deterministic:
                                zi.date_time = (1980, 1, 1, 0, 0, 0)
                                zi.external_attr = (0o755 & 0xFFFF) << 16
                            zi.compress_type = zipfile.ZIP_DEFLATED
                            zipf.writestr(zi, b"")
                        continue

                    # Archivos
                    for fname in files:
                        full = Path(root) / fname
                        # Symlinks
                        if full.is_symlink() and not follow_symlinks:
                            continue

                        rel = Path(fname).as_posix()
                        if single_dir_flat:
                            arcname = _sanitize_arcname(rel)
                        else:
                            arcname = _sanitize_arcname(f"{rel_prefix}/{rel}")

                        if not arcname or _should_exclude(arcname, exclude or []):
                            continue

                        zi = zipfile.ZipInfo(arcname)
                        if deterministic:
                            zi.date_time = (1980, 1, 1, 0, 0, 0)
                            zi.external_attr = (0o644 & 0xFFFF) << 16
                        zi.compress_type = zipfile.ZIP_DEFLATED

                        with zipf.open(zi, "w") as dst, open(full, "rb") as src:
                            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                                dst.write(chunk)

            else:
                if ap.is_symlink() and not follow_symlinks:
                    continue

                arcname = _sanitize_arcname(ap.name)
                if _should_exclude(arcname, exclude or []):
                    continue

                zi = zipfile.ZipInfo(arcname)
                if deterministic:
                    zi.date_time = (1980, 1, 1, 0, 0, 0)
                    zi.external_attr = (0o644 & 0xFFFF) << 16
                zi.compress_type = zipfile.ZIP_DEFLATED

                with zipf.open(zi, "w") as dst, open(ap, "rb") as src:
                    for chunk in iter(lambda: src.read(1024 * 1024), b""):
                        dst.write(chunk)

    return output_zip_path


# =========================
# Extracción segura
# =========================

def _is_within_directory(base: Path, target: Path) -> bool:
    """
    Verifica que 'target' esté dentro de 'base' usando commonpath.
    """
    try:
        base_res = base.resolve(strict=False)
        target_res = target.resolve(strict=False)
    except Exception:
        base_res = base
        target_res = target
    try:
        return os.path.commonpath([str(base_res)]) == os.path.commonpath([str(base_res), str(target_res)])
    except Exception:
        base_s = str(base_res)
        return str(target_res).startswith(base_s if base_s.endswith(os.sep) else base_s + os.sep)


def extract_zip_to_dir(
    zip_path: str,
    output_dir: str,
    *,
    overwrite: bool = True,
    on_member: Optional[Callable[[zipfile.ZipInfo], None]] = None,
    max_total_uncompressed: int = 10 * 1024 * 1024 * 1024,  
    max_ratio: float = 100.0, 
) -> None:
    """
    Extrae un ZIP de forma segura previniendo path traversal (zip-slip) y con
    defensas básicas contra zip bombs.

    - Normaliza separadores y rehúsa rutas absolutas o con '..'.
    - Si overwrite=False, no sobreescribe archivos existentes.
    - on_member: callback opcional por entrada (para progreso/log).
    - max_total_uncompressed: límite de bytes descomprimidos acumulados.
    - max_ratio: límite de ratio file_size / compress_size por entrada.
    """
    zp = Path(zip_path)
    if not zp.exists():
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zp, "r") as zipf:
        total_uncompressed = 0
        for member in zipf.infolist():
            if on_member:
                try:
                    on_member(member)
                except Exception:
                    pass

            if member.file_size and member.compress_size:
                ratio = member.file_size / max(1, member.compress_size)
                if ratio >= max_ratio:
                    raise ValueError(
                        f"Posible zip bomb: {member.filename} ratio={ratio:.2f} "
                        f"(límite permitido: {max_ratio})"
                    )

            total_uncompressed += member.file_size
            if total_uncompressed > max_total_uncompressed:
                raise ValueError(
                    f"Tamaño total descomprimido excede límite permitido "
                    f"({total_uncompressed} bytes > {max_total_uncompressed} bytes)"
                )

            mname = member.filename.replace("\\", "/")
            # Rechazar absolutos y traversal
            if mname.startswith("/") or ".." in Path(mname).parts:
                raise ValueError(f"Entrada ZIP insegura: {member.filename}")

            dest = out / mname
            # Garantizar que el destino está dentro de output_dir
            if not _is_within_directory(out, dest):
                raise ValueError(f"Extracción fuera de destino: {member.filename}")

            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue

            # Crear carpeta contenedora
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() and not overwrite:
                continue

            with zipf.open(member, "r") as src, open(dest, "wb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    dst.write(chunk)


# =========================
# I/O utilidades
# =========================

def read_binary_file(path: str, *, chunk_size: int = 1024 * 1024) -> bytes:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    with open(p, "rb") as f:
        buf = bytearray()
        for chunk in iter(lambda: f.read(chunk_size), b""):
            buf.extend(chunk)
    return bytes(buf)


def write_binary_file(path: str, data: bytes) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)


def detect_mime_type(path: str) -> str:
    mime_type, _ = mimetypes.guess_type(path)
    return mime_type or "application/octet-stream"


def hash_file(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# =========================
# Metadatos
# =========================

def collect_metadata(path: str) -> Dict[str, Any]:
    """
    Metadatos extendidos y multiplataforma:
      - filename, mime, size, sha256 (si es archivo regular)
      - mtime, atime, ctime (floats)
      - birthtime (si el OS lo expone)
      - mode, is_dir, is_symlink
      - owner/group (si están disponibles, en POSIX)
      - platform
      - entry_count si es .zip y es archivo
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Metadata collection failed, path not found: {path}")

    st = p.lstat() 
    meta: Dict[str, Any] = {
        "filename": p.name,
        "mime": detect_mime_type(str(p)),
        "size": st.st_size,
        "mode": st.st_mode,
        "is_dir": p.is_dir(),
        "is_symlink": p.is_symlink(),
        "platform": sys.platform,
        "mtime": float(st.st_mtime),
        "atime": float(st.st_atime),
        "ctime": float(st.st_ctime), 
    }

    if p.is_file():
        try:
            meta["sha256"] = hash_file(str(p))
        except Exception:
            meta["sha256"] = ""
    else:
        meta["sha256"] = ""

    if hasattr(st, "st_birthtime"):
        try:
            meta["birthtime"] = float(getattr(st, "st_birthtime"))  # type: ignore[attr-defined]
        except Exception:
            pass

    # owner/group en POSIX
    if os.name == "posix":
        try:
            import pwd  # type: ignore
            import grp  # type: ignore
            meta["owner"] = pwd.getpwuid(st.st_uid).pw_name  # type: ignore[attr-defined]
            meta["group"] = grp.getgrgid(st.st_gid).gr_name  # type: ignore[attr-defined]
        except Exception:
            pass

    # Conteo de entradas si es ZIP y archivo
    if p.suffix.lower() == ".zip" and p.is_file():
        try:
            with zipfile.ZipFile(p, "r") as zf:
                meta["entry_count"] = len(zf.infolist())
        except Exception:
            pass

    return meta


# =========================
# JSON helpers
# =========================

def save_encrypted_json(output_path: str, encrypted_obj: Dict[str, Any]) -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(encrypted_obj, f, indent=2, ensure_ascii=False)


def load_encrypted_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Encrypted JSON not found: {path}")
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
