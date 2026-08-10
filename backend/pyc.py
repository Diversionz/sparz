from __future__ import annotations

import re
from pathlib import Path

from xdis.unmarshal import load_code

from .const import (
    VersionContext,
    fabricate_header_suffix,
    has_pyc_header,
)


class PycError(Exception):
    pass


_PY_PATH = re.compile(rb"(?:^|[^A-Za-z0-9_.-])([\w.-]+)\.py\b")


def build_pyc_header(ctx: VersionContext, magic: bytes | None = None) -> bytes:
    magic = magic if magic is not None else ctx.magic
    if len(magic) != 4:
        raise PycError(f"pyc magic must be 4 bytes, got {len(magic)}")
    return magic + fabricate_header_suffix(ctx.header)


def ensure_pyc(data: bytes, ctx: VersionContext, magic: bytes | None = None) -> bytes:
    magic = magic if magic is not None else ctx.magic
    if has_pyc_header(data, ctx.header):
        if len(data) < ctx.header_size:
            raise PycError("Truncated pyc header")
        return magic + data[4:]
    return build_pyc_header(ctx, magic) + data


def extract_code_blob(data: bytes, ctx: VersionContext) -> bytes:
    if has_pyc_header(data, ctx.header):
        return data[ctx.header_size :]
    return data


def extract_crypto_key_blob(data: bytes, ctx: VersionContext) -> bytes:
    return extract_code_blob(data, ctx)


def _magic_int(magic: bytes) -> int:
    if len(magic) < 2:
        raise PycError("pyc magic too short")
    return magic[1] << 8 | magic[0]


def _normalize_code_filename(filename: object) -> str | None:
    if isinstance(filename, bytes):
        try:
            filename = filename.decode("utf-8")
        except UnicodeDecodeError:
            filename = filename.decode("latin-1", errors="replace")
    if not isinstance(filename, str) or not filename or filename.startswith("<"):
        return None
    name = Path(filename.replace("\\", "/")).name
    if name.lower().endswith(".py"):
        name = name[:-3]
    name = name.strip()
    if not name or name.startswith("<"):
        return None
    return name


def _guess_name_from_strings(data: bytes) -> str | None:
    found: str | None = None
    for match in _PY_PATH.finditer(data):
        stem = match.group(1).decode("ascii", errors="ignore")
        if not stem or stem.startswith("<"):
            continue
        lower = stem.lower()
        if lower in {"__init__", "__main__", "pyiboot01_bootstrap"} or lower.startswith(
            "pyi_rth"
        ):
            continue
        found = stem
    return found


def _load_code_object(data: bytes, ctx: VersionContext, magic: bytes):
    blob = extract_code_blob(data, ctx)
    candidates = [blob]
    if blob is not data:
        candidates.append(data)
    elif len(data) > ctx.header_size:
        candidates.append(data[ctx.header_size :])
    last_err: Exception | None = None
    for candidate in candidates:
        try:
            return load_code(candidate, _magic_int(magic))
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise PycError("unable to load code object")


def guess_code_name(
    data: bytes, ctx: VersionContext, magic: bytes | None = None
) -> str | None:
    magic = magic if magic is not None else ctx.magic
    try:
        co = _load_code_object(data, ctx, magic)
        name = _normalize_code_filename(getattr(co, "co_filename", None))
        if name:
            return name
    except Exception:
        pass
    return _guess_name_from_strings(data)


def write_pyc(
    path: str | Path,
    data: bytes,
    ctx: VersionContext,
    magic: bytes | None = None,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ensure_pyc(data, ctx, magic))
    return path


def fix_bare_pyc_magic(path: str | Path, magic: bytes) -> None:
    path = Path(path)
    if len(magic) != 4:
        raise PycError(f"pyc magic must be 4 bytes, got {len(magic)}")
    with path.open("r+b") as f:
        f.write(magic)


def maybe_capture_magic_from_module(data: bytes, ctx: VersionContext) -> bytes | None:
    if has_pyc_header(data, ctx.header) and len(data) >= 4:
        return data[:4]
    return None
