from __future__ import annotations

import re
from pathlib import Path
from uuid import uuid4 as uniquename

_UNSAFE = re.compile(r'[\x00-\x1f\x7f<>:"|?*]')
_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def cleaned_text(name: str) -> str:
    return _UNSAFE.sub("", name.replace("\\", "/"))


def _fix_part(part: str) -> str | None:
    part = _UNSAFE.sub("", part).strip().rstrip(".")
    if part in ("", "."):
        return None
    if part == "..":
        return "__"
    part = part.replace("..", "__")
    stem = part.split(".", 1)[0].upper()
    if stem in _RESERVED:
        part = f"_{part}"
    return part


def rel_parts(name: str) -> list[str]:
    cleaned = name.replace("\\", "/").lstrip("/")
    if len(cleaned) >= 2 and cleaned[1] == ":":
        cleaned = cleaned[2:].lstrip("/")
    parts: list[str] = []
    for part in cleaned.split("/"):
        fixed = _fix_part(part)
        if fixed is not None:
            parts.append(fixed)
    return parts or ["unnamed"]


def ensure_unique(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    new_path = path.with_name(f"{stem}_{uniquename()}{suffix}")
    print(f"[!] Warning: {path.name} exists, saving as {new_path.name}")
    return new_path


def safe_out_path(root: Path, name: str, suffix: str = "") -> Path:
    parts = rel_parts(name)
    if suffix:
        parts = list(parts)
        parts[-1] = f"{parts[-1]}{suffix}"
    path = root.joinpath(*parts)
    root_resolved = root.resolve()
    try:
        path.resolve().relative_to(root_resolved)
    except ValueError:
        path = root / f"unnamed_{uniquename()}{suffix}"
    return path


def safe_module_path(out_dir: Path, file_name: str, ispkg: bool) -> Path:
    parts = rel_parts(file_name)
    if ispkg:
        path = out_dir.joinpath(*parts, "__init__.pyc")
    else:
        path = out_dir.joinpath(*parts[:-1], f"{parts[-1]}.pyc")
    root = out_dir.resolve()
    try:
        path.resolve().relative_to(root)
    except ValueError:
        path = out_dir / "unnamed.pyc"
    return path
