from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

from .const import (
    PYTHON_TYPECODES,
    PYZ_TYPECODES,
    SKIP_TYPECODES,
    TOC_ENTRY_FIXED_STRUCT,
    TOC_ENTRY_SIZE_STRUCT,
    TYPE_PYMODULE,
    TYPE_PYPACKAGE,
    TYPE_PYSOURCE,
    TYPE_ZIPFILE,
)
from .cookie import CookieInfo
from .paths import cleaned_text, rel_parts


class TocError(Exception):
    pass


@dataclass
class TocEntry:
    position: int
    cmprsd_data_size: int
    uncmprsd_data_size: int
    cmprs_flag: int
    typecode: bytes
    name: str

    @property
    def is_skip(self) -> bool:
        return self.typecode in SKIP_TYPECODES

    @property
    def is_pyz(self) -> bool:
        return self.typecode in PYZ_TYPECODES

    @property
    def is_python(self) -> bool:
        return self.typecode in PYTHON_TYPECODES

    @property
    def is_script(self) -> bool:
        return self.typecode == TYPE_PYSOURCE

    @property
    def is_package(self) -> bool:
        return self.typecode == TYPE_PYPACKAGE

    @property
    def is_crypto_key(self) -> bool:
        return self.name.endswith("_crypto_key")

    @property
    def is_fallback_name(self) -> bool:
        return self.name.startswith("unnamed_")


def _fallback_name(data: bytes) -> str:
    residual = data.replace(b"\0", b"")
    suffix = residual.hex() if residual else "empty"
    return f"unnamed_{suffix}"


def _sanitize_name(name: bytes) -> str:
    raw = name.split(b"\0", 1)[0]
    if not raw:
        return _fallback_name(name)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _fallback_name(raw)
    if not cleaned_text(decoded).strip("/"):
        return _fallback_name(raw)
    return "/".join(rel_parts(decoded))


def parse_toc(fp: BinaryIO, cookie: CookieInfo) -> list[TocEntry]:
    fp.seek(cookie.table_of_contents_pos, os.SEEK_SET)
    entries: list[TocEntry] = []
    parsed_len = 0
    fixed_len = struct.calcsize(TOC_ENTRY_FIXED_STRUCT)
    size_len = struct.calcsize(TOC_ENTRY_SIZE_STRUCT)
    while parsed_len < cookie.table_of_contents_size:
        size_raw = fp.read(size_len)
        if len(size_raw) != size_len:
            raise TocError("Unexpected EOF while reading TOC entry size")
        try:
            (entry_size,) = struct.unpack(TOC_ENTRY_SIZE_STRUCT, size_raw)
        except struct.error as e:
            raise TocError(f"Failed to read TOC entry size: {e}") from e
        if entry_size < size_len + fixed_len:
            raise TocError(f"Invalid TOC entry size: {entry_size}")
        rest = fp.read(entry_size - size_len)
        if len(rest) != entry_size - size_len:
            raise TocError("Unexpected EOF while reading TOC entry")
        name_len = entry_size - size_len - fixed_len
        try:
            entry_pos, cmprsd, uncmprsd, flag, typecode, name = struct.unpack(
                f"!IIIBc{name_len}s", rest
            )
        except struct.error as e:
            raise TocError(f"Failed to unpack TOC entry: {e}") from e
        entries.append(
            TocEntry(
                position=cookie.overlay_pos + entry_pos,
                cmprsd_data_size=cmprsd,
                uncmprsd_data_size=uncmprsd,
                cmprs_flag=flag,
                typecode=typecode,
                name=_sanitize_name(name),
            )
        )
        parsed_len += entry_size
    return entries


def parse_toc_from_path(
    path: str | os.PathLike[str], cookie: CookieInfo
) -> list[TocEntry]:
    with open(path, "rb") as fp:
        return parse_toc(fp, cookie)


def is_runtime_script(name: str) -> bool:
    return name.startswith(("pyiboot", "pyi_rth_", "pyi-"))


def print_toc(entries: list[TocEntry], limit: int | None = None) -> None:
    listed = [e for e in entries if not e.is_skip]
    print(f"[+] Found {len(listed)} files in CArchive")
    shown = listed if limit is None else listed[:limit]
    name_width = max((len(e.name) for e in shown), default=8)
    name_width = min(max(name_width, 8), 48)
    for e in shown:
        flag = "zlib" if e.cmprs_flag == 1 else "raw"
        tc = e.typecode.decode("ascii", errors="replace")
        print(
            f"    [{tc}] {e.name:<{name_width}}  "
            f"cmpr={e.cmprsd_data_size:>10}  "
            f"raw={e.uncmprsd_data_size:>10}  ({flag})"
        )
    if limit is not None and len(listed) > limit:
        print(f"    ... ({len(listed) - limit} more)")


def summarize_toc(entries: list[TocEntry]) -> None:
    entry_points = [
        e.name for e in entries if e.is_script and not is_runtime_script(e.name)
    ]
    runtime = [e.name for e in entries if e.is_script and is_runtime_script(e.name)]
    pyz = [
        e.name
        for e in entries
        if e.is_pyz or (e.typecode == TYPE_ZIPFILE and e.name.lower().endswith(".pyz"))
    ]
    modules = sum(1 for e in entries if e.typecode in (TYPE_PYMODULE, TYPE_PYPACKAGE))
    encrypted = any(e.is_crypto_key for e in entries if not e.is_skip)
    print(f"[+] Entry points: {', '.join(entry_points) or 'None'}")
    if runtime:
        print(f"[+] Runtime scripts: {', '.join(runtime)}")
    print(f"[+] PYZ archives: {', '.join(pyz) or 'None'}")
    print(f"[+] CArchive modules: {modules}")
    print(f"[+] Encrypted PYZ: {'Yes' if encrypted else 'No'}")
