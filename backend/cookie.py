from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

from .const import (
    COOKIE_MAGIC,
    PYINST20_COOKIE_SIZE,
    PYINST20_COOKIE_STRUCT,
    PYINST21_COOKIE_SIZE,
    PYINST21_COOKIE_STRUCT,
    VersionContext,
    decode_cookie_pyver,
)


class CookieError(Exception):
    pass


@dataclass
class CookieInfo:
    cookie_pos: int
    pyinst_ver: int
    length_of_package: int
    toc: int
    pyver: int
    pylibname: str | None
    overlay_pos: int
    overlay_size: int
    table_of_contents_pos: int
    table_of_contents_size: int
    file_size: int

    @property
    def python_major_minor(self) -> tuple[int, int]:
        return decode_cookie_pyver(self.pyver)

    @property
    def python_version(self) -> str:
        major, minor = self.python_major_minor
        return f"{major}.{minor}"

    def version_context(self) -> VersionContext:
        return VersionContext(self.pyver)


def find_cookie_pos(fp: BinaryIO, file_size: int, chunk_size: int = 8192) -> int:
    if file_size < len(COOKIE_MAGIC):
        return -1

    end_pos = file_size
    while True:
        start_pos = end_pos - chunk_size if end_pos >= chunk_size else 0
        chunk = end_pos - start_pos
        if chunk < len(COOKIE_MAGIC):
            break

        fp.seek(start_pos, os.SEEK_SET)
        data = fp.read(chunk)
        offs = data.rfind(COOKIE_MAGIC)
        if offs != -1:
            return start_pos + offs

        end_pos = start_pos + len(COOKIE_MAGIC) - 1
        if start_pos == 0:
            break
    return -1


def detect_pyinst_generation(fp: BinaryIO, cookie_pos: int) -> int:
    fp.seek(cookie_pos + PYINST20_COOKIE_SIZE, os.SEEK_SET)
    tail = fp.read(64)
    if b"python" in tail.lower():
        return 21
    return 20


def parse_cookie(fp: BinaryIO, cookie_pos: int, file_size: int) -> CookieInfo:
    pyinst_ver = detect_pyinst_generation(fp, cookie_pos)
    fp.seek(cookie_pos, os.SEEK_SET)
    pylibname: str | None = None

    try:
        if pyinst_ver == 20:
            raw = fp.read(PYINST20_COOKIE_SIZE)
            if len(raw) != PYINST20_COOKIE_SIZE:
                raise CookieError("Truncated PyInstaller 2.0 cookie")
            (
                magic,
                length_of_package,
                toc,
                toc_len,
                pyver,
            ) = struct.unpack(PYINST20_COOKIE_STRUCT, raw)
        else:
            raw = fp.read(PYINST21_COOKIE_SIZE)
            if len(raw) != PYINST21_COOKIE_SIZE:
                raise CookieError("Truncated PyInstaller 2.1+ cookie")
            magic, length_of_package, toc, toc_len, pyver, pylib_raw = struct.unpack(
                PYINST21_COOKIE_STRUCT, raw
            )
            pylibname = pylib_raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
    except struct.error as e:
        raise CookieError(f"Failed to parse cookie: {e}") from e

    if magic != COOKIE_MAGIC:
        raise CookieError(f"Bad cookie magic at {cookie_pos}: {magic!r}")

    cookie_size = PYINST20_COOKIE_SIZE if pyinst_ver == 20 else PYINST21_COOKIE_SIZE
    tail_bytes = file_size - cookie_pos - cookie_size
    if tail_bytes < 0:
        raise CookieError("Cookie extends past end of file")
    overlay_size = length_of_package + tail_bytes
    overlay_pos = file_size - overlay_size
    if overlay_pos < 0:
        raise CookieError("Invalid overlay position computed from cookie")
    table_of_contents_pos = overlay_pos + toc
    table_of_contents_size = toc_len
    if table_of_contents_pos < 0 or table_of_contents_pos > file_size:
        raise CookieError("Invalid TOC position computed from cookie")
    if table_of_contents_pos + table_of_contents_size > file_size:
        raise CookieError("TOC extends past end of file")
    return CookieInfo(
        cookie_pos=cookie_pos,
        pyinst_ver=pyinst_ver,
        length_of_package=length_of_package,
        toc=toc,
        pyver=pyver,
        pylibname=pylibname,
        overlay_pos=overlay_pos,
        overlay_size=overlay_size,
        table_of_contents_pos=table_of_contents_pos,
        table_of_contents_size=table_of_contents_size,
        file_size=file_size,
    )


def read_cookie_from_path(path: str | os.PathLike[str]) -> CookieInfo:
    path = os.fspath(path)
    try:
        file_size = os.stat(path).st_size
    except OSError as e:
        raise CookieError(f"Cannot stat {path}: {e}") from e

    with open(path, "rb") as fp:
        cookie_pos = find_cookie_pos(fp, file_size)
        if cookie_pos == -1:
            raise CookieError(
                "Missing cookie: unsupported PyInstaller version or not a PyInstaller archive"
            )
        return parse_cookie(fp, cookie_pos, file_size)


def print_cookie_info(info: CookieInfo) -> None:
    gen = "2.0" if info.pyinst_ver == 20 else "2.1+"
    lib = f" | {info.pylibname}" if info.pylibname else ""
    print(
        f"[+] PyInstaller {gen} | Python {info.python_version} (pyver={info.pyver}){lib}"
    )
    print(
        f"[+] Cookie @{info.cookie_pos} | Overlay @{info.overlay_pos} "
        f"({info.overlay_size} bytes) | TOC @{info.table_of_contents_pos} "
        f"({info.table_of_contents_size} bytes) | Package {info.length_of_package} bytes"
    )
