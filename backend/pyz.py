from __future__ import annotations

import os
import struct
import sys
import zlib
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter
from xdis.unmarshal import load_code

from .const import (
    PYZ_ITEM_DATA,
    PYZ_ITEM_NSPKG,
    PYZ_ITEM_PKG,
    PYZ_MAGIC,
    VersionContext,
    normalize_aes_key,
)
from .paths import ensure_unique, rel_parts, safe_module_path, safe_out_path
from .pyc import PycError, extract_crypto_key_blob, write_pyc


class PyzError(Exception):
    pass


def pyc_header_to_magic_int(header: bytes) -> int:
    if len(header) < 2:
        raise PyzError("pyc magic too short")
    return header[1] << 8 | header[0]


def try_decrypt(ct: bytes, key: bytes, mode: str) -> bytes:
    key = normalize_aes_key(key)
    if len(ct) < 16:
        raise PyzError("ciphertext too short for IV")

    iv = ct[:16]
    body = ct[16:]

    if mode == "ctr":
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(body)
    if mode in ("cfb", "cfb8"):
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=8)
        return cipher.decrypt(body)
    if mode == "cfb128":
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        return cipher.decrypt(body)
    raise PyzError(f"Unknown AES mode: {mode}")


def load_crypto_key_from_blob(
    blob: bytes, ctx: VersionContext, magic: bytes | None = None
) -> bytes:
    code_blob = extract_crypto_key_blob(blob, ctx)
    magic = magic if magic is not None else ctx.magic
    co = load_code(code_blob, pyc_header_to_magic_int(magic))
    key = co.co_consts[0]
    if isinstance(key, (str, bytes)):
        return normalize_aes_key(key)
    raise PyzError(f"Unexpected crypto key type: {type(key)}")


def _decompress_or_decrypt(
    data: bytes, ctx: VersionContext, crypto_key: bytes | None
) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error:
        if not crypto_key:
            raise PyzError("zlib failed and no crypto key available")

        last_err: Exception | None = None
        for mode in ctx.encryption_try_order:
            try:
                pt = try_decrypt(data, crypto_key, mode)
                return zlib.decompress(pt)
            except (PyzError, ValueError, TypeError, zlib.error) as e:
                last_err = e
                continue
        raise PyzError(f"decrypt+decompress failed: {last_err}") from last_err


def _normalize_modname(key: object) -> str:
    if isinstance(key, bytes):
        try:
            return key.decode("utf-8")
        except UnicodeDecodeError:
            return f"unnamed_{key.hex()}"
    return str(key)


def extract_pyz(
    pyz_path: str | Path,
    out_dir: str | Path,
    ctx: VersionContext,
    *,
    crypto_key: bytes | None = None,
    magic: bytes | None = None,
) -> tuple[list[Path], bytes]:
    pyz_path = Path(pyz_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    magic = magic if magic is not None else ctx.magic
    with pyz_path.open("rb") as f:
        if f.read(4) != PYZ_MAGIC:
            raise PyzError(f"Not a PYZ archive: {pyz_path}")
        pyz_pyc_magic = f.read(4)
        if magic == b"\0" * 4 or magic != pyz_pyc_magic:
            if magic not in (b"\0" * 4, pyz_pyc_magic):
                print(
                    "[!] Warning: PYZ pyc magic differs from CArchive; using PYZ magic"
                )
            magic = pyz_pyc_magic
        toc_raw = f.read(4)
        if len(toc_raw) != 4:
            raise PyzError("Truncated PYZ header")
        (toc_position,) = struct.unpack("!i", toc_raw)
        f.seek(toc_position, os.SEEK_SET)
        try:
            toc = load_code(f, pyc_header_to_magic_int(pyz_pyc_magic))
        except (EOFError, ValueError, TypeError, AttributeError, OSError) as e:
            raise PyzError(f"Failed to unmarshal PYZ TOC: {e}") from e

        if isinstance(toc, list):
            toc = dict(toc)
        print(f"[+] Found {len(toc)} files in PYZ archive")
        for key, (ispkg, pos, length) in toc.items():
            file_name = _normalize_modname(key).replace(".", os.path.sep)
            parts = rel_parts(file_name)

            if ispkg == PYZ_ITEM_NSPKG:
                dir_path = out_dir.joinpath(*parts)
                dir_path.mkdir(parents=True, exist_ok=True)
                written.append(dir_path)
                continue

            is_data = ispkg == PYZ_ITEM_DATA
            if is_data:
                file_path = ensure_unique(safe_out_path(out_dir, file_name))
            else:
                file_path = ensure_unique(
                    safe_module_path(out_dir, file_name, ispkg == PYZ_ITEM_PKG)
                )
            if length == 0:
                print(f"[!] Warning: empty PYZ entry {file_path}")
                try:
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    if is_data:
                        file_path.write_bytes(b"")
                    else:
                        write_pyc(file_path, b"", ctx, magic)
                    written.append(file_path)
                except (PycError, OSError) as e:
                    print(f"[!] {e}", file=sys.stderr)
                continue
            f.seek(pos, os.SEEK_SET)
            data = f.read(length)
            if len(data) != length:
                print(
                    f"[!] Warning: short read for PYZ entry {file_path}: "
                    f"got {len(data)}, expected {length}",
                    file=sys.stderr,
                )
                continue
            try:
                data = _decompress_or_decrypt(data, ctx, crypto_key)
            except PyzError as e:
                enc_path = ensure_unique(Path(str(file_path) + ".encrypted"))
                enc_path.parent.mkdir(parents=True, exist_ok=True)
                enc_path.write_bytes(data)
                print(f"[!] {e}; saved {enc_path}", file=sys.stderr)
                continue

            try:
                if is_data:
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    file_path.write_bytes(data)
                else:
                    write_pyc(file_path, data, ctx, magic)
                written.append(file_path)
            except (PycError, OSError) as e:
                print(f"[!] {e}", file=sys.stderr)
    return written, magic
