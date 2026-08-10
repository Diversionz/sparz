from __future__ import annotations

import io
import sys
import zipfile
import zlib
from pathlib import Path

from .const import (
    PYZ_MAGIC,
    TYPE_NESTED_ARCHIVE,
    TYPE_PYMODULE,
    TYPE_PYPACKAGE,
    TYPE_SYMLINK,
    TYPE_ZIPFILE,
    ProfileError,
    has_pyc_header,
)
from .cookie import CookieError, print_cookie_info, read_cookie_from_path
from .paths import ensure_unique, rel_parts, safe_out_path
from .pyc import (
    PycError,
    fix_bare_pyc_magic,
    guess_code_name,
    maybe_capture_magic_from_module,
    write_pyc,
)
from .pyz import PyzError, extract_pyz, load_crypto_key_from_blob
from .toc import (
    TocEntry,
    TocError,
    is_runtime_script,
    parse_toc,
    print_toc,
    summarize_toc,
)


class ArchiveError(Exception):
    pass


def _read_entry_data(fp, entry: TocEntry) -> bytes:
    fp.seek(entry.position)
    data = fp.read(entry.cmprsd_data_size)
    if len(data) != entry.cmprsd_data_size:
        raise ArchiveError(
            f"Short read for {entry.name}: got {len(data)}, "
            f"expected {entry.cmprsd_data_size}"
        )
    if entry.cmprs_flag == 1:
        try:
            data = zlib.decompress(data)
        except zlib.error as e:
            raise ArchiveError(f"Failed to decompress {entry.name}: {e}") from e
        if len(data) != entry.uncmprsd_data_size:
            print(
                f"[!] Warning: uncompressed size mismatch for {entry.name}: "
                f"got {len(data)}, expected {entry.uncmprsd_data_size}"
            )
    return data


def _apply_recovered_name(entry: TocEntry, recovered: str, taken: set[str]) -> bool:
    parts = rel_parts(recovered)
    candidate = "/".join(parts)
    if not candidate or candidate in taken:
        return False
    taken.discard(entry.name)
    taken.add(candidate)
    entry.name = candidate
    return True


def _enrich_fallback_names(
    fp, entries: list[TocEntry], ctx, exe_stem: str | None = None
) -> bytes:
    magic = b"\0" * 4
    taken = {e.name for e in entries}
    cached: dict[int, bytes] = {}

    for entry in entries:
        if not entry.is_python:
            continue
        try:
            data = _read_entry_data(fp, entry)
        except ArchiveError as e:
            print(f"[!] {e}", file=sys.stderr)
            continue
        cached[id(entry)] = data
        captured = maybe_capture_magic_from_module(data, ctx)
        if captured:
            magic = captured

    write_magic = magic if magic != b"\0" * 4 else ctx.magic
    for entry in entries:
        if not entry.is_fallback_name or not entry.is_python:
            continue
        data = cached.get(id(entry))
        if data is None:
            print(f"[!] Warning: unnamed TOC entry remains {entry.name}")
            continue
        recovered = guess_code_name(data, ctx, write_magic)
        if recovered and _apply_recovered_name(entry, recovered, taken):
            continue
        if (
            entry.is_script
            and exe_stem
            and not is_runtime_script(exe_stem)
            and not is_runtime_script(entry.name)
            and _apply_recovered_name(entry, exe_stem, taken)
        ):
            continue
        print(f"[!] Warning: unnamed TOC entry remains {entry.name}")
    for entry in entries:
        if entry.is_fallback_name and not entry.is_python:
            print(f"[!] Warning: unnamed TOC entry remains {entry.name}")
    return magic


def _safe_extract_zip(data: bytes, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            parts = rel_parts(info.filename)
            target = dest.joinpath(*parts)
            try:
                target.resolve().relative_to(root)
            except ValueError:
                print(
                    f"[!] Warning: skipping unsafe zip path {info.filename!r}",
                    file=sys.stderr,
                )
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info))


def _write_symlink(root: Path, name: str, data: bytes) -> Path:
    target = data.split(b"\0", 1)[0].decode("utf-8", errors="replace")
    link_path = ensure_unique(safe_out_path(root, name))
    link_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if link_path.exists() or link_path.is_symlink():
            link_path.unlink()
        link_path.symlink_to(target)
        return link_path
    except OSError:
        out = ensure_unique(safe_out_path(root, name, ".symlink"))
        out.write_text(target, encoding="utf-8")
        print(f"[!] Warning: could not create symlink {name}; wrote {out.name}")
        return out


def _extract_pyz_entry(
    data: bytes,
    entry: TocEntry,
    extract_root: Path,
    one_dir: bool,
    ctx,
    crypto_key: bytes | None,
    write_magic: bytes,
) -> bytes:
    pyz_path = ensure_unique(safe_out_path(extract_root, entry.name))
    pyz_path.parent.mkdir(parents=True, exist_ok=True)
    pyz_path.write_bytes(data)
    pyz_out = extract_root if one_dir else extract_root / f"{pyz_path.name}_extracted"
    pyz_out.mkdir(parents=True, exist_ok=True)
    print(f"[+] Extracting PYZ -> {pyz_out}")
    try:
        _, magic = extract_pyz(
            pyz_path,
            pyz_out,
            ctx,
            crypto_key=crypto_key,
            magic=write_magic,
        )
        return magic
    except (PyzError, OSError, ValueError, TypeError) as e:
        print(f"[!] PYZ extract failed: {e}", file=sys.stderr)
        return write_magic


def _extract_nested_archive(
    data: bytes,
    entry: TocEntry,
    extract_root: Path,
    one_dir: bool,
    depth: int,
) -> None:
    if depth >= 8:
        print(
            f"[!] Warning: nested archive depth exceeded for {entry.name}",
            file=sys.stderr,
        )
        out_path = ensure_unique(safe_out_path(extract_root, entry.name))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        return
    nest_path = ensure_unique(safe_out_path(extract_root, entry.name))
    nest_path.parent.mkdir(parents=True, exist_ok=True)
    nest_path.write_bytes(data)
    nest_out = extract_root if one_dir else extract_root / f"{nest_path.name}_extracted"
    print(f"[+] Extracting nested archive -> {nest_out}")
    try:
        extract_archive(nest_path, out_dir=nest_out, one_dir=one_dir, _depth=depth + 1)
    except ArchiveError as e:
        print(f"[!] Nested archive extract failed: {e}", file=sys.stderr)


def extract_archive(
    exe_path: str | Path,
    *,
    out_dir: str | Path | None = None,
    one_dir: bool = False,
    info_only: bool = False,
    _depth: int = 0,
) -> Path | None:
    exe_path = Path(exe_path)
    if not exe_path.is_file():
        raise ArchiveError(f"Not a file: {exe_path}")

    try:
        cookie = read_cookie_from_path(exe_path)
    except CookieError as e:
        raise ArchiveError(str(e)) from e
    print(f"[+] Processing {exe_path.name}")
    print_cookie_info(cookie)

    try:
        ctx = cookie.version_context()
    except ProfileError as e:
        raise ArchiveError(f"Unsupported Python version in cookie: {e}") from e
    try:
        with exe_path.open("rb") as fp:
            entries = parse_toc(fp, cookie)
            magic = _enrich_fallback_names(fp, entries, ctx, exe_stem=exe_path.stem)
    except TocError as e:
        raise ArchiveError(str(e)) from e
    print_toc(entries, limit=40)
    summarize_toc(entries)
    if info_only:
        return None

    extract_root = (
        Path(out_dir)
        if out_dir is not None
        else Path.cwd() / f"{exe_path.name}_extracted"
    )
    extract_root.mkdir(parents=True, exist_ok=True)
    print(f"[+] Extracting to {extract_root}")

    crypto_key: bytes | None = None
    bare_pycs: list[Path] = []

    with exe_path.open("rb") as fp:
        for entry in entries:
            if entry.is_skip or not entry.is_crypto_key:
                continue
            try:
                data = _read_entry_data(fp, entry)
            except ArchiveError as e:
                print(f"[!] {e}", file=sys.stderr)
                continue
            captured = maybe_capture_magic_from_module(data, ctx)
            if captured:
                magic = captured
            try:
                crypto_key = load_crypto_key_from_blob(
                    data, ctx, magic if magic != b"\0" * 4 else ctx.magic
                )
                print("[+] Loaded crypto key for PYZ decryption")
            except (PyzError, ValueError, TypeError, AttributeError, OSError) as e:
                print(f"[!] Failed to load crypto key: {e}", file=sys.stderr)

        for entry in entries:
            if entry.is_skip:
                continue
            try:
                data = _read_entry_data(fp, entry)
            except ArchiveError as e:
                print(f"[!] {e}", file=sys.stderr)
                continue

            if entry.typecode in (TYPE_PYMODULE, TYPE_PYPACKAGE):
                captured = maybe_capture_magic_from_module(data, ctx)
                if captured:
                    magic = captured

            write_magic = magic if magic != b"\0" * 4 else ctx.magic

            try:
                if entry.is_script:
                    if not is_runtime_script(entry.name):
                        print(f"[+] Entry point: {entry.name}.pyc")
                    out_path = ensure_unique(
                        safe_out_path(extract_root, entry.name, ".pyc")
                    )
                    write_pyc(out_path, data, ctx, write_magic)
                    if magic == b"\0" * 4:
                        bare_pycs.append(out_path)
                elif entry.typecode in (TYPE_PYMODULE, TYPE_PYPACKAGE):
                    out_path = ensure_unique(
                        safe_out_path(extract_root, entry.name, ".pyc")
                    )
                    write_pyc(out_path, data, ctx, write_magic)
                    if magic == b"\0" * 4 and not has_pyc_header(data, ctx.header):
                        bare_pycs.append(out_path)
                elif entry.is_pyz or (
                    entry.typecode == TYPE_ZIPFILE and data[:4] == PYZ_MAGIC
                ):
                    magic = _extract_pyz_entry(
                        data,
                        entry,
                        extract_root,
                        one_dir,
                        ctx,
                        crypto_key,
                        write_magic,
                    )
                elif entry.typecode == TYPE_ZIPFILE:
                    zip_path = ensure_unique(safe_out_path(extract_root, entry.name))
                    zip_path.parent.mkdir(parents=True, exist_ok=True)
                    zip_path.write_bytes(data)
                    if zipfile.is_zipfile(io.BytesIO(data)):
                        zip_out = (
                            extract_root
                            if one_dir
                            else extract_root / f"{zip_path.name}_extracted"
                        )
                        print(f"[+] Extracting ZIP -> {zip_out}")
                        try:
                            _safe_extract_zip(data, zip_out)
                        except (zipfile.BadZipFile, OSError) as e:
                            print(f"[!] ZIP extract failed: {e}", file=sys.stderr)
                elif entry.typecode == TYPE_NESTED_ARCHIVE:
                    _extract_nested_archive(data, entry, extract_root, one_dir, _depth)
                elif entry.typecode == TYPE_SYMLINK:
                    _write_symlink(extract_root, entry.name, data)
                else:
                    out_path = ensure_unique(safe_out_path(extract_root, entry.name))
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_bytes(data)
            except (PycError, OSError) as e:
                print(f"[!] Failed to write {entry.name}: {e}", file=sys.stderr)

    final_magic = magic if magic != b"\0" * 4 else ctx.magic
    for path in bare_pycs:
        try:
            fix_bare_pyc_magic(path, final_magic)
        except (PycError, OSError) as e:
            print(f"[!] Failed to fix magic for {path}: {e}", file=sys.stderr)

    print(f"[+] Done. Extracted to {extract_root}")
    return extract_root
