from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COOKIE_MAGIC = b"MEI\014\013\012\013\016"
PYZ_MAGIC = b"PYZ\0"

PYINST20_COOKIE_SIZE = 24
PYINST21_COOKIE_SIZE = 24 + 64

PYINST20_COOKIE_STRUCT = "!8sIIII"
PYINST21_COOKIE_STRUCT = "!8sIIII64s"

TOC_ENTRY_SIZE_STRUCT = "!I"
TOC_ENTRY_FIXED_STRUCT = "!IIIBc"

TYPE_PYSOURCE = b"s"
TYPE_PYMODULE = b"m"
TYPE_PYPACKAGE = b"M"
TYPE_PYZ = b"z"
TYPE_ZIPFILE = b"Z"
TYPE_DEPENDENCY = b"d"
TYPE_RUNTIME_OPTION = b"o"
TYPE_DATA = b"x"
TYPE_SPLASH = b"l"
TYPE_SYMLINK = b"n"
TYPE_NESTED_ARCHIVE = b"a"
TYPE_BINARY = b"b"

SKIP_TYPECODES = {TYPE_DEPENDENCY, TYPE_RUNTIME_OPTION}
PYZ_TYPECODES = {TYPE_PYZ}
PYTHON_TYPECODES = {TYPE_PYSOURCE, TYPE_PYMODULE, TYPE_PYPACKAGE}

PYZ_ITEM_MODULE = 0
PYZ_ITEM_PKG = 1
PYZ_ITEM_DATA = 2
PYZ_ITEM_NSPKG = 3

SUPPORTED_PYTHON = "3.6-3.13"
VERSIONS_DIR = Path(__file__).resolve().parent / "versions"
DEFAULT_ENCRYPTION_TRY_ORDER = ["ctr", "cfb8", "cfb128"]


class ProfileError(Exception):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_all_profiles(versions_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    root = versions_dir or VERSIONS_DIR
    if not root.is_dir():
        raise ProfileError(f"Versions directory not found: {root}")
    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.json")):
        data = _load_json(path)
        pid = data.get("id") or path.stem
        profiles[pid] = data
        profiles.setdefault(path.stem, data)
    return profiles


def list_band_profiles(profiles: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    bands = []
    seen = set()
    for data in profiles.values():
        pid = data.get("id")
        if not pid or pid in seen:
            continue
        if "detect" in data and "cookie_pyver" in data["detect"]:
            bands.append(data)
            seen.add(pid)
    return bands


def decode_cookie_pyver(pyver: int) -> tuple[int, int]:
    if pyver >= 100:
        return pyver // 100, pyver % 100
    return pyver // 10, pyver % 10


def encode_cookie_pyver(major: int, minor: int) -> int:
    return major * 100 + minor


def _pyver_candidates(pyver: int) -> list[int]:
    candidates = [pyver]
    major, minor = decode_cookie_pyver(pyver)
    normalized = encode_cookie_pyver(major, minor)
    if normalized not in candidates:
        candidates.append(normalized)
    short = major * 10 + minor if minor < 10 else None
    if short is not None and short not in candidates:
        candidates.append(short)
    return candidates


def find_band_for_pyver(
    pyver: int, profiles: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    profiles = profiles if profiles is not None else load_all_profiles()
    candidates = _pyver_candidates(pyver)
    for band in list_band_profiles(profiles):
        detect = band["detect"]["cookie_pyver"]
        if any(c in detect for c in candidates):
            return band
    major, minor = decode_cookie_pyver(pyver)
    raise ProfileError(
        f"No band for cookie pyver={pyver} (Python {major}.{minor}). "
        f"Supported in this build: {SUPPORTED_PYTHON}"
    )


def resolve_pyc_header_profile(
    band: dict[str, Any], pyver: int, profiles: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    profiles = profiles if profiles is not None else load_all_profiles()
    candidates = _pyver_candidates(pyver)
    for rule in band.get("resolve_pyc_profile", []):
        when = rule.get("when_pyver", [])
        if any(c in when for c in candidates):
            pid = rule["profile"]
            if pid not in profiles:
                raise ProfileError(f"Missing pyc header profile: {pid}")
            return profiles[pid]
    raise ProfileError(f"No pyc header rule for pyver={pyver} in band {band.get('id')}")


def resolve_magics_profile(
    band: dict[str, Any], profiles: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    profiles = profiles if profiles is not None else load_all_profiles()
    pid = band.get("magics_profile")
    if not pid:
        raise ProfileError(f"Band {band.get('id')} has no magics_profile")
    if pid not in profiles:
        raise ProfileError(f"Missing magics profile: {pid}")
    return profiles[pid]


def magic_for_version(major: int, minor: int, magics_profile: dict[str, Any]) -> bytes:
    key = f"{major}.{minor}"
    entry = magics_profile.get("magics", {}).get(key)
    if not entry:
        raise ProfileError(f"No magic for Python {key} in {magics_profile.get('id')}")
    hex_str = entry.get("bytes_hex") or ""
    if hex_str:
        return bytes.fromhex(hex_str)
    magic_int = int(entry["int"])
    return magic_int.to_bytes(2, "little") + b"\r\n"


def fabricate_header_suffix(header_profile: dict[str, Any]) -> bytes:
    fab = header_profile.get("fabricate", {})
    out = bytearray()
    for field in header_profile.get("layout", []):
        if field == "magic":
            continue
        hex_str = fab.get(field)
        if hex_str is None:
            raise ProfileError(
                f"fabricate missing field {field!r} in {header_profile.get('id')}"
            )
        out.extend(bytes.fromhex(hex_str))
    return bytes(out)


def header_marker_bytes(header_profile: dict[str, Any]) -> tuple[int, bytes]:
    marker = header_profile["header_marker"]
    return int(marker["offset"]), bytes(marker["bytes"])


def has_pyc_header(data: bytes, header_profile: dict[str, Any]) -> bool:
    offset, expected = header_marker_bytes(header_profile)
    return (
        len(data) >= offset + len(expected)
        and data[offset : offset + len(expected)] == expected
    )


def normalize_aes_key(key: str | bytes) -> bytes:
    if isinstance(key, bytes):
        try:
            key = key.decode("utf-8")
        except UnicodeDecodeError:
            key = key.decode("latin-1")
    if len(key) > 16:
        key = key[:16]
    else:
        key = key.zfill(16)
    return key.encode("utf-8")


class VersionContext:
    def __init__(self, pyver: int, profiles: dict[str, dict[str, Any]] | None = None):
        self.profiles = profiles if profiles is not None else load_all_profiles()
        self.pyver = pyver
        self.major, self.minor = decode_cookie_pyver(pyver)
        self.band = find_band_for_pyver(pyver, self.profiles)
        self.header = resolve_pyc_header_profile(self.band, pyver, self.profiles)
        self.magics = resolve_magics_profile(self.band, self.profiles)
        self.magic = magic_for_version(self.major, self.minor, self.magics)
        self.header_size = int(self.header["header_size"])
        self.crypto_key_object_offset = int(self.header["crypto_key_object_offset"])
        order = self.band.get("pyz", {}).get("encryption_try_order")
        self.encryption_try_order = list(order or DEFAULT_ENCRYPTION_TRY_ORDER)

    @property
    def python_version(self) -> str:
        return f"{self.major}.{self.minor}"

    def __repr__(self) -> str:
        return (
            f"VersionContext(python={self.python_version!r}, "
            f"band={self.band.get('id')!r}, header={self.header.get('id')!r})"
        )
