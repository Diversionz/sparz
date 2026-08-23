# Sparz

Extract and inspect PyInstaller executables.

## Features

- Locate and parse CArchive cookies (PyInstaller 2.0 and 2.1+)
- List TOC entries and summarize scripts, PYZ archives, and encryption
- Extract bundled files, including nested PYZ contents
- Decrypt encrypted PYZ payloads (AES-CTR and AES-CFB)
- Rebuild `.pyc` headers for Python 3.6–3.13 bytecode

## Requirements

- Python 3.9 or newer
- [xdis](https://pypi.org/project/xdis/) 6.3.0
- [pycryptodome](https://pypi.org/project/pycryptodome/) 3.23.0

## Installation

```bash
pip install -e .
```

## Usage

```bash
sparz path/to/app.exe
```

Show archive metadata without extracting:

```bash
sparz -i path/to/app.exe
```

Extract PYZ modules alongside CArchive files:

```bash
sparz -d path/to/app.exe
```

Choose an output directory:

```bash
sparz -o ./out path/to/app.exe
```

## Output

By default, files are written to `<exe>_extracted` in the current working directory. Scripts and modules are written as `.pyc` files suitable for a decompiler. Encrypted PYZ entries that cannot be decrypted are saved with a `.encrypted` suffix.

## License

MIT License. Copyright (c) 2026 Diversion
