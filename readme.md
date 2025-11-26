# Semantic-Aware Firmware Diff Generator

[中文版请参见 `readme.zh.md`](readme.zh.md)。

This project provides a firmware delta update generator designed for resource-constrained microcontrollers (e.g. micro/nano satellites). It produces small, frame-friendly patch streams that can be verified and applied with minimal RAM on the target.

Key features:

- Semantic-aware global matching with disassembly-derived normalization.
- Tiny apply-side decoder (COPY/ADD/PATCH opcodes, zlib-compressed stream, optional CDC handling).
- Frame packaging (default 502-byte payloads) with multi-level CRC.
- Tools for patch analysis/simulation (`patch_sim.py`, `analyze_new_repeats.py`).

---

## Requirements / Environment

1. **IAR-generated `.out` firmware.**  
   The current pipeline relies on the IAR ELF format because we parse IAR’s sections/symbols/disassembly.
2. **IAR dump conversion tool (`generator/tools/iar_dump2json.py`).**  
   This wraps `ielfdumparm.exe` to convert `.out` → `.txt` and `.json`, capturing sections, symbols, and normalization hints.
3. **Python 3.8+** with the packages already vendored in this repo (no extra installation required).  
   On Windows, run from the provided Anaconda/Miniconda prompt or standard Python.

---

## Usage

### 1. Convert `.out` → `.json` (and `.txt`)

```bash
python -m generator.tools.iar_dump2json \
  --out QLS01CDHS224.out \
  --json QLS01CDHS224.json \
  --txt  QLS01CDHS224.txt
```

Repeat for the “new” firmware. This step uses IAR’s `ielfdumparm.exe`, so ensure it is available in `PATH` or the script’s directory.

### 2. Generate patch (`generate.py`)

```bash
python -m generator.generate gen \
  --old QLS01CDHS224.bin \
  --new QLS01CDHS225.bin \
  --old-sym QLS01CDHS224.json \
  --new-sym QLS01CDHS225.json \
  --flash-base 0x00000000 \
  --out QLS01CDHSpatch.bin \
  --mode global \
  --arch-mode arm \
  --endian be \
  --verify
```

Notes:
- `--mode global` is now the default/preferred global semantic path (advanced mode remains available for experiments via `--mode advanced`).
- `--verify` runs `apply_patch.py` locally to ensure the patch reconstructs the new firmware; if it fails in global mode, the process stops without fallback (advanced mode falls back to global-only automatically).
- Adjust `--arch-mode` / `--endian` per your target (QLS uses ARM big-endian; USB CDC uses ARM little-endian).

### 3. Optional: Simulate patch application (RAM/time estimates)

```bash
python -m generator.tools.patch_sim \
  --old QLS01CDHS224.bin \
  --patch QLS01CDHSpatch.bin \
  --new QLS01CDHS225.bin \
  --payload 502 \
  --scale 50
```

This reports decompressed size, max PATCH block length, rough peak RAM, and PC apply time (scaled to MCU via `--scale`).

---

## Directory Overview

- `generator/generate.py` – main patch generator CLI.
- `generator/tools/iar_dump2json.py` – convert `.out` → `.json`/`.txt`.
- `generator/tools/apply_patch.py` – apply and verify patch streams.
- `generator/tools/patch_sim.py` – simulate resource usage and timing.
- `generator/tools/analyze_new_repeats.py` – analyze potential for `COPY_NEW` style optimizations.
- `global.py` – convenience script for running the global patch generator with preset arguments.

---

## Notes & Limitations

- Currently supports **IAR toolchain outputs** only; other toolchains would require equivalent ELF/dump parsers.
- The MCU-side decoder currently expects zlib-compressed patches; if RAM is extremely limited, consider generating uncompressed patches (larger download, smaller decoder memory) or chunked PATCH implementations.
- Ensure `ielfdumparm.exe` (part of IAR) is licensed/available; the repo provides wrappers but not the binary itself.

For questions or contributions, open an issue or submit a pull request.
