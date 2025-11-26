# Semantic-Aware Firmware Diff Generator / 语义感知固件差分生成器

<p align="right">
Language / 语言：<a href="#readme-en">English</a> | <a href="#readme-zh">简体中文</a>
</p>

---

<a id="readme-en"></a>

## English

This project provides a firmware delta update generator designed for resource-constrained microcontrollers. It produces small, frame-friendly patch streams that can be verified and applied with minimal RAM on the target.

### Key Features

- Semantic-aware global matching with disassembly-derived normalization.
- Tiny apply-side decoder (COPY/ADD/PATCH opcodes, zlib-compressed stream, optional CDC handling).
- Frame packaging (default 502-byte payloads) with multi-level CRC.
- Tools for patch analysis/simulation (`patch_sim.py`, `analyze_new_repeats.py`).

### Requirements / Environment

1. **IAR-generated `.out` firmware.**  
   The current pipeline relies on the IAR ELF format because we parse IAR’s sections/symbols/disassembly.
2. **IAR dump conversion tool (`generator/tools/iar_dump2json.py`).**  
   This wraps `ielfdumparm.exe` to convert `.out` to `.txt` and `.json`, capturing sections, symbols, and normalization hints.
3. **Python 3.8+** with the packages already vendored in this repo (no extra installation required).  
   On Windows, run from the provided Anaconda/Miniconda prompt or standard Python.

### Usage

#### 1. Convert `.out` to `.json` (and `.txt`)

```bash
python -m generator.tools.iar_dump2json \
  --out old.out \
  --json old.json \
  --txt  old.txt
```

Repeat for the “new” firmware. This step uses IAR’s `ielfdumparm.exe`, so ensure it is available in `PATH` or the script’s directory.

#### 2. Generate patch (`generate.py`)

```bash
python -m generator.generate gen \
  --old olf.bin \
  --new new.bin \
  --old-sym old.json \
  --new-sym new.json \
  --flash-base 0x00000000 \
  --out patch.bin \
  --mode global \
  --arch-mode arm \
  --endian be \
  --verify
```

Notes:
- `--mode global` is now the default/preferred global semantic path (advanced mode remains available for experiments via `--mode advanced`).
- `--verify` runs `apply_patch.py` locally to ensure the patch reconstructs the new firmware; if it fails in global mode, the process stops without fallback (advanced mode falls back to global-only automatically).
- Adjust `--arch-mode` / `--endian` per your target (QLS uses ARM big-endian; USB CDC uses ARM little-endian).

#### 3. Optional: Simulate patch application (RAM/time estimates)

```bash
python -m generator.tools.patch_sim \
  --old old.bin \
  --patch patch.bin \
  --new new.bin \
  --payload 502 \
  --scale 50
```

This reports decompressed size, max PATCH block length, rough peak RAM, and PC apply time (scaled to MCU via `--scale`).

### Directory Overview

- `generator/generate.py` — main patch generator CLI.
- `generator/tools/iar_dump2json.py` — convert `.out` to `.json`/`.txt`.
- `generator/tools/apply_patch.py` — apply and verify patch streams.
- `generator/tools/patch_sim.py` — simulate resource usage and timing.
- `generator/tools/analyze_new_repeats.py` — analyze potential for `COPY_NEW` style optimizations.
- `global.py` — convenience script for running the global patch generator with preset arguments.

### Notes & Limitations

- Currently supports **IAR toolchain outputs** only; other toolchains would require equivalent ELF/dump parsers.
- The MCU-side decoder currently expects zlib-compressed patches; if RAM is extremely limited, consider generating uncompressed patches (larger download, smaller decoder memory) or chunked PATCH implementations.
- Ensure `ielfdumparm.exe` (part of IAR) is licensed/available; the repo provides wrappers but not the binary itself.

For questions or contributions, open an issue or submit a pull request.

---

<a id="readme-zh"></a>

## 简体中文

本项目提供一个面向资源受限微控制器的固件增量更新生成器。它可以生成小型、易分帧的补丁流，并在目标端以极少 RAM 即可验证和应用。

### 主要特性

- 结合反汇编归一化的语义感知全局匹配。
- 轻量级补丁应用端解码器（COPY/ADD/PATCH 操作码，zlib 压缩流，可选 CDC 处理）。
- 带多级 CRC 的帧封装（默认 502 字节有效载荷）。
- 补丁分析/仿真工具（`patch_sim.py`、`analyze_new_repeats.py`）。

### 环境与依赖

1. **IAR 生成的 `.out` 固件。**  
   现有流程依赖 IAR ELF 格式，因为需要解析 IAR 的段、符号及反汇编。
2. **IAR 导出转换工具（`generator/tools/iar_dump2json.py`）。**  
   该脚本封装 `ielfdumparm.exe`，将 `.out` 转为 `.txt` 和 `.json`，同步记录段、符号与归一化提示信息。
3. **Python 3.8+**，所需包已随仓库提供，无需额外安装。  
   Windows 上可直接使用提供的 Anaconda/Miniconda 环境或系统 Python 运行。

### 使用方法

#### 1. 将 `.out` 转为 `.json`（和 `.txt`）

```bash
python -m generator.tools.iar_dump2json \
  --out old.out \
  --json old.json \
  --txt  old.txt
```

对“新”固件重复上述操作。该步骤依赖 IAR 的 `ielfdumparm.exe`，请确保其位于 `PATH` 或脚本目录中。

#### 2. 生成补丁（`generate.py`）

```bash
python -m generator.generate gen \
  --old old.bin \
  --new new.bin \
  --old-sym old.json \
  --new-sym new.json \
  --flash-base 0x00000000 \
  --out patch.bin \
  --mode global \
  --arch-mode arm \
  --endian be \
  --verify
```

说明：
- `--mode global` 现为默认/推荐的全局语义路径；若需实验，可通过 `--mode advanced` 启用高级模式。
- `--verify` 会运行 `apply_patch.py` 来确认补丁可重建新固件；若在 global 模式失败，流程会直接终止（advanced 模式会自动回退到全局流程）。
- 请根据目标 MCU 调整 `--arch-mode` / `--endian`（QLS 为 ARM 大端，USB CDC 为 ARM 小端）。

#### 3. 可选：仿真补丁应用（RAM/耗时评估）

```bash
python -m generator.tools.patch_sim \
  --old old.bin \
  --patch patch.bin \
  --new new.bin \
  --payload 502 \
  --scale 50
```

脚本会报告解压后大小、最大 PATCH 块长度、峰值 RAM 估算及按 `--scale` 缩放后的 MCU 端执行时间。

### 目录概览

- `generator/generate.py` —— 主补丁生成 CLI。
- `generator/tools/iar_dump2json.py` —— 将 `.out` 转为 `.json`/`.txt`。
- `generator/tools/apply_patch.py` —— 在本地应用并验证补丁流。
- `generator/tools/patch_sim.py` —— 仿真资源占用与时间。
- `generator/tools/analyze_new_repeats.py` —— `COPY_NEW` 风格优化潜力分析。
- `global.py` —— 预设参数的全局补丁生成脚本。

### 注意事项与限制

- 目前仅支持 **IAR 工具链** 的输出；如需支持其他工具链，需要提供等效的 ELF/导出解析器。
- MCU 端解码器默认期望 zlib 压缩补丁；若 RAM 极度紧张，可考虑生成未压缩补丁（下载数据更大但解码占用更低），或实现分块 PATCH 流程。
- `ielfdumparm.exe` 属 IAR 工具链的一部分，需要合法授权；本仓库仅提供包装脚本，不包含该可执行文件。

如有问题或贡献意向，欢迎提 Issue 或提交 Pull Request。

