# 语义感知固件差分生成器

本项目提供一个面向资源受限微控制器（如微/纳卫星）的固件增量更新生成器。它可以生成小型、易分帧的补丁流，并在目标端以极少 RAM 即可验证和应用。

主要特性：

- 结合反汇编归一化的语义感知全局匹配。
- 轻量级补丁应用端解码器（COPY/ADD/PATCH 操作码，zlib 压缩流，可选 CDC 处理）。
- 带多级 CRC 的帧封装（默认 502 字节有效载荷）。
- 补丁分析/仿真工具（`patch_sim.py`、`analyze_new_repeats.py`）。

---

## 环境与依赖

1. **IAR 生成的 `.out` 固件。**  
   现有流程依赖 IAR ELF 格式，因为需要解析 IAR 的段、符号及反汇编。
2. **IAR 导出转换工具（`generator/tools/iar_dump2json.py`）。**  
   该脚本封装 `ielfdumparm.exe`，将 `.out` 转为 `.txt` 与 `.json`，同步记录段、符号与归一化提示信息。
3. **Python 3.8+**，所需包已随仓库提供，无需额外安装。  
   Windows 上可直接使用提供的 Anaconda/Miniconda 环境或系统 Python 运行。

---

## 使用方法

### 1. 将 `.out` 转为 `.json`（和 `.txt`）

```bash
python -m generator.tools.iar_dump2json \
  --out QLS01CDHS224.out \
  --json QLS01CDHS224.json \
  --txt  QLS01CDHS224.txt
```

对“新”固件重复上述操作。该步骤依赖 IAR 的 `ielfdumparm.exe`，请确保其位于 `PATH` 或脚本目录中。

### 2. 生成补丁（`generate.py`）

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

说明：
- `--mode global` 现为默认/推荐的全局语义路径；若需实验，可通过 `--mode advanced` 启用高级模式。
- `--verify` 会运行 `apply_patch.py` 来确认补丁可重建新固件；若在 global 模式失败，流程会直接终止（advanced 模式会自动回退到全局流程）。
- 请根据目标 MCU 调整 `--arch-mode` / `--endian`（QLS 为 ARM 大端，USB CDC 为 ARM 小端）。

### 3. 可选：仿真补丁应用（RAM/耗时评估）

```bash
python -m generator.tools.patch_sim \
  --old QLS01CDHS224.bin \
  --patch QLS01CDHSpatch.bin \
  --new QLS01CDHS225.bin \
  --payload 502 \
  --scale 50
```

脚本会报告解压后大小、最大 PATCH 块长度、峰值 RAM 估算及按 `--scale` 缩放后的 MCU 端执行时间。

---

## 目录概览

- `generator/generate.py` —— 主补丁生成 CLI。
- `generator/tools/iar_dump2json.py` —— 将 `.out` 转为 `.json`/`.txt`。
- `generator/tools/apply_patch.py` —— 在本地应用并验证补丁流。
- `generator/tools/patch_sim.py` —— 仿真资源占用与时间。
- `generator/tools/analyze_new_repeats.py` —— `COPY_NEW` 风格优化潜力分析。
- `global.py` —— 预设参数的全局补丁生成脚本。

---

## 注意事项与限制

- 目前仅支持 **IAR 工具链** 的输出；如需支持其他工具链，需要提供等效的 ELF/导出解析器。
- MCU 端解码器默认期望 zlib 压缩补丁；若 RAM 极度紧张，可考虑生成未压缩补丁（下载数据更大但解码占用更低），或实现分块 PATCH 流程。
- `ielfdumparm.exe` 属 IAR 工具链的一部分，需要合法授权；本仓库仅提供包装脚本，不包含该可执行文件。

如有问题或贡献意向，欢迎提 Issue 或提交 Pull Request。
