#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
arm_ir.py - 面向全局匹配的轻量级 ARM IR 实验模块

本模块的目标：
  * 将 IAR ielfdumparm 反汇编结果解析为紧凑的、逐指令的 IR；
  * 为代码段构建一个 IR 记号流，并记录对应的字节偏移；
  * 在 IR 记号流上运行已有的 global_dp_hybrid 全局匹配器；
  * 将 IR 级别的匹配映射回字节级匹配，并验证底层字节是否一致。

这是一个独立的实验模块，不会改变补丁格式或解码器；
用于验证：基于 IR 的全局匹配器能否为当前基于 COPY 的补丁构建器提供输入。
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

from generator.strategies.global_dp import global_dp_hybrid


@dataclass
class IRInstr:
    """
    一条 IR 指令，对应一段连续的字节范围。

    属性：
        addr:     反汇编中显示的虚拟地址（与 JSON 中的地址刻度一致）。
        size:     指令所占的字节数（ARM 通常为 4 字节）。
        token_id: 表示“归一化操作码 + 操作数模式”的小整数 ID，
                  即用于匹配的 IR 符号。
    """

    addr: int
    size: int
    token_id: int


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _find_section_bounds(sym_json: dict, section_name: str) -> Tuple[int, int]:
    """
    在 JSON 中按名称查找一个 section，并返回 (addr_start, addr_end)。
    如果未找到则抛出 ValueError。
    """
    sections = sym_json.get("sections") or {}
    for sec in sections.values():
        if not isinstance(sec, dict):
            continue
        name = (sec.get("name") or "").strip()
        if not name:
            continue
        # 做一点模糊匹配：既接受完全相等，也接受前缀匹配。
        if name == section_name or name.startswith(section_name):
            addr = int(sec.get("addr", 0) or 0)
            size = int(sec.get("size", 0) or 0)
            if size <= 0:
                raise ValueError(f"Section '{section_name}' has non-positive size")
            return addr, addr + size
    raise ValueError(f"Section '{section_name}' not found in JSON")


_INSTR_RE = re.compile(
    r"""^\s*"""
    r"""(0x[0-9a-fA-F]+):\s+"""          # 地址
    r"""([0-9a-fA-F]+)\s+"""             # 指令机器码（这里只用它的长度）
    r"""([A-Za-z0-9_.]+)"""              # 助记符
    r"""(.*)$"""                         # 其余部分：操作数 + 可选注释
)

_HEX_IMM_RE = re.compile(r"0x[0-9a-fA-F]+")
_HASH_IMM_RE = re.compile(r"#-?(0x[0-9a-fA-F]+|\d+)")


def _normalize_operand_text(operands: str) -> str:
    """
    对操作数字符串做粗略归一化：
      - 去掉 ';' 之后的注释；
      - 将立即数和绝对地址统一替换为 IMM；
      - 合并多余空格。
    这个逻辑刻意保持简单，只需要一个稳定的记号 key。
    """
    # 去掉行尾注释 / 额外标注
    if ";" in operands:
        operands = operands.split(";", 1)[0]
    # 优先替换形如 '#imm' 的立即数形式
    operands = _HASH_IMM_RE.sub("#IMM", operands)
    # 再替换裸露的十六进制字面值
    operands = _HEX_IMM_RE.sub("IMM", operands)
    # 折叠多余空白字符
    operands = " ".join(operands.strip().split())
    return operands


def _mnemonic_class(mnemonic: str) -> str:
    """
    将原始助记符（可能带条件码）映射到一个较粗粒度的类别。
    这样可以让 IR 字母表保持较小，从而可以用 1 字节编码 token_id。
    """
    m = mnemonic.upper()
    # 粗略地去掉结尾的条件后缀，例如 EQ/NE/GT/...。
    # 只保留从开头到第一个非字母字符之间的助记符前缀。
    m_base_match = re.match(r"[A-Z]+", m)
    base = m_base_match.group(0) if m_base_match else m

    if base in {"B", "BL", "BX", "BLX", "CBZ", "CBNZ"}:
        return "BR"
    if base.startswith("LDR"):
        return "LDR"
    if base.startswith("STR"):
        return "STR"
    if base in {"ADD", "ADC", "SUB", "SBC", "RSB", "MUL", "MLA"}:
        return "ALU"
    if base in {"MOV", "MVN"}:
        return "MOV"
    if base in {"CMP", "CMN", "TST", "TEQ"}:
        return "CMP"
    if base in {"PUSH", "POP", "STM", "LDM"}:
        return "STACK"
    if base.startswith("V") or base.startswith("F"):
        # VFP / FPU 浮点指令
        return "FP"
    # 兜底：直接使用原始助记符本身。
    return base


def parse_arm_disasm_to_ir(
    disasm_path: str,
    addr_start: int,
    addr_end: int,
    *,
    instr_size: int = 4,
) -> Tuple[List[IRInstr], Dict[str, int]]:
    """
    解析 IAR ielfdumparm 生成的反汇编文件，为地址落在
    [addr_start, addr_end) 区间的指令构建线性的 IR 序列。

    返回：
        ir_seq:      按地址排序的 IRInstr 列表；
        token_table: 从 IR 记号 key 字符串到 token_id 的映射。
    """
    token_table: Dict[str, int] = {}
    next_token_id = 1  # 0 预留给“空操作（no-op）”等特殊用途
    ir_seq: List[IRInstr] = []

    with open(disasm_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = _INSTR_RE.match(line)
            if not m:
                continue
            addr_s, _word_s, mnemonic, rest = m.groups()
            try:
                addr = int(addr_s, 16)
            except ValueError:
                continue
            if addr < addr_start or addr >= addr_end:
                continue

            operands = rest or ""
            cls = _mnemonic_class(mnemonic)
            # 在这一版实验中，我们刻意忽略操作数的具体形状，
            # 不把它编码进 IR 记号 key，以保持字母表较小（每个记号 1 字节），
            # 归一化后的操作数字符串仅保留以便将来做更细致的改进。
            # op_norm = _normalize_operand_text(operands)
            key = cls

            token_id = token_table.get(key)
            if token_id is None:
                token_id = next_token_id
                token_table[key] = token_id
                next_token_id += 1
                if next_token_id > 255:
                    # 在本实验中，将 token ID 限制在 1 字节范围内。
                    raise RuntimeError(
                        "IR token alphabet exceeds 255 symbols; "
                        "refine normalization to merge more patterns."
                    )

            ir_seq.append(IRInstr(addr=addr, size=instr_size, token_id=token_id))

    ir_seq.sort(key=lambda ins: ins.addr)
    return ir_seq, token_table


def _ir_seq_to_bytes(ir_seq: List[IRInstr]) -> bytes:
    """
    将 IRInstr 列表转换为字节流（每条指令 1 字节），供 global_dp_hybrid 使用。
    """
    return bytes(ins.token_id for ins in ir_seq)


def _compute_byte_coverage(matches: List[Tuple[int, int, int]], total_len: int) -> int:
    """
    根据一组 (n_off, o_off, length) 字节匹配，计算新固件中被覆盖的字节数。
    """
    if not matches or total_len <= 0:
        return 0
    intervals = [(n, n + ln) for (n, _o, ln) in matches if ln > 0]
    if not intervals:
        return 0
    intervals.sort(key=lambda x: x[0])
    total = 0
    cur_s, cur_e = intervals[0]
    for s, e in intervals[1:]:
        if s > cur_e:
            total += max(0, min(cur_e, total_len) - cur_s)
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    total += max(0, min(cur_e, total_len) - cur_s)
    return total


def map_ir_matches_to_byte_matches(
    ir_matches: List[Tuple[int, int, int]],
    old_ir: List[IRInstr],
    new_ir: List[IRInstr],
    old_bytes: bytes,
    new_bytes: bytes,
    flash_base: int,
) -> List[Tuple[int, int, int]]:
    """
    将 IR 层级的匹配（按指令索引）转换为字节层级的匹配，
    即固件镜像中的绝对偏移匹配。

    对于每个 IR 匹配 (n_off, o_off, length)，我们会：
      * 逐对遍历对应的指令；
      * 要求大小一致且底层字节完全相同；
      * 要求在旧/新字节流中都连续；
      * 将连续片段输出为 COPY 风格的字节匹配。
    """
    byte_matches: List[Tuple[int, int, int]] = []

    def flush_run(
        cur_n_start: Optional[int],
        cur_o_start: Optional[int],
        cur_len: int,
    ):
        if cur_n_start is not None and cur_o_start is not None and cur_len > 0:
            byte_matches.append((cur_n_start, cur_o_start, cur_len))

    for n_off_ir, o_off_ir, ln_ir in ir_matches:
        i_n = n_off_ir
        i_o = o_off_ir
        end_n = n_off_ir + ln_ir

        cur_n_start: Optional[int] = None
        cur_o_start: Optional[int] = None
        cur_len = 0
        last_n_end: Optional[int] = None
        last_o_end: Optional[int] = None

        while i_n < end_n and i_n < len(new_ir) and i_o < len(old_ir):
            ins_n = new_ir[i_n]
            ins_o = old_ir[i_o]

            # 将虚拟地址映射到文件内偏移。
            n_start = ins_n.addr - flash_base
            o_start = ins_o.addr - flash_base
            n_end = n_start + ins_n.size
            o_end = o_start + ins_o.size

            # 做一些基础的合法性检查。
            if (
                n_start < 0
                or o_start < 0
                or n_end > len(new_bytes)
                or o_end > len(old_bytes)
                or ins_n.size != ins_o.size
            ):
                # 如果当前存在连续区间，则先结束它。
                flush_run(cur_n_start, cur_o_start, cur_len)
                cur_n_start = cur_o_start = None
                cur_len = 0
                last_n_end = last_o_end = None
                i_n += 1
                i_o += 1
                continue

            # 要求底层字节完全相同，才能视为 COPY 风格匹配。
            if new_bytes[n_start:n_end] != old_bytes[o_start:o_end]:
                flush_run(cur_n_start, cur_o_start, cur_len)
                cur_n_start = cur_o_start = None
                cur_len = 0
                last_n_end = last_o_end = None
                i_n += 1
                i_o += 1
                continue

            if cur_n_start is None:
                # 开始一段新的连续区间。
                cur_n_start = n_start
                cur_o_start = o_start
                cur_len = ins_n.size
            else:
                # 要求在旧 / 新字节流中都保持连续。
                if n_start == last_n_end and o_start == last_o_end:
                    cur_len += ins_n.size
                else:
                    flush_run(cur_n_start, cur_o_start, cur_len)
                    cur_n_start = n_start
                    cur_o_start = o_start
                    cur_len = ins_n.size

            last_n_end = n_end
            last_o_end = o_end
            i_n += 1
            i_o += 1

        flush_run(cur_n_start, cur_o_start, cur_len)

    # 在字节空间合并重叠 / 相邻的匹配（可选，但更干净）。
    if not byte_matches:
        return []

    byte_matches.sort(key=lambda x: x[0])
    merged: List[Tuple[int, int, int]] = []
    cur_n, cur_o, cur_len = byte_matches[0]
    cur_n_end = cur_n + cur_len
    cur_o_end = cur_o + cur_len

    for n_off, o_off, ln in byte_matches[1:]:
        n_end = n_off + ln
        o_end = o_off + ln
        if n_off == cur_n_end and o_off == cur_o_end:
            # 若区间相邻，则扩展当前连续区间。
            cur_len += ln
            cur_n_end = n_end
            cur_o_end = o_end
        else:
            merged.append((cur_n, cur_o, cur_len))
            cur_n, cur_o, cur_len = n_off, o_off, ln
            cur_n_end = n_end
            cur_o_end = o_end
    merged.append((cur_n, cur_o, cur_len))
    return merged


def run_ir_experiment(args: argparse.Namespace) -> None:
    # 读取旧 / 新固件二进制。
    with open(args.old_bin, "rb") as f:
        old_bytes = f.read()
    with open(args.new_bin, "rb") as f:
        new_bytes = f.read()

    # 读取 JSON 元数据并定位代码段边界。
    old_json = _load_json(args.old_json)
    new_json = _load_json(args.new_json)
    old_start, old_end = _find_section_bounds(old_json, args.section)
    new_start, new_end = _find_section_bounds(new_json, args.section)

    flash_base = int(args.flash_base, 0)

    print(
        f"[IR] Using section '{args.section}':\n"
        f"     old: addr=[0x{old_start:X}, 0x{old_end:X})\n"
        f"     new: addr=[0x{new_start:X}, 0x{new_end:X})\n"
        f"     flash_base=0x{flash_base:X}"
    )

    # 将反汇编文本解析为 IR 序列。
    old_ir, old_tokens = parse_arm_disasm_to_ir(
        args.old_txt, old_start, old_end, instr_size=args.instr_size
    )
    new_ir, new_tokens = parse_arm_disasm_to_ir(
        args.new_txt, new_start, new_end, instr_size=args.instr_size
    )

    print(
        f"[IR] Parsed instructions: old={len(old_ir)} new={len(new_ir)} "
        f"| token_alphabet_old={len(old_tokens)} token_alphabet_new={len(new_tokens)}"
    )

    # 构造 IR 记号字节流并运行现有的全局 DP 匹配器。
    old_ir_bytes = _ir_seq_to_bytes(old_ir)
    new_ir_bytes = _ir_seq_to_bytes(new_ir)

    print(
        f"[IR] Running global_dp_hybrid on IR tokens, min_match_len={args.min_match_len}"
    )
    ir_matches = global_dp_hybrid(
        old_ir_bytes,
        new_ir_bytes,
        min_length=args.min_match_len,
        code_mask=None,
        func_boundary_prefix=None,
    )

    print(
        f"[IR] global_dp_hybrid produced {len(ir_matches)} IR matches "
        f"over {len(new_ir_bytes)} IR tokens"
    )

    # 将 IR 匹配映射回字节级匹配，并校验底层字节。
    byte_matches = map_ir_matches_to_byte_matches(
        ir_matches, old_ir, new_ir, old_bytes, new_bytes, flash_base
    )
    cov_bytes = _compute_byte_coverage(byte_matches, len(new_bytes))
    pct = (cov_bytes / len(new_bytes) * 100.0) if new_bytes else 0.0

    print(
        f"[IR] Byte-level matches derived from IR: {len(byte_matches)} segments, "
        f"covering {cov_bytes} bytes ({pct:.2f}% of new firmware)"
    )

    # 如有需要，打印若干示例匹配以便人工检查。
    show = min(len(byte_matches), args.show_matches)
    for i in range(show):
        n_off, o_off, ln = byte_matches[i]
        print(
            f"[IR-MATCH] {i}: new_off=0x{n_off:X} old_off=0x{o_off:X} len={ln}"
        )


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Lightweight ARM IR experiment:\n"
            "  - Parse disassembly into IR tokens\n"
            "  - Run global DP matching on IR\n"
            "  - Map IR matches back to byte matches and report coverage"
        )
    )
    p.add_argument("--old-bin", dest="old_bin", required=True, help="Old firmware .bin")
    p.add_argument("--new-bin", dest="new_bin", required=True, help="New firmware .bin")
    p.add_argument(
        "--old-json",
        dest="old_json",
        required=True,
        help="JSON metadata for old firmware (from iar_dump2json/dump.py)",
    )
    p.add_argument(
        "--new-json",
        dest="new_json",
        required=True,
        help="JSON metadata for new firmware (from iar_dump2json/dump.py)",
    )
    p.add_argument(
        "--old-txt",
        dest="old_txt",
        required=True,
        help="IAR ielfdumparm --all text dump for old firmware",
    )
    p.add_argument(
        "--new-txt",
        dest="new_txt",
        required=True,
        help="IAR ielfdumparm --all text dump for new firmware",
    )
    p.add_argument(
        "--flash-base",
        dest="flash_base",
        default="0x0",
        help="Flash base address used when extracting .bin (default: 0x0)",
    )
    p.add_argument(
        "--section",
        dest="section",
        default="P2 ro",
        help="Section name to treat as code for IR (default: 'P2 ro')",
    )
    p.add_argument(
        "--instr-size",
        dest="instr_size",
        type=int,
        default=4,
        help="Instruction size in bytes for ARM state (default: 4)",
    )
    p.add_argument(
        "--min-match-len",
        dest="min_match_len",
        type=int,
        default=16,
        help="Minimum IR-token match length for global_dp_hybrid (default: 16)",
    )
    p.add_argument(
        "--show-matches",
        dest="show_matches",
        type=int,
        default=10,
        help="Number of byte-level matches to print as examples (default: 10)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    run_ir_experiment(args)


if __name__ == "__main__":
    main()
