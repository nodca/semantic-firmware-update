"""
用于解析 IAR ielfdumparm --all 输出的文本 dump。

生成的 JSON 结构大致为：
  {
    "segment": { "file_offset": int, "vaddr": int },
    "sections": {
      idx: { "name": str, "addr": int, "file_offset": int, "size": int,
             "norm_sites": [ { "addr": int, "kind": "branch"|"ptr" }, ... ]? }
    },
    "symbols": {
      name: {
        "addr": int,
        "section_index": int,
        "file_offset": int,
        "size": int,
        "type": str,        # 原始 .symtab 中的 Type 列（例如 Code/Data）
        "binding": str,     # 原始 Bd 列（例如 Lc/Gb）
        "size_decl": int    # .symtab 中声明的 size（若无则为 0）
      },
      ...
    }
  }

本文件是在旧版脚本基础上整理而成，并增加了若干扩展：
  - 保留 .symtab 的 Type / Binding / 声明 Size 等信息；
  - 试验性地为 P2 ro 代码段提取“归一化站点”信息
    （分支立即数和基于符号的常量）。
"""

from __future__ import annotations

import json
import re
import sys
from typing import Dict, List, Optional, Tuple


# 默认的 flash 地址窗口；可通过 ADDR_MIN/MAX 覆盖。
FLASH_BASE_MIN = 0x08000000
FLASH_BASE_MAX = 0x08FFFFFF

# 可选的全局覆盖变量，由 main() 或调用方设置。
ADDR_MIN: Optional[int] = None
ADDR_MAX: Optional[int] = None


def _extract_norm_sites_for_section(
    content: str,
    sec_idx: int,
    sec_name: str,
) -> List[Dict]:
    """
    Lightweight prototype for Courgette‑style normalization:

    Look at the disassembly block for a given section (currently mainly "P2 ro")
    and mark instruction words / constants that should be treated as
    "relocatable" in a normalized view:
      - ARM branch instructions (B/BL/Bxx)
      - DC16/DC32 with a symbolic operand
      - LDR/ADR whose operand text contains a symbol

    The caller can then use these sites to build a normalized byte stream
    while still emitting patches from the real bytes.
    """
    # 定位该 section 对应的反汇编文本块。
    hdr_re = re.compile(rf"^Section #{sec_idx}\s+{re.escape(sec_name)}:", re.MULTILINE)
    m = hdr_re.search(content)
    if not m:
        return []

    start = m.end()
    tail = content[start:]
    # 截止到下一个 \"Section #N ...\" 头或分隔线为止。
    end_m = re.search(r"^Section #\d+\s+|^-{5,}\s*$", tail, re.MULTILINE)
    block = tail[: end_m.start()] if end_m else tail

    # 指令 / 数据行的大致格式示例：
    #   0x20:    0xe1b01000     MOV   R1, R0
    #   0x4f040: 0x0078         DC16  ??TMH_GetFDIRStage_2 + 0x14
    #   0x4f044: 0x08001234     DC32  0x08001234
    insn_re = re.compile(
        r"^\s*0x([0-9a-fA-F]+):\s+0x([0-9a-fA-F]{8})\s+(\S+)\s+(.*)$",
        re.MULTILINE,
    )
    branch_mnems = {
        "B",
        "BL",
        "BX",
        "BEQ",
        "BNE",
        "BPL",
        "BMI",
        "BCC",
        "BCS",
        "BHS",
        "BLO",
        "BVS",
        "BVC",
        "BHI",
        "BLS",
        "BGE",
        "BGT",
        "BLE",
        "BLT",
    }

    sites: List[Dict] = []
    for mm in insn_re.finditer(block):
        addr_s, _word_s, mnem, ops = mm.groups()
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue

        up = mnem.upper()
        kind: Optional[str] = None

        # 1) Branch instructions – in normalized view we only care that it's a
        #    branch，而不关心具体的立即数。
        if up in branch_mnems:
            kind = "branch"
        # 2) DCxx pseudo‑ops with a symbol or obvious address → pointer‑like constant.
        elif up.startswith("DC"):
            # 如果操作数字符串中包含字母，则认为它是符号引用。
            if any(c.isalpha() for c in ops):
                kind = "ptr"
            else:
                # Also treat plain numeric addresses as pointer‑like if they look
                # 类似 flash 地址的数值（启发式判断）。
                m_hex = re.search(r"0x([0-9a-fA-F]+)", ops)
                if m_hex:
                    try:
                        val = int(m_hex.group(1), 16)
                    except ValueError:
                        val = None
                    if val is not None:
                        lo = ADDR_MIN if ADDR_MIN is not None else FLASH_BASE_MIN
                        hi = ADDR_MAX if ADDR_MAX is not None else FLASH_BASE_MAX
                        if lo <= val <= hi:
                            kind = "ptr"
        # 3) LDR/ADR 操作数中出现符号名的情况。
        elif up in ("LDR", "ADR") and any(
            "??" in tok or tok.isidentifier()
            for tok in ops.replace(",", " ").split()
        ):
            kind = "ptr"
        # 4) LDR with PC‑relative literal and absolute address in comment: treat as ptr.
        elif up == "LDR" and "[PC" in ops and "; 0x" in ops:
            kind = "ptr"

        if kind:
            sites.append({"addr": addr, "kind": kind})

    return sites


def parse_iar_dump(dump_path: str) -> Dict:
    with open(dump_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # === 1) SEGMENTS：取第一个 \"load\" 段 ===
    seg_match = re.search(
        r"^\s*\d+:\s+load\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)",
        content,
        re.MULTILINE,
    )
    if not seg_match:
        raise ValueError("No LOAD segment found in dump")
    file_offset = int(seg_match.group(1), 16)
    vaddr = int(seg_match.group(2), 16)
    segment = {"file_offset": file_offset, "vaddr": vaddr}

    # === 2) SECTIONS 段信息 ===
    sections: Dict[int, Dict] = {}
    # 示例：
    #   3: P1 ro            pbits   0x8000188  0x1bc  0x5c5c 0x4 ...
    sec_pattern = re.compile(
        r"^\s*(\d+):\s+(\S+(?:\s+\S+)?)\s+(\S+)\s+0x([0-9a-fA-F]+)\s+"
        r"0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)",
        re.MULTILINE,
    )
    for m in sec_pattern.finditer(content):
        idx = int(m.group(1))
        name = m.group(2).strip()
        addr = int(m.group(4), 16)
        off = int(m.group(5), 16)
        size = int(m.group(6), 16)
        sections[idx] = {
            "name": name,
            "addr": addr,
            "file_offset": off,
            "size": size,
        }

    # === 3) .symtab 区块（可能被拆分，这里做合并） ===
    symbols: Dict[str, Dict] = {}

    sym_hdr_iter = list(
        re.finditer(r"^Section #(\d+)\s+\.symtab:", content, re.MULTILINE)
    )
    if not sym_hdr_iter:
        # 如果没有符号表，也仍然返回段和 section 信息。
        return {"segment": segment, "sections": sections, "symbols": symbols}

    # 为每个 .symtab section 提取原始文本块。
    sym_blocks: List[str] = []
    for i, hdr in enumerate(sym_hdr_iter):
        start = hdr.end()
        if i + 1 < len(sym_hdr_iter):
            end = sym_hdr_iter[i + 1].start()
            block_full = content[start:end]
        else:
            # 一直读到文件末尾，或直到遇到下一个分隔线 / Section 头。
            tail = content[start:]
            end_m = re.search(r"^-+\s*$|^Section #\d+\s+", tail, re.MULTILINE)
            block_full = tail[: end_m.start()] if end_m else tail
        sym_blocks.append(block_full)

    # 符号表中的行大致长这样：
    #   N: name  0xADDR  Sec Type Bd [Size   ...]
    line_re = re.compile(
        r"^\s*\d+:\s+(\S+)\s+0x([0-9a-fA-F]+)\s+"
        r"(Abs|Ext|[0-9]+)\s+(\S+)\s+(\S+)"
        r"(?:\s+0x([0-9a-fA-F]+))?",
        re.MULTILINE,
    )

    # 临时收集结构：(sec_idx -> [(addr, name, type, binding, size_decl)])
    by_sec: Dict[int, List[Tuple[int, str, str, str, int]]] = {}

    for block in sym_blocks:
        for m in line_re.finditer(block):
            name = m.group(1)
            addr = int(m.group(2), 16)
            sec_tok = m.group(3)

            # Abs / Ext 没有具体的 section，直接跳过。
            if sec_tok in ("Abs", "Ext"):
                continue
            try:
                sec_idx = int(sec_tok)
            except ValueError:
                continue

            sym_type = m.group(4) or ""
            binding = m.group(5) or ""
            size_decl = int(m.group(6), 16) if m.group(6) else 0

            # 只保留落在 flash 地址范围内的符号（可通过参数覆盖）。
            lo = ADDR_MIN if ADDR_MIN is not None else FLASH_BASE_MIN
            hi = ADDR_MAX if ADDR_MAX is not None else FLASH_BASE_MAX
            if not (lo <= addr <= hi):
                continue

            by_sec.setdefault(sec_idx, []).append(
                (addr, name, sym_type, binding, size_decl)
            )

    if not by_sec:
        return {"segment": segment, "sections": sections, "symbols": symbols}

    # === 4) 在每个 section 内推断符号大小并构建最终符号表 ===

    def sec_end_addr(idx: int) -> Optional[int]:
        sec = sections.get(idx)
        if not sec:
            return None
        return sec["addr"] + sec["size"]

    for sec_idx, items in by_sec.items():
        # Sort by (addr, is_dollar, name) and prefer non‑"$" names at same addr.
        items.sort(key=lambda x: (x[0], x[1].startswith("$"), x[1]))

        dedup: List[Tuple[int, str, str, str, int]] = []
        seen_addr: Optional[int] = None
        for addr, name, sym_type, binding, size_decl in items:
            if seen_addr is None or addr != seen_addr:
                dedup.append((addr, name, sym_type, binding, size_decl))
                seen_addr = addr
            else:
                # 地址相同：如果当前名称更“真实”（不以 '$' 开头），
                # 且之前的是汇编辅助标签，则用当前名称替换掉之前的。
                if not name.startswith("$") and dedup[-1][1].startswith("$"):
                    dedup[-1] = (addr, name, sym_type, binding, size_decl)

        items = dedup
        end_addr = sec_end_addr(sec_idx)

        for i, (addr, name, sym_type, binding, size_decl) in enumerate(items):
            # 用于推断大小的下一个边界地址。
            if i + 1 < len(items):
                next_addr = items[i + 1][0]
            else:
                next_addr = end_addr if end_addr is not None else addr

            # 若有声明的 size 优先使用，否则回退到相邻符号的差值。
            size = size_decl if size_decl > 0 else max(0, next_addr - addr)

            # 跳过明显的汇编辅助标签（例如以 '$' 开头的标签）。
            if name.startswith("$"):
                continue

            sec = sections.get(sec_idx)
            if not sec:
                continue

            file_off = sec["file_offset"] + (addr - sec["addr"])
            symbols[name] = {
                "addr": addr,
                "section_index": sec_idx,
                "file_offset": file_off,
                "size": size,
                # 来自原始 .symtab 的附加元数据：
                "type": sym_type,
                "binding": binding,
                "size_decl": size_decl,
            }

    # === 5) 为感兴趣的代码段提取“归一化掩码”信息 ===
    for idx, sec in sections.items():
        name = sec.get("name", "")
        if not isinstance(name, str):
            continue
        # 当前仅关注 IAR 中标准的代码段 \"P2 ro\"。
        if name == "P2 ro":
            try:
                norm_sites = _extract_norm_sites_for_section(content, idx, name)
            except Exception:
                norm_sites = []
            if norm_sites:
                sec["norm_sites"] = norm_sites

    return {"segment": segment, "sections": sections, "symbols": symbols}


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Parse IAR ielfdumparm text into JSON")
    ap.add_argument("dump", help="ielfdumparm --all output text")
    ap.add_argument("--out", required=True, help="output JSON path")
    ap.add_argument(
        "--addr-min",
        type=lambda x: int(x, 0),
        help="minimum address to keep (supports 0x prefix)",
    )
    ap.add_argument(
        "--addr-max",
        type=lambda x: int(x, 0),
        help="maximum address to keep (supports 0x prefix)",
    )
    args = ap.parse_args()

    global ADDR_MIN, ADDR_MAX
    ADDR_MIN = args.addr_min
    ADDR_MAX = args.addr_max

    dump_path = args.dump
    out_path = args.out

    try:
        data = parse_iar_dump(dump_path)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print("[OK] parsed IAR dump successfully")
        print(
            f"  LOAD seg: VAddr=0x{data['segment']['vaddr']:08X}, "
            f"FileOffset=0x{data['segment']['file_offset']:04X}"
        )
        print(f"  sections: {len(data['sections'])}")
        print(f"  flash symbols: {len(data['symbols'])}")
        print(f"  output: {out_path}")
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
