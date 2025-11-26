#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# generate.py - 语义感知的轻量固件差分补丁生成器（主入口）

import argparse
import json
import os
import sys
import subprocess
from typing import Optional, Tuple, List, Dict
from tqdm import tqdm

from generator.strategies.global_match import global_greedy_hybrid
from generator.strategies.global_dp import global_dp_hybrid
from generator.core.protocol import (
    PatchBuilder,
    OP_ADD,
    OP_COPY,
    estimate_add_bytes,
    estimate_copy_bytes,
)
from generator.parsers.symbols import load_symbols_any, pair_symbols, safe_merge_symbol_regions
from generator.strategies.cdc import cdc_emit_region, build_cdc_index
from generator.strategies.greedy import build_block_index, greedy_match
from generator.strategies.heuristics import (
    diff_symbol_region,
    emit_literals,
    emit_best_for_region,
    try_global_compact_patch,
    try_local_sparse_patch,
)
from generator.tools.framing import split_frames
from generator.analysis.simlite import (
    reloc_aware_similarity_lite,
    guess_arch_mode,
    find_ptr_sites,
    mask_ptr_like,
)
from generator.core.utils import uleb128_len

MIN_COPY_SAVING = 2  # require COPY to save at least 2 bytes vs literal


def _speed_profile_kwargs(profile: str) -> dict:
    """Return global_dp_hybrid tuning knobs for the desired speed profile."""
    if profile == "fast":
        return {
            "skip_local_if_cover": 0.90,
            "greedy_block": 48,
            "greedy_index_step": 8,
            "greedy_min_run": 24,
            "greedy_scan_step": 8,
        }
    return {}

def _build_normalized_stream_from_raw(
    bin_bytes: bytes,
    raw_json: Optional[dict],
    flash_base: int,
    *,
    arch_mode: str = "arm",
    endian: str = "le",
) -> bytes:
    """
    使用反汇编得到的掩码点（存放在符号 JSON 中，由 iar_dump2json/dump.py 生成），
    在固件字节流上构建“归一化”的视图。

    当前只是一个简单的原型：
      - 仅在 sections[...]['norm_sites'] 存在时使用
      - 将每个站点视为虚拟地址 'addr' 处的 4 字节字
      - 如果 kind 为 'branch'：保留高 8 位（opcode/cond），其余立即数清零
      - 如果 kind 为 'ptr'：整个字清零

    生成的字节串与原始固件长度相同，可作为 global_dp_hybrid 的输入驱动匹配，
    补丁发射阶段仍然使用真实（未归一化）的字节。
    """
    if not raw_json or not isinstance(raw_json, dict):
        return bin_bytes

    sections = raw_json.get("sections")
    if not isinstance(sections, dict):
        return bin_bytes

    # 当前只实现按 32 位字工作的归一化方案；ARM 和 Thumb 都按代码处理，
    # 其他模式直接回退为使用原始字节。
    if arch_mode not in ("arm", "thumb", "auto"):
        return bin_bytes

    norm = bytearray(bin_bytes)
    be = (endian == "be")

    for sec_info in sections.values():
        if not isinstance(sec_info, dict):
            continue
        sites = sec_info.get("norm_sites")
        if not sites:
            continue

        for site in sites:
            if not isinstance(site, dict):
                continue
            try:
                addr = int(site.get("addr"))
            except (TypeError, ValueError):
                continue
            kind = (site.get("kind") or "").lower()

            off = addr - flash_base
            if off < 0 or off + 4 > len(norm):
                continue

            word = int.from_bytes(norm[off:off + 4], "big" if be else "little")
            if kind == "branch":
                # 保留高 8 位（opcode/cond），清零立即数字段。
                norm_word = word & 0xFF000000
            else:
                # 指针/基于符号的常量：全部视为通配符（清零）。
                norm_word = 0

            norm[off:off + 4] = norm_word.to_bytes(4, "big" if be else "little")

    return bytes(norm)

def _looks_like_function(name: str) -> bool:
    if not name:
        return False
    bad_prefix = ("$", ".L", "__", "@")
    return not name.startswith(bad_prefix)

def _build_code_mask_from_symbols(
    raw_json: Optional[dict],
    parsed_syms: Optional[Dict[str, List]],
    new_len: int,
    flash_base: int,
) -> Tuple[Optional[List[bool]], Optional[List[int]]]:
    """
    Construct a boolean code mask and function-boundary prefix array from symbol metadata.
    """
    if new_len <= 0:
        return None, None

    mask = [False] * new_len
    func_flags = [False] * new_len
    code_names: set = set()
    symbol_meta = None

    if isinstance(raw_json, dict):
        symbol_meta = raw_json.get("symbols")
        if isinstance(symbol_meta, dict):
            for name, meta in symbol_meta.items():
                entries = meta if isinstance(meta, list) else [meta]
                for ent in entries:
                    if not isinstance(ent, dict):
                        continue
                    typ = str(ent.get("type", "")).lower()
                    if typ == "code":
                        code_names.add(name)

    def _mark_range(name: str, off: int, size: int) -> None:
        if size <= 0 or off >= new_len or off < 0:
            return
        end = min(new_len, off + size)
        for idx in range(off, end):
            mask[idx] = True
        if _looks_like_function(name) and size >= 24:
            func_flags[off] = True

    has_ranges = False
    if parsed_syms:
        for name, entries in parsed_syms.items():
            if not entries:
                continue
            is_code = True if not code_names else (name in code_names)
            if not is_code:
                continue
            for sym in entries:
                off = int(getattr(sym, "off", -1))
                size = int(getattr(sym, "size", 0))
                _mark_range(name, off, size)
                has_ranges = True

    if not has_ranges and isinstance(symbol_meta, dict):
        for name, meta in symbol_meta.items():
            is_code = True if not code_names else (name in code_names)
            if not is_code:
                continue
            entries = meta if isinstance(meta, list) else [meta]
            for ent in entries:
                if not isinstance(ent, dict):
                    continue
                try:
                    size = int(ent.get("size", 0) or 0)
                except Exception:
                    continue
                if size <= 0:
                    continue
                off = None
                if "addr" in ent:
                    try:
                        off = int(ent["addr"]) - flash_base
                    except Exception:
                        off = None
                if off is None and "file_offset" in ent:
                    try:
                        off = int(ent["file_offset"])
                    except Exception:
                        off = None
                if off is None and "off" in ent:
                    try:
                        off = int(ent["off"])
                    except Exception:
                        off = None
                if off is None:
                    continue
                _mark_range(name, off, size)

    code_bytes = sum(1 for flag in mask if flag)
    if code_bytes == 0:
        mask = None
    else:
        print(f"[GLOBAL] code-mask coverage {code_bytes} bytes ({code_bytes/new_len*100:.2f}%)")

    func_prefix: Optional[List[int]] = None
    if any(func_flags):
        func_prefix = [0] * (new_len + 1)
        acc = 0
        for idx, flag in enumerate(func_flags):
            if flag:
                acc += 1
            func_prefix[idx + 1] = acc

    return mask, func_prefix

def process_gap_region(
    old_bin: bytes,
    new_region: bytes,
    block_idx: dict,
    pb: PatchBuilder,
    block_size: int = 48,
    min_run: int = 32,
    scan_step: int = 8,
    *,
    global_matches: Optional[List[Tuple[int, int, int]]] = None,
    region_start: int = 0,
) -> Tuple[int, int, int, int, int, int, int]:
    """
    处理间隙区域，返回统计元组: 
    (add_data_bytes, add_meta_bytes, add_count, 
     copy_meta_bytes, copy_count, 
     total_region_bytes)
    注意: COPY指令不含数据，只有元数据
    """
    if not new_region:
        return (0, 0, 0, 0, 0, 0)
    
    start_size = pb.current_size()
    add_data = add_meta = add_count = 0
    copy_meta = copy_count = 0  # COPY没有数据部分

    # 如果提供了全局匹配结果，则优先使用全局匹配（Path 2: 强全局匹配驱动 gap 区域）
    if global_matches is not None:
        matches: List[Tuple[int, int, int]] = []
        region_end = region_start + len(new_region)
        # global_matches 已按新固件偏移排序，这里筛选完全落在当前 gap 区域内的匹配
        for n_abs, o_off_m, ln in global_matches:
            if n_abs >= region_end:
                break
            if n_abs < region_start:
                continue
            if n_abs + ln > region_end:
                # 目前为了简单，只接受完全落在 gap 内的匹配；跨界匹配直接丢弃
                continue
            matches.append((n_abs - region_start, o_off_m, ln))
    else:
        # 回退到局部 greedy 匹配
        matches = greedy_match(
            old_bin,
            new_region,
            block_idx,
            block=block_size,
            min_run=min_run,
            scan_step=scan_step,
        )
    cur = 0
    for (n_off_rel, o_off_m, ln) in matches:
        if n_off_rel < 0 or o_off_m < 0 or ln <= 0:
            continue

        if n_off_rel > cur:
            add_len = n_off_rel - cur
            if add_len > 0:
                add_data += add_len
                add_meta += 1 + uleb128_len(add_len)
                add_count += 1
                emit_literals(pb, new_region[cur:n_off_rel])
            cur = n_off_rel

        copy_cost = estimate_copy_bytes(o_off_m, ln)
        add_cost = estimate_add_bytes(ln)
        if copy_cost + MIN_COPY_SAVING <= add_cost:
            copy_meta += copy_cost
            copy_count += 1
            pb.op_copy(o_off_m, ln)
        else:
            literal = new_region[cur:cur + ln]
            add_data += len(literal)
            add_meta += 1 + uleb128_len(len(literal))
            add_count += 1
            emit_literals(pb, literal)
        cur = n_off_rel + ln
    if cur < len(new_region):
        add_len = len(new_region) - cur
        if add_len > 0:
            add_data += add_len
            add_meta += 1 + uleb128_len(add_len)
            add_count += 1
            emit_literals(pb, new_region[cur:])
    
    total_region_bytes = pb.current_size() - start_size
    return (add_data, add_meta, add_count, copy_meta, copy_count, total_region_bytes)


def _refine_matches_to_real_bytes(
    matches: List[Tuple[int, int, int]],
    old_bin: bytes,
    new_bin: bytes,
) -> List[Tuple[int, int, int]]:
    """
    Given matches computed on a normalized view (old_norm/new_norm), split them
    into sub‑matches that are guaranteed to be byte‑identical on the real
    firmware bytes.

    This keeps the patch correct even when normalization made two regions look
    equal (e.g. branch immediates masked out) but their raw bytes differ.
    """
    refined: List[Tuple[int, int, int]] = []
    for n_off, o_off, ln in matches:
        if ln <= 0:
            continue
        i = 0
        while i < ln:
            if o_off + i >= len(old_bin) or n_off + i >= len(new_bin):
                break
            if old_bin[o_off + i] != new_bin[n_off + i]:
                i += 1
                continue
            # 在真实字节上找到一段相同数据的起始位置。
            start = i
            j = i + 1
            while j < ln:
                if (
                    o_off + j >= len(old_bin)
                    or n_off + j >= len(new_bin)
                    or old_bin[o_off + j] != new_bin[n_off + j]
                ):
                    break
                j += 1
            run_len = j - start
            if run_len > 0:
                # 只有在相对于直接 ADD 确实省字节时才保留这个子匹配。
                meta_cost = 1 + uleb128_len(o_off + start) + uleb128_len(run_len)
                if run_len > meta_cost:
                    refined.append((n_off + start, o_off + start, run_len))
            i = j
    return refined


def _extract_section_pairs(old_raw, new_raw, flash_base: int, old_len: int, new_len: int):
    """
    从原始 JSON raw_data 中提取 section 级别的粗粒度配对:
      返回列表 [(n_off, o_off, size), ...]
    只考虑同时出现在 old/new 中、且位于 FLASH 区间内的段.
    """
    pairs = []
    if not isinstance(old_raw, dict) or not isinstance(new_raw, dict):
        return pairs
    old_secs = old_raw.get("sections")
    new_secs = new_raw.get("sections")
    if not isinstance(old_secs, dict) or not isinstance(new_secs, dict):
        return pairs

    keys = set(old_secs.keys()) & set(new_secs.keys())
    if not keys:
        return pairs

    flash_lo = flash_base
    flash_hi = flash_base + max(old_len, new_len)

    for k in keys:
        o_sec = old_secs.get(k)
        n_sec = new_secs.get(k)
        if not isinstance(o_sec, dict) or not isinstance(n_sec, dict):
            continue
        try:
            o_size = int(o_sec.get("size", 0) or 0)
            n_size = int(n_sec.get("size", 0) or 0)
        except Exception:
            continue
        size = min(o_size, n_size)
        if size <= 0:
            continue

        # 优先使用 addr 计算偏移
        try:
            o_addr = int(o_sec.get("addr", 0) or 0)
            n_addr = int(n_sec.get("addr", 0) or 0)
        except Exception:
            o_addr = n_addr = 0
        o_off = None
        n_off = None
        if flash_lo <= o_addr < flash_hi and flash_lo <= n_addr < flash_hi:
            o_off = o_addr - flash_lo
            n_off = n_addr - flash_lo
        else:
            # 回退到 file_offset
            try:
                o_file = int(o_sec.get("file_offset", 0) or 0)
                n_file = int(n_sec.get("file_offset", 0) or 0)
                o_off = o_file
                n_off = n_file
            except Exception:
                o_off = n_off = None

        if o_off is None or n_off is None:
            continue
        if o_off < 0 or n_off < 0 or o_off >= old_len or n_off >= new_len:
            continue

        # 截断到文件长度范围内
        max_size = min(size, old_len - o_off, new_len - n_off)
        if max_size <= 0:
            continue
        pairs.append((n_off, o_off, max_size))

    # 按新文件偏移排序
    pairs.sort(key=lambda t: t[0])
    return pairs


def diff_symbol_region_reloc(
    old_bytes: bytes,
    new_bytes: bytes,
    old_off: int,
    new_off: int,
    size: int,
    flash_lo: int,
    flash_hi: int,
    *,
    endian: str = "le",
    max_changes: int = 16,
    max_ratio: float = 0.15,
):
    """
    diff_symbol_region 的重定位感知版本（阶段 1）。

    正确性要求：
      - 仍然必须对所有不同的字节打补丁，包括重定位字，
        这样重建出来的固件才能与新镜像逐位一致。
      - 只是在判断该区域是否“变化密集”（max_ratio）时，
        把类似重定位的字节从统计中折扣，以避免在主要差异
        只是地址变化的代码上过于激进地退回到 ADD。
    """
    if size <= 0:
        return []

    olds = old_bytes[old_off:old_off + size]
    news = new_bytes[new_off:new_off + size]

    if olds == news:
        return []

    # 1) 收集所有“类似重定位”的字节位置（范围在 [0, size) 内）。
    reloc_bytes = set()
    ptr_o = find_ptr_sites(olds, flash_lo, flash_hi, endian=endian)
    ptr_n = find_ptr_sites(news, flash_lo, flash_hi, endian=endian)
    for off in ptr_o | ptr_n:
        for k in range(off, min(off + 4, size)):
            reloc_bytes.add(k)

    # 2) 在原始字节上做 diff，但只把非重定位字节计入变化密度。
    i = 0
    changes = []
    changed_semantic = 0

    while i < size:
        if olds[i] != news[i]:
            start = i
            j = i + 1
            while j < size and olds[j] != news[j]:
                j += 1
            run = news[start:j]
            changes.append((start, run))

            # 统计本段中语义相关（非重定位样）的字节数。
            for k in range(start, j):
                if k not in reloc_bytes:
                    changed_semantic += 1

            i = j
        else:
            i += 1
        if len(changes) > max_changes:
            return None

    if changed_semantic / max(1, size) > max_ratio:
        return None

    return changes


def _estimate_patch_cost(old_off: int, size: int, changes: List[Tuple[int, bytes]]) -> int:
    """
    估算某个区域使用 PATCH_FROM_OLD 指令编码时的大致大小。
    """
    total = 1 + uleb128_len(old_off) + uleb128_len(size) + uleb128_len(len(changes))
    last = 0
    for off, data in changes:
        delta = off - last
        total += uleb128_len(delta) + uleb128_len(len(data)) + len(data)
        last = off
    return total


def _estimate_add_cost(length: int) -> int:
    """
    估算一段字面量序列使用 ADD 指令编码时的大致大小。
    """
    return 1 + uleb128_len(length) + length


def generate_patch(old_path: str, new_path: str,
                   old_sym_json: Optional[str] = None, new_sym_json: Optional[str] = None,
                   old_map: Optional[str] = None, new_map: Optional[str] = None,
                   flash_base: int = 0x08000000,
                   use_cdc: bool = False,
                   arch_mode: str = "auto",
                   reloc_aware: bool = False,
                   reloc_th: float = 0.6,
                   reloc_filter: bool = False,
                   reloc_debug: bool = False,
                   endian: str = "le"):
    with open(old_path, 'rb') as f:
        old_bin = f.read()
    with open(new_path, 'rb') as f:
        new_bin = f.read()
    old_len = len(old_bin)
    new_len = len(new_bin)
    target_size = new_len
    flash_lo = flash_base
    flash_hi = flash_base + max(old_len, new_len)

    fast = try_global_compact_patch(old_bin, new_bin, ratio_threshold=0.02)
    if fast is not None:
        return fast

    old_syms_raw, _ = load_symbols_any(old_sym_json, old_map, flash_base, old_len)
    new_syms_raw, _ = load_symbols_any(new_sym_json, new_map, flash_base, new_len)

    semantic_regions = []
    covered = [False] * new_len

    if old_syms_raw and new_syms_raw:
        pairs = pair_symbols(old_syms_raw, new_syms_raw, old_len, new_len)

        merged_pairs = safe_merge_symbol_regions(
            pairs, old_bin, new_bin, 
            debug=reloc_debug
        )
        
        if reloc_debug and len(merged_pairs) != len(pairs):
            print(f"[MERGE-INFO] 符号区域合并: {len(pairs)} -> {len(merged_pairs)} 个区域")

        for n_off, o_off, size in merged_pairs:
            size = min(size, new_len - n_off, old_len - o_off)
            if size <= 0:
                continue

            if reloc_aware:
                mode_sel = arch_mode
                if mode_sel == "auto":
                    mo = guess_arch_mode(old_bin[o_off:o_off+min(size, 4096)], flash_lo, flash_hi)
                    mn = guess_arch_mode(new_bin[n_off:n_off+min(size, 4096)], flash_lo, flash_hi)
                    mode_sel = mo if mo == mn else mn

                old_base_addr = int(old_syms_raw.get('flash_base', flash_base)) if isinstance(old_syms_raw, dict) else flash_base
                new_base_addr = int(new_syms_raw.get('flash_base', flash_base)) if isinstance(new_syms_raw, dict) else flash_base
                o_abs = old_base_addr + o_off
                n_abs = new_base_addr + n_off

                try:
                    sim = reloc_aware_similarity_lite(
                        old_bin[o_off:o_off+size],
                        new_bin[n_off:n_off+size],
                        o_abs, n_abs,
                        mode=mode_sel,
                        endian=endian
                    )
                except TypeError:
                    sim = reloc_aware_similarity_lite(
                        old_bin[o_off:o_off+size],
                        new_bin[n_off:n_off+size]
                    )
                
                if reloc_filter and sim < reloc_th:
                    continue
                if sim >= 0.85:
                    max_ratio = 0.7
                elif sim >= 0.70:
                    max_ratio = 0.6
                else:
                    max_ratio = 0.5
            else:
                max_ratio = 0.5

            allowed_changes = max(128, size // 4) if reloc_aware else 64
            if reloc_aware:
                # 第 3 阶段 / 第 1 步：在语义区域内部做重定位感知差分。
                # 对类似指针的字进行掩码，避免地址噪声抬高变化密度。
                changes = diff_symbol_region_reloc(
                    old_bin,
                    new_bin,
                    o_off,
                    n_off,
                    size,
                    flash_lo,
                    flash_hi,
                    endian=endian,
                    max_changes=allowed_changes,
                    max_ratio=max_ratio,
                )
            else:
                changes = diff_symbol_region(
                    old_bin,
                    new_bin,
                    o_off,
                    n_off,
                    size,
                    max_changes=allowed_changes,
                    max_ratio=max_ratio,
                )

            if changes is None:
                print(f"[DEBUG] 区域 0x{n_off:08X}-0x{n_off+size:08X} 使用ADD: "
                      f"size={size}, max_ratio={max_ratio}, allowed_changes={allowed_changes}")
            else:
                change_bytes = sum(len(data) for _, data in changes)
                density = change_bytes / size if size > 0 else 0
                print(f"[DEBUG] 区域 0x{n_off:08X}-0x{n_off+size:08X} 使用PATCH: "
                      f"size={size}, 变更点={len(changes)}, 变更字节={change_bytes}, "
                      f"密度={density:.3f}, 阈值={max_ratio}")
            if reloc_debug:
                print(f"[RELOC] n=0x{n_off:08X} o=0x{o_off:08X} sz={size} sim={locals().get('sim',0):.3f} "
                      f"max_ratio={max_ratio:.2f} max_changes={allowed_changes}")

            if changes is not None:
                semantic_regions.append((n_off, o_off, size, changes))
                for k in range(n_off, n_off + size):
                    covered[k] = True

        # ====== 追加: section 级别的粗粒度语义区域 ======
        if reloc_aware and new_len < 200000:
            sec_pairs = _extract_section_pairs(
                old_syms_raw, new_syms_raw, flash_base, old_len, new_len
            )
            for n_off, o_off, size in sec_pairs:
                # 只在尚未覆盖的区间内追加，避免与符号区域重叠
                start = n_off
                end = n_off + size
                cur = start
                while cur < end:
                    if cur >= new_len:
                        break
                    if covered[cur]:
                        cur += 1
                        continue
                    run_start = cur
                    while cur < end and cur < new_len and not covered[cur]:
                        cur += 1
                    run_size = cur - run_start
                    if run_size <= 0:
                        continue
                    # 尝试对这一段做重定位感知差分
                    allowed = max(128, run_size // 4)
                    changes = diff_symbol_region_reloc(
                        old_bin,
                        new_bin,
                        o_off + (run_start - n_off),
                        run_start,
                        run_size,
                        flash_lo,
                        flash_hi,
                        endian=endian,
                        max_changes=allowed,
                        max_ratio=0.5,
                    )
                    if changes is not None:
                        semantic_regions.append(
                            (run_start, o_off + (run_start - n_off), run_size, changes)
                        )
                        for k in range(run_start, run_start + run_size):
                            if 0 <= k < new_len:
                                covered[k] = True

    # ====== 识别间隙区 ======
    gap_regions = []
    start = -1
    for i in range(new_len):
        if not covered[i]:
            if start == -1:
                start = i
        else:
            if start != -1:
                gap_regions.append((start, i - start))
                start = -1
    if start != -1 and start < new_len:
        gap_regions.append((start, new_len - start))
    
    # ====== 合并语义区和间隙区，按地址排序 ======
    all_regions = []
    # 添加间隙区
    for start, size in gap_regions:
        all_regions.append({
            'type': 'gap',
            'start': start,
            'size': size
        })
    # 添加语义区
    for n_off, o_off, size, changes in semantic_regions:
        all_regions.append({
            'type': 'semantic',
            'start': n_off,
            'size': size,
            'old_offset': o_off,
            'changes': changes
        })
    
    # 按起始地址排序
    all_regions.sort(key=lambda x: x['start'])

    # 为 Path 2 预先构建基于整个新固件的全局匹配，用于后续 gap 区域复用
    # 注意：这里不直接发射指令，只作为 gap 处理中 COPY 候选。
    # 这里首先基于 dump.txt/dump.py 提供的 norm_sites 构造“归一化”视图，
    # 然后在真实固件字节上细化匹配，确保 COPY 只覆盖完全相同的字节。
    match_old = old_bin
    match_new = new_bin
    if old_syms_raw and new_syms_raw:
        try:
            match_old = _build_normalized_stream_from_raw(
                old_bin, old_syms_raw, flash_base,
                arch_mode=arch_mode, endian=endian,
            )
            match_new = _build_normalized_stream_from_raw(
                new_bin, new_syms_raw, flash_base,
                arch_mode=arch_mode, endian=endian,
            )
            print("[GLOBAL] 使用“归一化”字节流执行 gap 全局匹配")
        except Exception as e:
            print(f"[GLOBAL] 归一化失败, 回退到原始字节: {e}")
            match_old = old_bin
            match_new = new_bin

    # 仍然使用 global_greedy_hybrid 进行全局/局部混合匹配
    matches_norm = global_greedy_hybrid(match_old, match_new, min_length=16)
    # 在真实固件字节上细化 / 过滤匹配，确保 COPY 只覆盖完全相同的数据
    global_matches = _refine_matches_to_real_bytes(matches_norm, old_bin, new_bin)

    pb = PatchBuilder(target_size)
    pb.header()

    # 间隙区统计
    gap_add_data = gap_add_meta = gap_add_count = 0
    gap_copy_meta = gap_copy_count = 0
    gap_bytes = 0
    
    # 非间隙区统计
    non_gap_bytes = 0

    # 准备索引
    if use_cdc:
        cdc_avg_size = 256
        cdc_min_size = 64
        cdc_max_size = 1024
        _ = build_cdc_index(old_bin, avg_size=cdc_avg_size, min_size=cdc_min_size, max_size=cdc_max_size)
        block_idx = build_block_index(old_bin, block=32, step=4)
    else:
        block_idx = build_block_index(old_bin, block=48, step=8)

    # ======按顺序处理所有区域 ======
    semantic_add_count = 0
    semantic_copy_count = 0

    for region in tqdm(all_regions, desc="处理所有区域"):
        if region['type'] == 'gap':
            # 处理间隙区
            region_data = new_bin[region['start']:region['start'] + region['size']]
            start_size = pb.current_size()
            
            inc = process_gap_region(
                old_bin,
                region_data,
                block_idx,
                pb,
                block_size=48,
                min_run=32,
                scan_step=8,
                
                global_matches=None,
                region_start=region['start'],
            )
            
            # 更新统计
            region_bytes = pb.current_size() - start_size
            gap_add_data += inc[0]
            gap_add_meta += inc[1]
            gap_add_count += inc[2]
            gap_copy_meta += inc[3]
            gap_copy_count += inc[4]
            gap_bytes += region_bytes
            
        else:  # 语义区
            # 处理语义区
            start_size = pb.current_size()
            before_add = pb.stats['ADD']
            before_copy = pb.stats['COPY']
            emit_best_for_region(
                pb, 
                region['old_offset'], 
                new_bin[region['start']:region['start'] + region['size']], 
                region['changes']
            )
            semantic_add_count += pb.stats['ADD'] - before_add
            semantic_copy_count += pb.stats['COPY'] - before_copy
            non_gap_bytes += pb.current_size() - start_size

    if use_cdc:
        pb.flush_add()

    pb.end()
    patch_bytes = pb.bytes(compress=True)
    total_patch_size = len(patch_bytes)
    
    # 计算真实间隙区大小
    true_gap_size = sum(size for _, size in gap_regions)
    true_non_gap_size = new_len - true_gap_size

    # ====== 打印统计信息 ======
    total_gap_data = gap_add_data  # 只有ADD指令有数据
    total_gap_meta = gap_add_meta + gap_copy_meta
    
    print(f"[GAP] 间隙区数量: {len(gap_regions)}")
    print(f"[GAP] 间隙区总大小: {true_gap_size} bytes ({true_gap_size / new_len * 100:.2f}%)")
    print(f"[GAP] 间隙区指令大小: {gap_bytes} bytes ({gap_bytes / total_patch_size * 100:.2f}%)")
    
    if gap_add_count > 0:
        print(f"[GAP-DETAIL] ADD: 平均长度={gap_add_data/max(1,gap_add_count):.2f}, 元数据比例={gap_add_meta/max(1,gap_add_data+gap_add_meta)*100:.2f}%")
    if gap_copy_count > 0:
        print(f"[GAP-DETAIL] COPY: 指令数={gap_copy_count}, 平均元数据大小={(gap_copy_meta/gap_copy_count):.2f} bytes")
    print(f"[GAP-DETAIL] 间隙区总数据={total_gap_data} bytes, 元数据={total_gap_meta} bytes")
    
    # 新增：压缩率统计
    if true_gap_size > 0:
        compression_ratio = (true_gap_size - gap_bytes) / true_gap_size * 100
        ratio_status = "压缩" if compression_ratio > 0 else "膨胀"
        print(f"[GAP-ANALYSIS] 间隙区压缩率: {ratio_status} {abs(compression_ratio):.2f}% (原始{true_gap_size} bytes → 补丁{gap_bytes} bytes)")
    
    print(f"[SEMANTIC] 语义区 COPY 指令数: {semantic_copy_count}，ADD 指令数: {semantic_add_count}")

    return patch_bytes, pb.stats

def _verify_with_apply(old_path: str, new_path: str, patch_path: str, payload: int = 502) -> bool:
    """用模块方式调用 apply_patch。"""
    cmd = [
        sys.executable, "-m", "generator.tools.apply_patch",
        "--old", old_path,
        "--patch", patch_path,
        "--expect", new_path,
        "--payload", str(payload),
    ]
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        print(f"[VERIFY] 运行失败: {e}")
        return False
    out = cp.stdout or ""
    print(out.strip())
    return cp.returncode == 0 and "[OK] 重建结果与期望固件一致" in out

def count_op_bytes(patch_bytes):
    import zlib
    from generator.core.protocol import OP_COPY, OP_ADD, OP_PATCH_FROM_OLD, OP_FILL, OP_PATCH_COMPACT, OP_END, HEADER_SIZE
    try:
        raw = zlib.decompress(patch_bytes)
    except Exception:
        raw = patch_bytes
    op_map = {
        OP_COPY: "COPY",
        OP_ADD: "ADD",
        OP_PATCH_FROM_OLD: "PATCH",
        OP_FILL: "FILL",
        OP_PATCH_COMPACT: "PATCH_COMPACT",
    }
    def read_uleb128(raw, i):
        val = 0
        shift = 0
        start = i
        while True:
            b = raw[i]
            val |= (b & 0x7F) << shift
            shift += 7
            i += 1
            if not (b & 0x80):
                break
        return val, i, i - start

    i = HEADER_SIZE
    from collections import Counter
    op_bytes = Counter()
    while i < len(raw):
        op = raw[i]
        start = i
        i += 1
        if op == OP_COPY:
            for _ in range(2):
                _, i, _ = read_uleb128(raw, i)
        elif op == OP_ADD:
            l, i2, llen = read_uleb128(raw, i)
            i = i2 + l
        elif op == OP_PATCH_FROM_OLD:
            _, i, _ = read_uleb128(raw, i)
            plen, i, _ = read_uleb128(raw, i)
            nchanges, i, _ = read_uleb128(raw, i)
            last = 0
            for _ in range(nchanges):
                delta, i, _ = read_uleb128(raw, i)
                clen, i, _ = read_uleb128(raw, i)
                i += clen
                last += delta
        elif op == OP_PATCH_COMPACT:
            _, i, _ = read_uleb128(raw, i)
            plen, i, _ = read_uleb128(raw, i)
            nchanges, i, _ = read_uleb128(raw, i)
            if nchanges == 0:
                pass
            else:
                change_len, i, _ = read_uleb128(raw, i)
                for _ in range(nchanges):
                    _, i, _ = read_uleb128(raw, i)
                i += nchanges * change_len
        elif op == OP_FILL:
            for _ in range(2):
                _, i, _ = read_uleb128(raw, i)
        elif op == OP_END:
            break
        else:
            break
        op_bytes[op_map.get(op, "OTHER")] += (i - start)
    other_bytes = len(raw) - sum(op_bytes.values())
    if other_bytes > 0:
        op_bytes["OTHER"] += other_bytes
    return op_bytes

def count_op_bytes_meta_data(patch_bytes):
    import zlib
    from generator.core.protocol import OP_COPY, OP_ADD, OP_PATCH_FROM_OLD, OP_FILL, OP_PATCH_COMPACT, OP_END, HEADER_SIZE
    try:
        raw = zlib.decompress(patch_bytes)
    except Exception:
        raw = patch_bytes
    op_map = {
        OP_COPY: "COPY",
        OP_ADD: "ADD",
        OP_PATCH_FROM_OLD: "PATCH",
        OP_FILL: "FILL",
        OP_PATCH_COMPACT: "PATCH_COMPACT",
        OP_END: "END"
    }
    def read_uleb128(raw, i):
        val = 0
        shift = 0
        start = i
        while True:
            b = raw[i]
            val |= (b & 0x7F) << shift
            shift += 7
            i += 1
            if not (b & 0x80):
                break
        return val, i, i - start

    i = HEADER_SIZE
    from collections import Counter, defaultdict
    meta_bytes = Counter()
    data_bytes = Counter()
    while i < len(raw):
        op = raw[i]
        op_name = op_map.get(op, "OTHER")
        start = i
        i += 1
        meta = 1  # 指令头部
        if op == OP_COPY:
            _, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
            _, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
        elif op == OP_ADD:
            l, i2, llen = read_uleb128(raw, i)
            meta += llen
            i = i2
            data_bytes[op_name] += l
            i += l
        elif op == OP_PATCH_FROM_OLD:
            _, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
            _, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
            nchanges, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
            last = 0
            for _ in range(nchanges):
                delta, i2, l1 = read_uleb128(raw, i)
                meta += l1
                i = i2
                clen, i2, l2 = read_uleb128(raw, i)
                meta += l2
                i = i2
                data_bytes[op_name] += clen
                i += clen
                last += delta
        elif op == OP_PATCH_COMPACT:
            _, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
            _, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
            nchanges, i2, l = read_uleb128(raw, i)
            meta += l
            i = i2
            if nchanges > 0:
                change_len, i2, llen = read_uleb128(raw, i)
                meta += llen
                i = i2
                last = 0
                for _ in range(nchanges):
                    delta, i2, l = read_uleb128(raw, i)
                    meta += l
                    i = i2
                    last += delta
                data_bytes[op_name] += nchanges * change_len
                i += nchanges * change_len
        elif op == OP_FILL:
            for _ in range(2):
                _, i2, l = read_uleb128(raw, i)
                meta += l
                i = i2
        elif op == OP_END:
            pass
        else:
            break
        meta_bytes[op_name] += meta
    return meta_bytes, data_bytes


def generate_patch_global_only(
    old_path: str,
    new_path: str,
    min_match_len: int = 16,
    *,
    old_sym_json: Optional[str] = None,
    new_sym_json: Optional[str] = None,
    flash_base: int = 0,
    arch_mode: str = "arm",
    endian: str = "le",
    speed_profile: str = "balanced",
) -> Tuple[bytes, dict]:
    """
    仅使用全局匹配的基线版本：忽略符号 / 重定位信息，
    只依赖 global_greedy_hybrid 找到的匹配，用 COPY+ADD 构造补丁。
    """
    with open(old_path, 'rb') as f:
        old_bin = f.read()
    with open(new_path, 'rb') as f:
        new_bin = f.read()
    new_len = len(new_bin)

    # （可选）基于反汇编得到的掩码点构建归一化视图，掩码点来自符号 JSON（如果提供），
    # 用于驱动匹配，而补丁发射阶段仍然使用真实字节。
    old_raw = None
    new_raw = None
    old_parsed = {}
    new_parsed = {}
    if old_sym_json and os.path.isfile(old_sym_json):
        try:
            old_raw, old_parsed = load_symbols_any(old_sym_json, None, flash_base, len(old_bin))
        except Exception:
            old_raw = None
            old_parsed = {}
    if new_sym_json and os.path.isfile(new_sym_json):
        try:
            new_raw, new_parsed = load_symbols_any(new_sym_json, None, flash_base, len(new_bin))
        except Exception:
            new_raw = None
            new_parsed = {}

    code_mask, func_start_prefix = _build_code_mask_from_symbols(
        new_raw,
        new_parsed,
        new_len,
        flash_base,
    )

    if old_raw and new_raw:
        old_match_bytes = _build_normalized_stream_from_raw(
            old_bin, old_raw, flash_base, arch_mode=arch_mode, endian=endian
        )
        new_match_bytes = _build_normalized_stream_from_raw(
            new_bin, new_raw, flash_base, arch_mode=arch_mode, endian=endian
        )
        print(f"[GLOBAL] using global_dp_hybrid (normalized), min_match_len={min_match_len}")
    else:
        old_match_bytes = old_bin
        new_match_bytes = new_bin
        print(f"[GLOBAL] using global_dp_hybrid, min_match_len={min_match_len}")

    speed_kwargs = _speed_profile_kwargs(speed_profile)
    matches = global_dp_hybrid(
        old_match_bytes,
        new_match_bytes,
        min_length=min_match_len,
        code_mask=code_mask,
        func_boundary_prefix=func_start_prefix,
        **speed_kwargs,
    )

    pb = PatchBuilder(new_len)
    pb.header()

    cur = 0
    for n_off, o_off, ln in matches:
        if ln <= 0:
            continue
        if n_off < cur:
            # DP 结果中不应该出现重叠，防御性跳过
            continue
        if n_off > cur:
            # 先发射 gap 区域的字面量
            emit_literals(pb, new_bin[cur:n_off])
        size = ln
        # 在全局匹配块上做一次局部 diff，决定是 COPY / PATCH_FROM_OLD / ADD 更合算
        try:
            changes = diff_symbol_region(
                old_bin,
                new_bin,
                o_off,
                n_off,
                size,
                max_changes=1 << 30,
                max_ratio=1.0,
            )
        except Exception:
            changes = None
        emit_best_for_region(
            pb,
            o_off,
            new_bin[n_off:n_off + size],
            changes,
        )
        cur = n_off + size

    if cur < new_len:
        emit_literals(pb, new_bin[cur:])

    pb.end()
    patch_bytes = pb.bytes(compress=True)
    return patch_bytes, pb.stats


def main():
    ap = argparse.ArgumentParser(description="语义感知固件差分补丁生成器（含 502B 分片）")
    sub = ap.add_subparsers(dest='cmd', required=True)

    g = sub.add_parser('gen', help='生成补丁')
    g.add_argument('--old', required=True, help='旧固件 bin')
    g.add_argument('--new', required=True, help='新固件 bin')
    g.add_argument('--old-sym', default=None, help='旧符号 JSON')
    g.add_argument('--new-sym', default=None, help='新符号 JSON')
    g.add_argument('--old-map', default=None, help='旧固件 map')
    g.add_argument('--new-map', default=None, help='新固件 map')
    g.add_argument('--flash-base', default='0x08000000', help='FLASH 基地址')
    g.add_argument('--out', required=True, help='输出补丁文件')
    g.add_argument('--frames', default=None, help='分片输出目录')
    g.add_argument('--frame-size', type=int, default=502, help='每片有效载荷字节数')
    g.add_argument('--cdc', action='store_true', help='启用 CDC 匹配策略（仅高级模式）')
    g.add_argument('--arch-mode', default='auto', choices=['auto','thumb','arm','raw'], help='ARM 架构模式（自动/Thumb/ARM/raw）')
    g.add_argument('--endian', default='le', choices=['le','be'], help='端序（TMS570 多为 be）')
    g.add_argument('--mode', default='global', choices=['global', 'advanced'],
                   help='选择补丁生成模式：global（默认，全局语义匹配）或 advanced（原始语义差分路径）')
    g.add_argument('--reloc-aware', action='store_true', help='启用重定位/指令模式相似性判别')
    g.add_argument('--reloc-th', type=float, default=0.6, help='语义区进入阈值（0-1）')
    g.add_argument('--reloc-filter', action='store_true', help='当相似度低于阈值时丢弃语义区（默认不丢弃，仅调阈值）')
    g.add_argument('--reloc-debug', action='store_true', help='打印相似度分项以便诊断')
    g.add_argument("--verify", action="store_true", help="生成后用设备端应用器校验（apply_patch.py）")
    g.add_argument("--payload", type=int, default=502, help="校验时模拟设备端每片有效载荷字节数，默认 502")
    g.add_argument('--speed-profile', default='balanced', choices=['balanced', 'fast'],
                   help='速度/体积权衡：balanced（默认）或 fast（更快生成，可能轻微增大补丁）')

    args = ap.parse_args()
    try:
        flash_base = int(args.flash_base, 0)
    except Exception:
        print("[ERROR] --flash-base 格式错误", file=sys.stderr)
        sys.exit(2)

    if args.mode == 'global':
        print("[MODE] 使用 global 语义匹配路径（首选）")
        patch_bytes, stats = generate_patch_global_only(
            args.old,
            args.new,
            old_sym_json=args.old_sym,
            new_sym_json=args.new_sym,
            flash_base=flash_base,
            arch_mode=args.arch_mode,
            endian=args.endian,
        )
    else:
        print("[MODE] 使用 advanced 语义差分路径")
        patch_bytes, stats = generate_patch(
            args.old, args.new,
            old_sym_json=args.old_sym, new_sym_json=args.new_sym,
            old_map=args.old_map, new_map=args.new_map,
            flash_base=flash_base,
            use_cdc=args.cdc,
            arch_mode=args.arch_mode,
            reloc_aware=args.reloc_aware,
            reloc_th=args.reloc_th,
            reloc_filter=args.reloc_filter,
            reloc_debug=args.reloc_debug,
            endian=args.endian
        )
    with open(args.out, 'wb') as f:
        f.write(patch_bytes)
    print(f"[OK] 补丁已生成: {args.out}, 长度 {len(patch_bytes)} bytes")
    total_ops = sum(stats.values())
    print(f"[STATS] 指令总数={total_ops} | COPY={stats.get('COPY',0)} "
          f"PATCH={stats.get('PATCH',0)} ADD={stats.get('ADD',0)} FILL={stats.get('FILL',0)} "
          f"PATCH_COMPACT={stats.get('PATCH_COMPACT',0)}")

    op_bytes = count_op_bytes(patch_bytes)
    total_bytes = sum(op_bytes.values())
    print("[COST] 指令类型字节开销:")
    for k, v in op_bytes.items():
        print(f"  {k}: bytes={v} pct={v/total_bytes*100:.2f}%")

    def count_op_stats(patch_bytes):
        import zlib
        from generator.core.protocol import OP_COPY, OP_ADD, OP_PATCH_FROM_OLD, OP_FILL, OP_PATCH_COMPACT, OP_END, HEADER_SIZE
        try:
            raw = zlib.decompress(patch_bytes)
        except Exception:
            raw = patch_bytes
        op_map = {
            OP_COPY: "COPY",
            OP_ADD: "ADD",
            OP_PATCH_FROM_OLD: "PATCH",
            OP_FILL: "FILL",
            OP_PATCH_COMPACT: "PATCH_COMPACT",
        }
        def read_uleb128(raw, i):
            val = 0
            shift = 0
            while True:
                b = raw[i]
                val |= (b & 0x7F) << shift
                shift += 7
                i += 1
                if not (b & 0x80):
                    break
            return val, i

        i = HEADER_SIZE
        from collections import defaultdict
        op_lens = defaultdict(list)
        while i < len(raw):
            op = raw[i]
            start = i
            i += 1
            if op == OP_COPY:
                for _ in range(2):
                    _, i = read_uleb128(raw, i)
                op_lens["COPY"].append(i - start)
            elif op == OP_ADD:
                l, i2 = read_uleb128(raw, i)
                i = i2 + l
                op_lens["ADD"].append(l)
            elif op == OP_PATCH_FROM_OLD:
                _, i = read_uleb128(raw, i)
                plen, i = read_uleb128(raw, i)
                nchanges, i = read_uleb128(raw, i)
                last = 0
                for _ in range(nchanges):
                    delta, i = read_uleb128(raw, i)
                    clen, i = read_uleb128(raw, i)
                    i += clen
                    last += delta
                op_lens["PATCH"].append(i - start)
            elif op == OP_PATCH_COMPACT:
                _, i = read_uleb128(raw, i)
                plen, i = read_uleb128(raw, i)
                nchanges, i = read_uleb128(raw, i)
                if nchanges == 0:
                    pass
                else:
                    change_len, i = read_uleb128(raw, i)
                    for _ in range(nchanges):
                        _, i = read_uleb128(raw, i)
                    i += nchanges * change_len
                op_lens["PATCH_COMPACT"].append(i - start)
            elif op == OP_FILL:
                for _ in range(2):
                    _, i = read_uleb128(raw, i)
                op_lens["FILL"].append(i - start)
            elif op == OP_END:
                break
            else:
                break
        return op_lens

    op_lens = count_op_stats(patch_bytes)
    if op_lens["ADD"]:
        add_lens = op_lens["ADD"]
        print(f"[DIAG] ADD 片段数={len(add_lens)} 总字节={sum(add_lens)} 平均长度={sum(add_lens)/len(add_lens):.2f}")
        print(f"[DIAG] ADD Top10 长度={sorted(add_lens, reverse=True)[:10]}")
        if sum(add_lens)/len(add_lens) < 4:
            print("[DIAG] 注意: 平均 ADD 长度 <4, 分块过碎, 可尝试聚簇合并或提高 CDC 最小块大小.")
    if op_lens["COPY"]:
        copy_lens = op_lens["COPY"]
        print(f"[DIAG] COPY 片段数={len(copy_lens)} 总字节={sum(copy_lens)} 平均长度={sum(copy_lens)/len(copy_lens):.2f}")
        print(f"[DIAG] COPY Top10 长度={sorted(copy_lens, reverse=True)[:10]}")
    if op_lens["PATCH_COMPACT"]:
        pc_lens = op_lens["PATCH_COMPACT"]
        print(f"[DIAG] PATCH_COMPACT 区域数={len(pc_lens)} 平均长度={sum(pc_lens)/len(pc_lens):.2f}")
    if op_lens["PATCH"]:
        p_lens = op_lens["PATCH"]
        print(f"[DIAG] PATCH 区域数={len(p_lens)} 平均长度={sum(p_lens)/len(p_lens):.2f}")

    meta_bytes, data_bytes = count_op_bytes_meta_data(patch_bytes)
    total_meta = sum(meta_bytes.values())
    total_data = sum(data_bytes.values())
    print("[META] 指令元数据字节开销:")
    try:
        from generator.parsers.symbols import load_symbols_any, pair_symbols
        with open(args.old, 'rb') as f:
            old_bin = f.read()
        with open(args.new, 'rb') as f:
            new_bin = f.read()
        old_len = len(old_bin)
        new_len = len(new_bin)
        old_syms_raw, _ = load_symbols_any(args.old_sym, args.old_map, int(args.flash_base, 0), old_len)
        new_syms_raw, _ = load_symbols_any(args.new_sym, args.new_map, int(args.flash_base, 0), new_len)
        semantic_bytes = 0
        if old_syms_raw and new_syms_raw:
            pairs = pair_symbols(old_syms_raw, new_syms_raw, old_len, new_len)
            for n_off, o_off, size in pairs:
                size = min(size, new_len - n_off)
                if size > 0:
                    semantic_bytes += size
        hole_bytes = new_len - semantic_bytes
        print(f"[COVERAGE] 语义区覆盖={semantic_bytes} bytes ({semantic_bytes/new_len*100:.2f}%) | 空洞区={hole_bytes} bytes ({hole_bytes/new_len*100:.2f}%)")
    except Exception as e:
        print(f"[COVERAGE] 语义区覆盖统计失败: {e}")
    for k in meta_bytes:
        print(f"  {k}: meta_bytes={meta_bytes[k]} data_bytes={data_bytes.get(k,0)} "
              f"meta_pct={meta_bytes[k]/(total_meta+total_data)*100:.2f}% data_pct={data_bytes.get(k,0)/(total_meta+total_data)*100:.2f}%")
    print(f"  总元数据: {total_meta} bytes, 总数据: {total_data} bytes, 总补丁: {total_meta+total_data} bytes")

    if args.frames:
        os.makedirs(args.frames, exist_ok=True)
        frames, manifest = split_frames(patch_bytes, frame_payload_size=args.frame_size)
        for i, ch in enumerate(frames):
            with open(os.path.join(args.frames, f'frame_{i:05d}.bin'), 'wb') as f:
                f.write(ch)
        with open(os.path.join(args.frames, 'manifest.json'), 'w', encoding='utf-8') as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        print(f"[OK] 已输出分片到 {args.frames}, 共 {len(frames)} 片, 每片有效载荷 {args.frame_size}B")
        print(f"[OK] manifest.json: total_len={manifest['total_len']} total_crc32=0x{manifest['total_crc32']:08X}")

    if args.verify:
        ok = _verify_with_apply(args.old, args.new, args.out, payload=args.payload)
        if ok:
            print("[VERIFY] OK: apply_patch 重建与新固件一致")
        else:
            print("[VERIFY] FAIL: apply_patch 重建与新固件不一致")
            if args.mode == 'global':
                print("[VERIFY] 已在 global 模式下，无法继续回退。")
                sys.exit(2)
            # 自动回退到全局 COPY+ADD 补丁，但这一次带上符号 / 段信息，启用归一化与 code-aware DP。
            print("[VERIFY] fallback: 尝试使用全局匹配生成的简单补丁 (global-only)")
            patch_bytes2, stats2 = generate_patch_global_only(
                args.old,
                args.new,
                min_match_len=16,
                old_sym_json=args.old_sym,
                new_sym_json=args.new_sym,
                flash_base=flash_base,
                arch_mode=args.arch_mode,
                endian=args.endian,
            )
            with open(args.out, 'wb') as f:
                f.write(patch_bytes2)
            print(f"[FALLBACK] 已生成 global-only 补丁到 {args.out}, size={len(patch_bytes2)}")
            ok2 = _verify_with_apply(args.old, args.new, args.out, payload=args.payload)
            if ok2:
                print("[VERIFY] OK: fallback global-only 补丁重建与新固件一致")
            else:
                print("[VERIFY] FAIL: fallback global-only 补丁仍然不一致")
                sys.exit(2)

if __name__ == '__main__':
    main()
