#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# generate.py - 语义感知的轻量固件差分补丁生成器（主入口）

from typing import Optional, Tuple, List, Dict
from tqdm import tqdm

from generator.cli.main import run_cli

from generator.strategies.global_match import global_greedy_hybrid
from generator.strategies.global_dp import global_dp_hybrid
from generator.core.protocol import (
    PatchBuilder,
    OP_ADD,
    OP_COPY,
    estimate_add_bytes,
    estimate_copy_bytes,
)
from generator.parsers.symbols import pair_symbols, safe_merge_symbol_regions
from generator.strategies.cdc import cdc_emit_region, build_cdc_index
from generator.strategies.greedy import build_block_index, greedy_match
from generator.strategies.heuristics import (
    diff_symbol_region,
    emit_literals,
    emit_best_for_region,
    try_global_compact_patch,
    try_local_sparse_patch,
)
from generator.utils.symbols import load_symbol_context
from generator.analysis.simlite import (
    reloc_aware_similarity_lite,
    guess_arch_mode,
    find_ptr_sites,
    mask_ptr_like,
)
from generator.core.utils import uleb128_len

MIN_COPY_SAVING = 2  # require COPY to save at least 2 bytes vs literal
GAP_OPT_THRESHOLD = 256


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

class _GlobalMatchIndex:
    """Streaming index over global DP matches keyed by new-image offset."""

    def __init__(self, matches: Optional[List[Tuple[int, int, int]]]):
        self.matches = matches or []
        self.cursor = 0

    def slice(self, start: int, end: int) -> List[Tuple[int, int, int]]:
        matches = self.matches
        idx = self.cursor
        # Skip all matches that end before the requested range.
        while idx < len(matches) and matches[idx][0] + matches[idx][2] <= start:
            idx += 1
        self.cursor = idx
        out: List[Tuple[int, int, int]] = []
        while idx < len(matches):
            n_abs, o_off, ln = matches[idx]
            if n_abs >= end:
                break
            out.append((n_abs, o_off, ln))
            idx += 1
        return out


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
    flash_lo: Optional[int] = None,
    flash_hi: Optional[int] = None,
    endian: str = "le",
    reloc_hint: bool = False,
) -> Tuple[int, int, int, int, int, int, int]:
    """
    处理间隙区域，返回统计元素：
    (add_data_bytes, add_meta_bytes, add_count,
     copy_meta_bytes, copy_count,
     total_region_bytes)
    """
    region_len = len(new_region)
    if region_len == 0:
        return (0, 0, 0, 0, 0, 0)
    region_end = region_start + region_len

    start_size = pb.current_size()
    add_data = add_meta = add_count = 0
    copy_meta = copy_count = 0

    if (
        reloc_hint
        and flash_lo is not None
        and flash_hi is not None
        and 0 <= region_start <= len(old_bin) - region_len
        and region_len >= 48
        and _region_has_flash_pointer(new_region, flash_lo, flash_hi, endian=endian)
    ):
        reloc_changes = diff_symbol_region_reloc(
            old_bin,
            new_region,
            region_start,
            0,
            region_len,
            flash_lo,
            flash_hi,
            endian=endian,
            max_changes=min(256, region_len // 4),
            max_ratio=0.35,
        )
        if reloc_changes is not None:
            emit_best_for_region(
                pb,
                region_start,
                new_region,
                reloc_changes,
            )
            total_region_bytes = pb.current_size() - start_size
            return (0, 0, 0, 0, 0, total_region_bytes)

    if region_len <= GAP_OPT_THRESHOLD:
        emit_literals(pb, new_region)
        total_region_bytes = pb.current_size() - start_size
        return (
            region_len,
            1 + uleb128_len(region_len),
            1,
            0,
            0,
            total_region_bytes,
        )

    matches: List[Tuple[int, int, int]] = []
    covered = [False] * region_len

    if global_matches:
        for n_abs, o_off_m, ln in global_matches:
            if n_abs >= region_end:
                break
            if n_abs + ln <= region_start:
                continue
            overlap_start = max(n_abs, region_start)
            overlap_end = min(n_abs + ln, region_end)
            overlap_len = overlap_end - overlap_start
            if overlap_len < 8:
                continue
            rel_new = overlap_start - region_start
            rel_old = o_off_m + (overlap_start - n_abs)
            matches.append((rel_new, rel_old, overlap_len))
            for idx in range(rel_new, rel_new + overlap_len):
                if 0 <= idx < region_len:
                    covered[idx] = True

    def _fill_with_local_matches(seg_start: int, seg_end: int) -> None:
        if seg_end - seg_start <= 0:
            return
        local = greedy_match(
            old_bin,
            new_region[seg_start:seg_end],
            block_idx,
            block=block_size,
            min_run=min_run,
            scan_step=scan_step,
        )
        for rel_new, o_off_m, ln in local:
            abs_new = seg_start + rel_new
            matches.append((abs_new, o_off_m, ln))
            for idx in range(abs_new, abs_new + ln):
                if 0 <= idx < region_len:
                    covered[idx] = True

    if not matches:
        _fill_with_local_matches(0, region_len)
    else:
        cur = 0
        while cur < region_len:
            if covered[cur]:
                cur += 1
                continue
            seg_start = cur
            while cur < region_len and not covered[cur]:
                cur += 1
            _fill_with_local_matches(seg_start, cur)

    matches.sort(key=lambda x: x[0])

    cur = 0
    for n_off_rel, o_off_m, ln in matches:
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

    if cur < region_len:
        add_len = region_len - cur
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


def _looks_like_flash_ptr(value: int, flash_lo: int, flash_hi: int) -> bool:
    return flash_lo <= value < flash_hi


def _region_has_flash_pointer(data: bytes, flash_lo: int, flash_hi: int, *, endian: str = "le", sample_limit: int = 256) -> bool:
    if flash_lo is None or flash_hi is None:
        return False
    word = 4
    if len(data) < word:
        return False
    limit = min(len(data), sample_limit)
    byte_order = "big" if endian == "be" else "little"
    hits = 0
    for off in range(0, limit - word + 1, word):
        val = int.from_bytes(data[off:off + word], byte_order)
        if _looks_like_flash_ptr(val, flash_lo, flash_hi):
            hits += 1
            if hits >= 2:
                return True
    return False


def _detect_relocation_regions(
    old_bin: bytes,
    new_bin: bytes,
    covered: List[bool],
    flash_lo: int,
    flash_hi: int,
    *,
    endian: str = "le",
    min_words: int = 4,
    max_span: int = 4096,
) -> List[Tuple[int, int, List[Tuple[int, bytes]]]]:
    """
    检测仍在 gap 中但呈现重定位指针特征的区域，返回 (start, size, changes)。
    只有当对应旧固件位置存在、非指针字节完全一致且至少有一个指针值发生变化时才认为有效。
    """
    byte_order = "big" if endian == "be" else "little"
    word = 4
    limit = min(len(new_bin), len(covered))
    regions: List[Tuple[int, int, List[Tuple[int, bytes]]]] = []
    i = 0
    while i + word <= limit:
        if covered[i]:
            i += 1
            continue
        new_word = int.from_bytes(new_bin[i:i + word], byte_order)
        old_word = int.from_bytes(old_bin[i:i + word], byte_order) if i + word <= len(old_bin) else 0
        if not (_looks_like_flash_ptr(new_word, flash_lo, flash_hi) or _looks_like_flash_ptr(old_word, flash_lo, flash_hi)):
            i += 1
            continue

        start = i
        j = i
        ptr_offsets: List[int] = []
        while j + word <= limit and not covered[j] and (j - start) < max_span:
            nw = int.from_bytes(new_bin[j:j + word], byte_order)
            if j + word > len(old_bin):
                break
            ow = int.from_bytes(old_bin[j:j + word], byte_order)
            if not (_looks_like_flash_ptr(nw, flash_lo, flash_hi) or _looks_like_flash_ptr(ow, flash_lo, flash_hi)):
                break
            ptr_offsets.append(j)
            j += word

        run_len = j - start
        if len(ptr_offsets) < min_words or run_len <= 0 or start + run_len > len(old_bin):
            i = start + 1
            continue

        consistent = True
        changes: List[Tuple[int, bytes]] = []
        mask = [False] * run_len
        for ptr in ptr_offsets:
            rel0 = ptr - start
            for k in range(word):
                if rel0 + k < run_len:
                    mask[rel0 + k] = True

        for rel in range(run_len):
            if mask[rel]:
                continue
            if new_bin[start + rel] != old_bin[start + rel]:
                consistent = False
                break
        if not consistent:
            i = start + 1
            continue

        for ptr_off in ptr_offsets:
            rel = ptr_off - start
            new_slice = new_bin[ptr_off:ptr_off + word]
            old_slice = old_bin[ptr_off:ptr_off + word]
            if new_slice != old_slice:
                changes.append((rel, new_slice))

        if changes:
            regions.append((start, run_len, changes))
            for k in range(start, start + run_len):
                if k < len(covered):
                    covered[k] = True
            i = start + run_len
        else:
            i = start + 1
    return regions


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

    old_syms_raw, _ = load_symbol_context(old_sym_json, old_map, flash_base, old_len)
    new_syms_raw, _ = load_symbol_context(new_sym_json, new_map, flash_base, new_len)

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

    # 额外识别未覆盖但呈现重定位特征的区域
    reloc_regions = _detect_relocation_regions(
        old_bin,
        new_bin,
        covered,
        flash_lo,
        flash_hi,
        endian=endian,
    )
    for start, size, changes in reloc_regions:
        semantic_regions.append((start, start, size, changes))

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
    global_match_index = _GlobalMatchIndex(global_matches)

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
            
            gm_slice = global_match_index.slice(region['start'], region['start'] + region['size'])
            inc = process_gap_region(
                old_bin,
                region_data,
                block_idx,
                pb,
                block_size=48,
                min_run=32,
                scan_step=8,
                global_matches=gm_slice,
                region_start=region['start'],
                flash_lo=flash_lo,
                flash_hi=flash_hi,
                endian=endian,
                reloc_hint=True,
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
    flash_lo = flash_base
    flash_hi = flash_base + max(len(old_bin), new_len)

    # （可选）基于反汇编得到的掩码点构建归一化视图，掩码点来自符号 JSON（如果提供），
    # 用于驱动匹配，而补丁发射阶段仍然使用真实字节。
    old_raw, old_parsed = load_symbol_context(old_sym_json, None, flash_base, len(old_bin))
    new_raw, new_parsed = load_symbol_context(new_sym_json, None, flash_base, len(new_bin))

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

    block_idx = build_block_index(old_bin, block=48, step=8)

    cur = 0
    for n_off, o_off, ln in matches:
        if ln <= 0:
            continue
        if n_off < cur:
            # DP 结果中不应该出现重叠，防御性跳过
            continue
        if n_off > cur:
            process_gap_region(
                old_bin,
                new_bin[cur:n_off],
                block_idx,
                pb,
                block_size=48,
                min_run=32,
                scan_step=8,
                global_matches=None,
                region_start=cur,
                flash_lo=flash_lo,
                flash_hi=flash_hi,
                endian=endian,
                reloc_hint=True,
            )
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
        process_gap_region(
            old_bin,
            new_bin[cur:],
            block_idx,
            pb,
            block_size=48,
            min_run=32,
            scan_step=8,
            global_matches=None,
            region_start=cur,
            flash_lo=flash_lo,
            flash_hi=flash_hi,
            endian=endian,
            reloc_hint=True,
        )

    pb.end()
    patch_bytes = pb.bytes(compress=True)
    return patch_bytes, pb.stats


def main() -> None:
    run_cli(generate_patch_global_only, generate_patch)


if __name__ == '__main__':
    main()
