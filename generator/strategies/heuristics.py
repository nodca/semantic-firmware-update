from typing import List, Tuple, Optional
from ..core.protocol import PatchBuilder, compute_diff_data
from ..core.utils import uleb128_len

def diff_symbol_region(old_bytes: bytes, new_bytes: bytes, old_off: int, new_off: int, size: int,
                       max_changes: int = 16, max_ratio: float = 0.15) -> Optional[List[Tuple[int, bytes]]]:
    #print(max_ratio)
    olds = old_bytes[old_off:old_off+size]
    news = new_bytes[new_off:new_off+size]
    if olds == news:
        return []
    i = 0
    changes = []
    changed_bytes = 0
    while i < size:
        if olds[i] != news[i]:
            start = i
            j = i + 1
            while j < size and olds[j] != news[j]:
                j += 1
            run = news[start:j]
            changes.append((start, run))
            changed_bytes += (j - start)
            i = j
        else:
            i += 1
        if len(changes) > max_changes:
            return None
    if changed_bytes / max(1, size) > max_ratio:
        return None
    return changes

def emit_literals(pb: PatchBuilder, data: bytes, fill_threshold: int = 8):
    """
    使用缓冲的字面量发射
    """
    if not data:
        return
        
    # 如果有缓冲机制，使用缓冲ADD
    if hasattr(pb, 'buffered_add_literal'):
        pb.buffered_add_literal(data)
    else:
        # 回退到原来的逻辑
        i = 0
        n = len(data)
        while i < n:
            b = data[i]
            j = i + 1
            while j < n and data[j] == b:
                j += 1
            run_len = j - i
            if run_len >= fill_threshold:
                pb.flush_add()
                pb.op_fill(b, run_len)
            else:
                pb.add_literal(data[i:j])
            i = j

def try_local_sparse_patch(pb: PatchBuilder, old_bin: bytes, new_bin: bytes,
                           start: int, end: int,
                           max_runs: int = 24, max_ratio: float = 0.20) -> bool:
    length = end - start
    if length <= 0:
        return True
    old_len = len(old_bin)
    new_len = len(new_bin)
    if start >= old_len or start >= new_len:
        return False
    length = min(length, old_len - start, new_len - start)
    olds = old_bin[start:start+length]
    news = new_bin[start:start+length]
    if olds == news:
        pb.op_copy(start, length)
        return True
    i = 0
    runs = []
    diff_bytes = 0
    while i < length:
        if olds[i] != news[i]:
            s = i
            i += 1
            while i < length and olds[i] != news[i]:
                i += 1
            runs.append((s, news[s:i]))
            diff_bytes += (i - s)
            if len(runs) > max_runs:
                return False
        else:
            i += 1
    if diff_bytes / max(1, length) > max_ratio:
        return False
    cost_patch = _estimate_patch_size(start, length, runs)
    cost_add   = _estimate_add_size(length)
    if cost_add < cost_patch:
        return False
    pb.op_patch_from_old(start, length, runs)
    return True

def _estimate_patch_size(old_off: int, size: int, changes: List[Tuple[int, bytes]]) -> int:
    total = 1 + uleb128_len(old_off) + uleb128_len(size) + uleb128_len(len(changes))
    last = 0
    for off, data in changes:
        delta = off - last
        total += uleb128_len(delta) + uleb128_len(len(data)) + len(data)
        last = off
    return total

def _estimate_patch_compact_size(old_off: int, size: int, changes: List[Tuple[int, bytes]]) -> int:
    """
    粗略估算 PATCH_COMPACT 编码的大小：
      op, old_off, size, nchanges, change_len, deltas, data...
    只在所有改动块长度相同的情况下有效。
    """
    if not changes:
        return 0
    clen = len(changes[0][1])
    if clen <= 0:
        return 0
    # 要求所有块的长度完全相同
    for _, data in changes:
        if len(data) != clen:
            return 0
    total = 1  # opcode 字节
    total += uleb128_len(old_off) + uleb128_len(size)
    total += uleb128_len(len(changes))  # nchanges（改动块数量）
    total += uleb128_len(clen)          # change_len（单个改动块长度）
    last = 0
    for off, _ in changes:
        delta = off - last
        total += uleb128_len(delta)
        last = off
    total += len(changes) * clen  # 所有改动块的数据字节
    return total

def _estimate_add_size(lit_len: int) -> int:
    return 1 + uleb128_len(lit_len) + lit_len


def _estimate_diff_size(old_off: int, lit_len: int) -> int:
    """估算 DIFF 指令大小（不含压缩增益）"""
    return 1 + uleb128_len(old_off) + uleb128_len(lit_len) + lit_len


def emit_literals_with_diff(
    pb: PatchBuilder,
    new_data: bytes,
    old_bin: bytes,
    new_off: int,
    fill_threshold: int = 8,
    min_diff_len: int = 8,
) -> None:
    """
    智能选择 ADD 或 DIFF 来发射字面量数据。

    策略：如果 new_off 在旧固件范围内，计算差分数据并比较：
    - 差分数据中 0x00 的比例（越高越好压缩）
    - 基于压缩后预估大小来选择 ADD 或 DIFF
    """
    if not new_data:
        return

    length = len(new_data)
    old_len = len(old_bin)

    # 检查是否可以使用 DIFF（需要在旧固件范围内）
    can_diff = (
        new_off >= 0 and
        new_off + length <= old_len and
        length >= min_diff_len  # 最小长度阈值
    )

    if can_diff:
        # 计算差分数据
        diff_data = compute_diff_data(old_bin, new_data, new_off, 0, length)

        # 统计差分数据中的零字节比例
        zero_count = diff_data.count(0)
        zero_ratio = zero_count / length

        # 估算 DIFF 压缩后大小
        # DIFF 元数据：1 (opcode) + uleb128(old_off) + uleb128(length)
        diff_meta = 1 + uleb128_len(new_off) + uleb128_len(length)
        # 零字节在 zlib 中压缩效果很好，估算压缩后数据大小
        # 经验公式：零字节几乎不占空间，非零字节约占 0.9 比例
        estimated_diff_data = int(length * (1 - zero_ratio * 0.85))
        cost_diff = diff_meta + estimated_diff_data

        # 估算 ADD 的大小
        # ADD 元数据：1 (opcode) + uleb128(length)
        # ADD 数据压缩效果一般，假设约 0.7 的压缩率
        add_meta = 1 + uleb128_len(length)
        estimated_add_data = int(length * 0.7)
        cost_add = add_meta + estimated_add_data

        # 如果 DIFF 更划算，使用 DIFF
        # 额外条件：至少有 20% 的零字节才考虑 DIFF
        if cost_diff < cost_add and zero_ratio >= 0.20:
            pb.op_diff(new_off, diff_data)
            return

    # 回退到原来的 ADD 逻辑
    i = 0
    n = len(new_data)
    while i < n:
        b = new_data[i]
        j = i + 1
        while j < n and new_data[j] == b:
            j += 1
        run_len = j - i
        if run_len >= fill_threshold:
            pb.flush_add()
            pb.op_fill(b, run_len)
        else:
            pb.add_literal(new_data[i:j])
        i = j

def emit_best_for_region(pb: PatchBuilder, old_off: int, new_slice: bytes,
                         changes: Optional[List[Tuple[int, bytes]]],
                         old_bin: Optional[bytes] = None) -> None:
    size = len(new_slice)
    if size == 0:
        return

    # 完全相同 -> COPY
    if changes is not None and len(changes) == 0:
        pb.op_copy(old_off, size)
        return

    cost_add = _estimate_add_size(size)

    # 计算 DIFF 的预估成本（考虑压缩增益）
    cost_diff = 0
    diff_data = None
    if old_bin is not None and old_off >= 0 and old_off + size <= len(old_bin):
        diff_data = compute_diff_data(old_bin, new_slice, old_off, 0, size)
        # 统计零字节比例来估算压缩增益
        zero_count = diff_data.count(0)
        zero_ratio = zero_count / size if size > 0 else 0
        # DIFF 的元数据成本
        diff_meta = 1 + uleb128_len(old_off) + uleb128_len(size)
        # 估算压缩后大小：零字节压缩效果好，非零字节压缩效果一般
        # 粗略估计：零字节在 zlib 中几乎不占空间
        estimated_compressed = int(size * (1 - zero_ratio * 0.8))
        cost_diff = diff_meta + estimated_compressed

    # 计算 PATCH 成本（仅当 changes 有效时）
    cost_patch = 0
    cost_compact = 0
    if changes is not None and len(changes) > 0:
        cost_patch = _estimate_patch_size(old_off, size, changes)
        cost_compact = _estimate_patch_compact_size(old_off, size, changes)

    # 在 ADD / DIFF / PATCH / PATCH_COMPACT 中选择总开销最小的编码方式。
    best = cost_add
    kind = "ADD"
    if cost_diff and cost_diff < best:
        best = cost_diff
        kind = "DIFF"
    if cost_patch and cost_patch < best:
        best = cost_patch
        kind = "PATCH"
    if cost_compact and cost_compact < best:
        best = cost_compact
        kind = "PATCH_COMPACT"

    if kind == "ADD":
        emit_literals(pb, new_slice)
    elif kind == "DIFF":
        pb.op_diff(old_off, diff_data)
    elif kind == "PATCH":
        pb.op_patch_from_old(old_off, size, changes)
    else:  # PATCH_COMPACT
        pb.op_patch_compact(old_off, size, changes)

def _sum_changed_bytes(changes: List[Tuple[int, bytes]]) -> int:
    return sum(len(ch) for _, ch in changes)

def try_global_compact_patch(old_bytes: bytes, new_bytes: bytes,
                             ratio_threshold: float = 0.02) -> Optional[Tuple[bytes, dict]]:
    old_len = len(old_bytes)
    new_len = len(new_bytes)
    if old_len == 0 and new_len == 0:
        from ..core.protocol import PatchBuilder
        pb = PatchBuilder(0); pb.header(); pb.end()
        return pb.bytes(), pb.stats
    p = 0
    lim = min(old_len, new_len)
    while p < lim and old_bytes[p] == new_bytes[p]:
        p += 1
    s = 0
    while s < (old_len - p) and s < (new_len - p) and old_bytes[old_len - 1 - s] == new_bytes[new_len - 1 - s]:
        s += 1
    old_mid = max(0, old_len - p - s)
    new_mid = max(0, new_len - p - s)
    pre_changes = []
    suf_changes = []
    if p > 0:
        pre_changes = diff_symbol_region(old_bytes, new_bytes, 0, 0, p, max_changes=1<<30, max_ratio=1.0) or []
    if s > 0:
        suf_changes = diff_symbol_region(old_bytes, new_bytes, old_len - s, new_len - s, s, max_changes=1<<30, max_ratio=1.0) or []
    mid_patch_len = min(old_mid, new_mid)
    mid_changes = []
    if mid_patch_len > 0:
        mid_changes = diff_symbol_region(old_bytes, new_bytes, p, p, mid_patch_len, max_changes=1<<30, max_ratio=1.0) or []
    inserted = b''
    if new_mid > old_mid:
        inserted = new_bytes[p + mid_patch_len: p + new_mid]
    total_changed = _sum_changed_bytes(pre_changes) + _sum_changed_bytes(mid_changes) + _sum_changed_bytes(suf_changes) + len(inserted)
    ratio = total_changed / max(1, new_len)
    if ratio > ratio_threshold:
        return None
    from ..core.protocol import PatchBuilder
    pb = PatchBuilder(new_len)
    pb.header()
    if p > 0:
        if len(pre_changes) == 0:
            pb.op_copy(0, p)
        else:
            pb.op_patch_from_old(0, p, pre_changes)
    if mid_patch_len > 0:
        if len(mid_changes) == 0:
            pb.op_copy(p, mid_patch_len)
        else:
            pb.op_patch_from_old(p, mid_patch_len, mid_changes)
    if inserted:
        pb.op_add(inserted)
    if s > 0:
        o_off = old_len - s
        if len(suf_changes) == 0:
            pb.op_copy(o_off, s)
        else:
            pb.op_patch_from_old(o_off, s, suf_changes)
    pb.end()
    return pb.bytes(), pb.stats
