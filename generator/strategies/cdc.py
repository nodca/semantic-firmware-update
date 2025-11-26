import random
import zlib
from typing import List
from ..core.protocol import PatchBuilder
from .heuristics import emit_literals
from .greedy import greedy_match  # 新增：用于字面量回退匹配

GEAR_TABLE = [
    0x3328387794b98651, 0x433a019734184879, 0x9143e31981822323, 0x8334341374343913,
    0x1337383314884141, 0x0198414134848418, 0x4148418418418418, 0x8184184184184184,
]
_rng = random.Random(0x1337)
while len(GEAR_TABLE) < 256:
    GEAR_TABLE.append(_rng.getrandbits(64))

def _stable_hash(b: bytes) -> int:
    #  32bit 哈希
    return zlib.crc32(b) & 0xFFFFFFFF

def cdc_chunker(data: bytes, avg_size: int, min_size: int, max_size: int):
    #每次切出一个分片后必须重置滚动指纹，否则边界取决于前序分片
    mask = (1 << (avg_size.bit_length() - 1)) - 1
    fp = 0
    i = 0
    start = 0
    n = len(data)
    while i < n:
        fp = (fp << 1) + GEAR_TABLE[data[i]]
        if i - start + 1 < min_size:
            i += 1
            continue
        if (fp & mask) == 0 or (i - start + 1) >= max_size:
            end = i + 1
            yield start, end   # 半开区间 [start, end)
            start = end
            fp = 0
        i += 1
    if start < n:
        yield start, n

def build_cdc_index(old_bytes: bytes, avg_size: int = 4096, min_size: int = 1024, max_size: int = 16384):
    """为旧固件构建基于 CDC 的块索引（多位置）。"""
    idx = {}
    for start, end in cdc_chunker(old_bytes, avg_size, min_size, max_size):
        chunk = old_bytes[start:end]
        h = _stable_hash(chunk)
        idx.setdefault(h, []).append((start, end - start))
    return idx

def _emit_greedy_region(pb: PatchBuilder, old_bytes: bytes, region: bytes, block_idx):
    # 与非 CDC 分支一致的 greedy 回退
    if not region:
        return
    # 使用传入的 block_idx
    matches = greedy_match(old_bytes, region, block_idx, block=48, min_run=64, scan_step=8)
    cur = 0
    for (n_off_rel, o_off_m, ln) in matches:
        if n_off_rel > cur:
            emit_literals(pb, region[cur:n_off_rel])
        pb.op_copy(o_off_m, ln)
        cur = n_off_rel + ln
    if cur < len(region):
        emit_literals(pb, region[cur:])

def cdc_emit_region(old_bytes: bytes, region_bytes: bytes, pb: PatchBuilder, idx,
                    avg_size: int = 256, min_size: int = 64, max_size: int = 1024,
                    greedy_min: int = 32, extend_limit: int = 32, block_idx=None,
                    min_copy_len: int = 8):
    """对指定的新固件片段做 CDC 匹配，未命中则回退到 Greedy。"""
    if not region_bytes:
        return

    # 如果整个区域太小，直接交由 greedy 处理
    if len(region_bytes) < min_size:
        if block_idx:
            _emit_greedy_region(pb, old_bytes, region_bytes, block_idx)
        else:
            emit_literals(pb, region_bytes)
        return

    chunk_start_rel = 0
    for c_start, c_end in cdc_chunker(region_bytes, avg_size, min_size, max_size):
        if c_end <= chunk_start_rel:
            continue
        if c_start < chunk_start_rel:
            c_start = chunk_start_rel

        chunk = region_bytes[c_start:c_end]
        h = _stable_hash(chunk)
        best = None
        for off, ln in idx.get(h, ()):
            if ln != len(chunk) or old_bytes[off:off+ln] != chunk:
                continue

            left_max = min(extend_limit, c_start - chunk_start_rel, off)
            left_ext = 0
            while left_ext < left_max and region_bytes[c_start - 1 - left_ext] == old_bytes[off - 1 - left_ext]:
                left_ext += 1

            right_max = min(extend_limit, len(region_bytes) - c_end, len(old_bytes) - (off + ln))
            right_ext = 0
            while right_ext < right_max and region_bytes[c_end + right_ext] == old_bytes[off + ln + right_ext]:
                right_ext += 1

            total = ln + left_ext + right_ext
            if total >= min_copy_len and (best is None or total > best[0]):
                best = (total, off - left_ext, ln + left_ext + right_ext, left_ext, right_ext)

        if best:
            total, off_adj, ln_adj, left_ext, right_ext = best
            
            # 处理左侧的字面量空隙
            literal_chunk = region_bytes[chunk_start_rel : c_start - left_ext]
            if literal_chunk:
                if block_idx:
                    _emit_greedy_region(pb, old_bytes, literal_chunk, block_idx)
                else:
                    emit_literals(pb, literal_chunk)

            pb.op_copy(off_adj, ln_adj)
            chunk_start_rel = c_end + right_ext

    # 将所有剩余未处理的部分交给 greedy
    final_literals = region_bytes[chunk_start_rel:]
    if final_literals:
        if block_idx:
            _emit_greedy_region(pb, old_bytes, final_literals, block_idx)
        else:
            emit_literals(pb, final_literals)
