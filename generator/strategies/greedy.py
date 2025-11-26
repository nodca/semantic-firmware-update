from collections import defaultdict
from typing import Dict, List, Tuple
import zlib

def build_block_index(buf: bytes, block: int = 64, step: int = 16) -> Dict[bytes, List[int]]:
    """构建块索引 """
    idx: Dict[bytes, List[int]] = defaultdict(list)
    n = len(buf)
    if n < block:
        return idx
    for off in range(0, n - block + 1, step):
        idx[buf[off:off+block]].append(off)
    return idx

def find_long_matches_optimized(old_bytes, new_bytes, min_length=32, window_size=16, step=4, max_distance=65536):
    """
    优化版长匹配发现 - 平衡性能与压缩率
    参数:
        min_length: 最小匹配长度，提高此值可减少碎片但可能漏掉有用匹配
        window_size: 哈希窗口大小，影响索引精度和内存使用
        step: 索引步长，影响索引大小和匹配密度  
        max_distance: 最大匹配距离，限制搜索范围提高性能
    """
    idx = defaultdict(list)
    old_len = len(old_bytes)
    
    # 构建高效的滚动哈希索引
    for off in range(0, old_len - window_size + 1, step):
        window = old_bytes[off:off+window_size]
        # 使用强哈希减少冲突
        hash_val = zlib.crc32(window)
        idx[hash_val].append(off)
    
    matches = []
    i = 0
    n_new = len(new_bytes)
    covered = [False] * n_new
    
    while i <= n_new - min_length:
        if covered[i]:
            i += 1
            continue
            
        window = new_bytes[i:i+window_size]
        hash_val = zlib.crc32(window)
        
        best_match = None
        best_length = 0
        
        if hash_val in idx:
            for cand in idx[hash_val]:
                # 注意：这里的 cand 是旧固件中的偏移，i 是“当前 new_bytes 切片”中的偏移。
                # 两者不在同一坐标系中，不能用 abs(cand - i) 当作“距离”过滤，
                # 否则在对局部片段调用 greedy_match 时会错误地丢弃大量有效匹配。
                # 快速验证前32字节
                verify_len = min(32, n_new - i, old_len - cand)
                if old_bytes[cand:cand+verify_len] != new_bytes[i:i+verify_len]:
                    continue
                
                # 向后扩展匹配
                a, b = i + verify_len, cand + verify_len
                while (a < n_new and b < old_len and 
                       new_bytes[a] == old_bytes[b] and 
                       a - i < min_length * 8):  # 限制最大扩展长度
                    a += 1
                    b += 1
                
                length = a - i
                if length >= min_length and length > best_length:
                    best_match = (i, cand, length)
                    best_length = length
                    # 如果找到很长的匹配，提前停止搜索候选
                    if length >= min_length * 4:
                        break
        
        if best_match:
            n_off, o_off, length = best_match
            matches.append(best_match)
            # 标记覆盖区域
            for k in range(n_off, n_off + length):
                if k < n_new:
                    covered[k] = True
            i += length  # 跳过整个匹配区域
        else:
            i += 1
    
    return matches

def greedy_match(old_bytes: bytes, new_bytes: bytes, block_idx, block=48, min_run=32, scan_step=8) -> List[Tuple[int, int, int]]:
    """优化的贪心匹配算法"""
    # 先用优化的长匹配发现
    long_matches = find_long_matches_optimized(
        old_bytes, new_bytes, 
        min_length=8,        # 降低最小长度捕获更多匹配  24
        window_size=8,       # 较小窗口提高匹配密度  12
        step=1,               # 较小步长提高匹配机会  2
        max_distance=32768    # 限制搜索范围
    )
    
    # 标记覆盖区域
    n_new = len(new_bytes)
    covered = [False] * n_new
    for n_off, o_off, ln in long_matches:
        for k in range(n_off, min(n_off+ln, n_new)):
            covered[k] = True
    
    # 再用原有贪心算法补全
    matches: List[Tuple[int, int, int]] = []
    i = 0
    while i <= n_new - block:
        if covered[i]:
            i += 1
            continue
            
        key = new_bytes[i:i+block]
        cands = block_idx.get(key, [])
        
        best_length = 0
        best_cand = 0
        
        for cand in cands:
            # cand 是旧固件中的偏移，i 是当前 new_bytes 切片中的偏移；
            # 不能用 abs(cand - i) 作为距离限制，否则在对局部区域调用时会误删远处的有效匹配。
            # 扩展匹配
            a, b = i, cand
            max_check = min(n_new - i, len(old_bytes) - cand, 256)  # 限制检查长度
            while (a - i < max_check and 
                   b < len(old_bytes) and 
                   new_bytes[a] == old_bytes[b] and 
                   not covered[a]):
                a += 1
                b += 1
            
            length = a - i
            if length >= min_run and length > best_length:
                best_length = length
                best_cand = cand
                if length >= min_run * 2:  # 找到足够长的匹配就停止
                    break
        
        if best_length >= min_run:
            matches.append((i, best_cand, best_length))
            for k in range(i, i + best_length):
                if k < n_new:
                    covered[k] = True
            i += best_length
        else:
            i += scan_step
    
    # 合并结果并去重
    all_matches = long_matches + matches
    all_matches.sort(key=lambda x: x[0])
    
    # 去除重叠的匹配
    final_matches = []
    last_end = 0
    for match in all_matches:
        n_off, o_off, length = match
        if n_off >= last_end:
            final_matches.append(match)
            last_end = n_off + length
        elif n_off + length > last_end:
            # 部分重叠，取非重叠部分
            overlap = last_end - n_off
            if length - overlap >= 8:  # 只保留足够长的非重叠部分
                final_matches.append((last_end, o_off + overlap, length - overlap))
                last_end = n_off + length
    
    return final_matches

def merge_adjacent_matches(matches: List[Tuple[int, int, int]], max_gap=8) -> List[Tuple[int, int, int]]:
    """合并相邻的匹配，减少碎片化"""
    if not matches:
        return []
    
    matches.sort(key=lambda x: x[0])
    merged = []
    current = list(matches[0])
    
    for i in range(1, len(matches)):
        n_off, o_off, length = matches[i]
        
        # 检查是否可以合并
        if (n_off <= current[0] + current[2] + max_gap and
            o_off <= current[1] + current[2] + max_gap and
            n_off + length - (current[0] + current[2]) == o_off + length - (current[1] + current[2])):
            # 扩展当前匹配
            current[2] = max(current[2], n_off + length - current[0])
        else:
            merged.append(tuple(current))
            current = [n_off, o_off, length]
    
    merged.append(tuple(current))
    return merged

