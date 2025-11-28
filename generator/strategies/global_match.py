# 在strategies目录下创建global_match.py

import heapq
from typing import List, Tuple

def build_suffix_array(data: bytes) -> List[int]:
    """构建后缀数组 - 使用倍增算法"""
    n = len(data)
    sa = list(range(n))
    rank = [data[i] for i in range(n)]
    k = 1
    
    while k < n:
        # 使用元组排序：第一关键字rank[i]，第二关键字rank[i+k]
        sa.sort(key=lambda i: (rank[i], rank[i + k] if i + k < n else -1))
        
        # 重新计算rank
        new_rank = [0] * n
        new_rank[sa[0]] = 0
        for i in range(1, n):
            prev = sa[i-1]
            curr = sa[i]
            same = (rank[prev] == rank[curr] and 
                   (rank[prev + k] if prev + k < n else -1) == 
                   (rank[curr + k] if curr + k < n else -1))
            new_rank[curr] = new_rank[prev] + (0 if same else 1)
        
        rank = new_rank
        k <<= 1
    
    return sa

def build_lcp_array(data: bytes, sa: List[int]) -> List[int]:
    """构建LCP数组（最长公共前缀）"""
    n = len(data)
    rank = [0] * n
    for i, pos in enumerate(sa):
        rank[pos] = i
    
    lcp = [0] * n
    h = 0
    for i in range(n):
        if rank[i] > 0:
            j = sa[rank[i] - 1]
            while i + h < n and j + h < n and data[i + h] == data[j + h]:
                h += 1
            lcp[rank[i]] = h
            if h > 0:
                h -= 1
    return lcp

def find_global_matches(old_bytes: bytes, new_bytes: bytes, min_length: int = 32) -> List[Tuple[int, int, int]]:
    """基于后缀数组的全局匹配发现"""
    # 构建旧固件的后缀数组
    print("构建后缀数组...")
    sa = build_suffix_array(old_bytes)
    lcp = build_lcp_array(old_bytes, sa)
    
    matches = []
    n_new = len(new_bytes)
    
    print("搜索全局匹配...")
    # 对新固件的每个位置，在后缀数组中二分查找最长匹配
    i = 0
    while i < n_new - min_length:
        best_match = None
        best_length = 0
        
        # 二分查找找到匹配区间
        left, right = 0, len(sa) - 1
        pattern = new_bytes[i:i+min_length]
        
        # 找到第一个匹配的位置
        first_match = -1
        low, high = 0, len(sa) - 1
        while low <= high:
            mid = (low + high) // 2
            pos = sa[mid]
            compare_len = min(min_length, len(old_bytes) - pos)
            if old_bytes[pos:pos+compare_len] < pattern:
                low = mid + 1
            else:
                first_match = mid
                high = mid - 1
        
        if first_match == -1:
            i += 1
            continue
            
        # 找到最后一个匹配的位置
        last_match = -1
        low, high = first_match, len(sa) - 1
        while low <= high:
            mid = (low + high) // 2
            pos = sa[mid]
            compare_len = min(min_length, len(old_bytes) - pos)
            if old_bytes[pos:pos+compare_len] > pattern:
                high = mid - 1
            else:
                last_match = mid
                low = mid + 1
        
        # 在匹配区间内寻找最长匹配
        for idx in range(first_match, last_match + 1):
            pos = sa[idx]
            # 扩展匹配
            length = min_length
            while (i + length < n_new and 
                   pos + length < len(old_bytes) and 
                   new_bytes[i + length] == old_bytes[pos + length]):
                length += 1
            
            if length > best_length:
                best_length = length
                best_match = (i, pos, length)
        
        if best_match and best_length >= min_length:
            matches.append(best_match)
            # 允许一定重叠，提高覆盖率
            i += max(1, best_length // 2)
        else:
            i += 1
    
    return matches

def global_greedy_hybrid(old_bytes: bytes, new_bytes: bytes, min_length: int = 32) -> List[Tuple[int, int, int]]:
    """全局+局部混合匹配策略"""
    # 先用全局匹配找到长匹配
    global_matches = find_global_matches(old_bytes, new_bytes, min_length)
    
    # 标记已覆盖区域
    covered = [False] * len(new_bytes)
    for n_off, o_off, length in global_matches:
        for k in range(n_off, min(n_off + length, len(new_bytes))):
            covered[k] = True
    
    # 再用局部贪心匹配填补空隙
    from .greedy import greedy_match, build_block_index
    block_idx = build_block_index(old_bytes, block=32, step=4)
    local_matches = greedy_match(old_bytes, new_bytes, block_idx, 
                                block=32, min_run=16, scan_step=4)
    
    # 合并结果，优先使用全局匹配
    all_matches = global_matches + [m for m in local_matches if not covered[m[0]]]
    all_matches.sort(key=lambda x: x[0])
    
    # 去除重叠
    final_matches = []
    last_end = 0
    for match in all_matches:
        n_off, o_off, length = match
        if n_off >= last_end:
            final_matches.append(match)
            last_end = n_off + length
        elif n_off + length > last_end:
            overlap = last_end - n_off
            if length - overlap >= 8:
                final_matches.append((last_end, o_off + overlap, length - overlap))
                last_end = n_off + length
    
    return final_matches