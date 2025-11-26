from typing import List, Tuple, Optional
from generator.core.utils import uleb128_len
from .global_match import find_global_matches
from .greedy import greedy_match, build_block_index


def _compute_coverage(matches: List[Tuple[int, int, int]], new_len: int) -> int:
    """
    计算给定匹配在 new_bytes 中覆盖了多少字节。
    匹配格式： (n_off, o_off, length)。
    """
    if not matches or new_len <= 0:
        return 0
    intervals = [(n_off, n_off + ln) for (n_off, _o, ln) in matches if ln > 0]
    if not intervals:
        return 0
    intervals.sort(key=lambda x: x[0])
    total = 0
    cur_s, cur_e = intervals[0]
    for s, e in intervals[1:]:
        if s > cur_e:
            total += max(0, min(cur_e, new_len) - cur_s)
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    total += max(0, min(cur_e, new_len) - cur_s)
    return total


def _choose_best_cover(
    matches: List[Tuple[int, int, int]],
    code_prefix: Optional[List[int]] = None,
    func_boundary_prefix: Optional[List[int]] = None,
) -> List[Tuple[int, int, int]]:
    """
    在所有匹配上做带权区间调度，以最大化覆盖的总长度。
    每个匹配的权重近似为相对于直接用 ADD 发射相同字节的净收益：
      benefit ~= length - COPY_metadata_overhead。
    """
    if not matches:
        return []

    intervals = []
    for n_off, o_off, ln in matches:
        if ln <= 0:
            continue
        end = n_off + ln
        # 估算 COPY 指令的元数据开销：1 字节操作码 + ULEB128(old_off) + ULEB128(length)
        meta_cost = 1 + uleb128_len(o_off) + uleb128_len(ln)
        weight = ln - meta_cost
        if code_prefix is not None:
            # 对 new_bytes 中落在代码区的字节给予一些额外加分。
            inside = code_prefix[end] - code_prefix[n_off]
            if inside > 0:
                # 每个代码字节都会增加一点得分；总加分不超过 ln，避免权重过大。
                bonus = min(inside, ln)
                weight += bonus
        if func_boundary_prefix is not None:
            # 对跨越过多函数起始边界的匹配施加惩罚。
            # 近似策略：统计严格落在区间 (n_off, end) 内的函数起始位置个数。
            s = n_off + 1
            e = end
            if s < e and e <= len(func_boundary_prefix) - 1:
                bcount = func_boundary_prefix[e] - func_boundary_prefix[s]
                if bcount > 0:
                    # 每多跨越一个边界，就略微降低该匹配的权重。
                    penalty = min(bcount, ln // 8 or 1)
                    weight -= penalty
        if weight <= 0:
            # 相比直接使用 ADD，这个匹配并不节省字节；
            # 赋予 0 权重，DP 在连锁选择时仍然可以用它，但不会单独选择它。
            weight = 0
        intervals.append((n_off, end, o_off, ln, weight))
    if not intervals:
        return []

    intervals.sort(key=lambda x: x[1])  # 按 new_bytes 中的结束位置排序
    starts = [it[0] for it in intervals]
    ends = [it[1] for it in intervals]

    from bisect import bisect_right
    n = len(intervals)
    p = [-1] * n
    for i in range(n):
        s_i = starts[i]
        j = bisect_right(ends, s_i - 1) - 1
        p[i] = j

    dp = [0] * n
    choose = [False] * n
    for i in range(n):
        _, _, _o, ln, w = intervals[i]
        take = w + (dp[p[i]] if p[i] >= 0 else 0)
        skip = dp[i - 1] if i > 0 else 0
        if take > skip:
            dp[i] = take
            choose[i] = True
        else:
            dp[i] = skip
            choose[i] = False

    chosen: List[Tuple[int, int, int]] = []
    i = n - 1
    while i >= 0:
        if choose[i]:
            n_off, _end, o_off, ln, _w = intervals[i]
            chosen.append((n_off, o_off, ln))
            i = p[i]
        else:
            i -= 1
    chosen.sort(key=lambda x: x[0])
    return chosen


def global_dp_hybrid(
    old_bytes: bytes,
    new_bytes: bytes,
    min_length: int = 32,
    code_mask: Optional[List[bool]] = None,
    func_boundary_prefix: Optional[List[int]] = None,
) -> List[Tuple[int, int, int]]:
    """
    全局 + 局部混合匹配器，使用 DP 选择最优的不重叠覆盖：
    - find_global_matches（基于后缀数组的全局匹配）
    - greedy_match（局部贪心匹配）
    - DP（带权区间调度）从候选中挑选覆盖长度最大的一组匹配。
    """
    new_len = len(new_bytes)

    # 1) 可选：基于代码区构建前缀和，用于加权
    code_prefix: Optional[List[int]] = None
    if code_mask is not None and len(code_mask) == new_len:
        code_prefix = [0] * (new_len + 1)
        acc = 0
        for i, flag in enumerate(code_mask):
            acc += 1 if flag else 0
            code_prefix[i + 1] = acc

    # 2) 全局匹配
    global_matches = find_global_matches(old_bytes, new_bytes, min_length)
    cov_g = _compute_coverage(global_matches, new_len)
    if new_len > 0:
        print(f"[GLOBAL-COVERAGE] global_matches={len(global_matches)} "
              f"covered={cov_g} ({cov_g/new_len*100:.2f}%)")

    # 3) 局部贪心匹配
    block_idx = build_block_index(old_bytes, block=32, step=4)
    local_matches = greedy_match(old_bytes, new_bytes, block_idx,
                                 block=32, min_run=16, scan_step=4)

    # 4) 在所有候选上做 DP 选择
    all_matches = global_matches + local_matches
    final_matches = _choose_best_cover(
        all_matches,
        code_prefix=code_prefix,
        func_boundary_prefix=func_boundary_prefix,
    )
    cov_f = _compute_coverage(final_matches, new_len)
    if new_len > 0:
        print(f"[GLOBAL-COVERAGE] final_matches={len(final_matches)} "
              f"covered={cov_f} ({cov_f/new_len*100:.2f}%)")

    return final_matches
