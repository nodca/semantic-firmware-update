#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_new_repeats.py - 评估“从新固件复制（COPY-from-new）”指令的潜在收益。

针对一对旧/新固件，本脚本会查找这样一些重复模式：
  * 在“新固件”中至少出现两次，并且
  * 在“旧固件”中完全不存在（也即不能通过普通 COPY 复用）。

这些字节可以看作是假想的 COPY_NEW 指令的候选目标：
它不是从旧固件复制，而是从新镜像中已经写入的字节复制。

脚本会按不同块大小统计：新固件中有多少字节落在这类
“仅在新固件中重复”的模式里（按不重叠计数），
从而给出 COPY_NEW 在该块大小下理论上最多能覆盖的数据上界。
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from typing import Iterable, List


def _parse_block_sizes(s: str) -> List[int]:
    return [int(x) for x in s.split(",") if x.strip()]


def analyze_repeats(
    old_bytes: bytes,
    new_bytes: bytes,
    *,
    block_sizes: Iterable[int],
    step: int = 4,
) -> None:
    new_len = len(new_bytes)
    old_len = len(old_bytes)
    print(f"[ANALYZE] old_len={old_len} bytes, new_len={new_len} bytes")

    for B in block_sizes:
        if B <= 0:
            continue
        if new_len < B or old_len < B:
            print(f"[ANALYZE] block={B}: skipped (firmware too small)")
            continue

        print(f"\n[ANALYZE] block_size={B}, step={step}")

        # 在旧固件中构建所有 B 字节模式的集合（步长为 step）。
        old_patterns = set()
        for i in range(0, old_len - B + 1, step):
            old_patterns.add(old_bytes[i : i + B])
        print(f"  old_patterns: {len(old_patterns)} unique B-byte slices")

        # 将仅在新固件中出现的模式映射到它们的位置列表。
        pattern_pos = defaultdict(list)  # 模式 -> [出现位置列表]
        for i in range(0, new_len - B + 1, step):
            chunk = new_bytes[i : i + B]
            if chunk in old_patterns:
                continue
            pattern_pos[chunk].append(i)

        # 只保留在新固件中至少出现两次的模式。
        repeated = {p: pos for p, pos in pattern_pos.items() if len(pos) >= 2}
        if not repeated:
            print("  No new-only repeated patterns found.")
            continue

        # 统计这些模式在新固件中的不重叠覆盖字节数。
        covered = [False] * new_len
        total_bytes = 0
        groups = 0
        extra_occurrences = 0

        for positions in repeated.values():
            positions.sort()
            groups += 1
            # 第一次出现必须作为字面量，后续出现才作为 COPY_NEW 候选。
            for pos in positions[1:]:
                extra_occurrences += 1
                end = min(pos + B, new_len)
                for k in range(pos, end):
                    if not covered[k]:
                        covered[k] = True
                        total_bytes += 1

        pct = total_bytes * 100.0 / max(1, new_len)
        print(f"  repeated_groups (new-only)   : {groups}")
        print(f"  extra_occurrences (>=2nd)    : {extra_occurrences}")
        print(f"  bytes_covered_nonoverlap     : {total_bytes} "
              f"({pct:.2f}% of new)")
        print("  (Upper bound on data COPY_NEW could potentially cover "
              "at this block size.)")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        description="Analyze repeated patterns unique to the new firmware "
                    "to estimate potential COPY-from-new benefit.",
    )
    ap.add_argument("--old", required=True, help="Old firmware .bin")
    ap.add_argument("--new", required=True, help="New firmware .bin")
    ap.add_argument(
        "--block-sizes",
        default="16,32,64",
        help="Comma-separated list of block sizes (bytes) to analyze, "
             "e.g. '16,32,64' (default).",
    )
    ap.add_argument(
        "--step",
        type=int,
        default=4,
        help="Stride when scanning firmware (default: 4 bytes).",
    )
    args = ap.parse_args(argv)

    with open(args.old, "rb") as f:
        old_bytes = f.read()
    with open(args.new, "rb") as f:
        new_bytes = f.read()

    block_sizes = _parse_block_sizes(args.block_sizes)
    analyze_repeats(old_bytes, new_bytes, block_sizes=block_sizes, step=args.step)


if __name__ == "__main__":
    main()
