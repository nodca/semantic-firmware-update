#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# analyze_patch.py - 分析补丁文件的实际构成

import sys
import zlib
import struct
from collections import defaultdict

# 操作码定义
OP_END = 0x00
OP_COPY = 0x01
OP_ADD = 0x02
OP_DIFF = 0x03  # 差分编码指令
OP_PATCH_FROM_OLD = 0x04
OP_FILL = 0x06
OP_PATCH_COMPACT = 0x07
OP_PATCH_DIFF = 0x08  # PATCH 变种：变更数据使用差分编码

MAGIC = b'DPT1'
HEADER_FMT = '<4sHII'
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def read_uleb128(buf: bytes, idx: int):
    """读取 ULEB128 编码的整数"""
    val = 0
    shift = 0
    start = idx
    while idx < len(buf):
        b = buf[idx]
        val |= (b & 0x7F) << shift
        shift += 7
        idx += 1
        if not (b & 0x80):
            break
    return val, idx, idx - start


def analyze_patch(patch_path: str):
    """分析补丁文件"""
    with open(patch_path, 'rb') as f:
        compressed = f.read()

    print(f"压缩后大小: {len(compressed)} bytes")

    # 解压
    try:
        raw = zlib.decompress(compressed)
        print(f"解压后大小: {len(raw)} bytes")
        print(f"压缩率: {(1 - len(compressed)/len(raw))*100:.2f}%")
    except:
        raw = compressed
        print("未压缩或解压失败")

    # 解析头部
    if len(raw) < HEADER_SIZE:
        print("文件太小")
        return

    magic, flags, target_size, reserved = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
    print(f"\n头部信息:")
    print(f"  Magic: {magic}")
    print(f"  Target size: {target_size} bytes")
    print(f"  Header size: {HEADER_SIZE} bytes")

    # 统计各类指令
    stats = {
        'COPY': {'count': 0, 'meta_bytes': 0, 'data_bytes': 0, 'lengths': []},
        'ADD': {'count': 0, 'meta_bytes': 0, 'data_bytes': 0, 'lengths': []},
        'DIFF': {'count': 0, 'meta_bytes': 0, 'data_bytes': 0, 'lengths': [], 'zero_ratios': []},
        'PATCH': {'count': 0, 'meta_bytes': 0, 'data_bytes': 0, 'lengths': [], 'changes': []},
        'PATCH_COMPACT': {'count': 0, 'meta_bytes': 0, 'data_bytes': 0, 'lengths': [], 'changes': []},
        'PATCH_DIFF': {'count': 0, 'meta_bytes': 0, 'data_bytes': 0, 'lengths': [], 'changes': [], 'zero_ratios': []},
        'FILL': {'count': 0, 'meta_bytes': 0, 'data_bytes': 0, 'lengths': []},
    }

    i = HEADER_SIZE
    total_output = 0

    while i < len(raw):
        op = raw[i]
        op_start = i
        i += 1

        if op == OP_END:
            break

        elif op == OP_COPY:
            old_off, i, _ = read_uleb128(raw, i)
            length, i, _ = read_uleb128(raw, i)
            meta_size = i - op_start
            stats['COPY']['count'] += 1
            stats['COPY']['meta_bytes'] += meta_size
            stats['COPY']['lengths'].append(length)
            total_output += length

        elif op == OP_ADD:
            lit_len, i, _ = read_uleb128(raw, i)
            meta_size = i - op_start
            i += lit_len  # 跳过字面量数据
            stats['ADD']['count'] += 1
            stats['ADD']['meta_bytes'] += meta_size
            stats['ADD']['data_bytes'] += lit_len
            stats['ADD']['lengths'].append(lit_len)
            total_output += lit_len

        elif op == OP_DIFF:
            old_off, i, _ = read_uleb128(raw, i)
            length, i, _ = read_uleb128(raw, i)
            meta_size = i - op_start
            # 读取差分数据并统计零字节比例
            diff_data = raw[i:i + length]
            i += length
            zero_count = diff_data.count(0)
            zero_ratio = zero_count / length if length > 0 else 0
            stats['DIFF']['count'] += 1
            stats['DIFF']['meta_bytes'] += meta_size
            stats['DIFF']['data_bytes'] += length
            stats['DIFF']['lengths'].append(length)
            stats['DIFF']['zero_ratios'].append(zero_ratio)
            total_output += length

        elif op == OP_PATCH_FROM_OLD:
            old_off, i, _ = read_uleb128(raw, i)
            length, i, _ = read_uleb128(raw, i)
            nchanges, i, _ = read_uleb128(raw, i)
            meta_start = i
            data_bytes = 0
            for _ in range(nchanges):
                delta, i, _ = read_uleb128(raw, i)
                clen, i, _ = read_uleb128(raw, i)
                i += clen
                data_bytes += clen
            meta_size = (i - op_start) - data_bytes
            stats['PATCH']['count'] += 1
            stats['PATCH']['meta_bytes'] += meta_size
            stats['PATCH']['data_bytes'] += data_bytes
            stats['PATCH']['lengths'].append(length)
            stats['PATCH']['changes'].append(nchanges)
            total_output += length

        elif op == OP_PATCH_COMPACT:
            old_off, i, _ = read_uleb128(raw, i)
            length, i, _ = read_uleb128(raw, i)
            nchanges, i, _ = read_uleb128(raw, i)
            if nchanges > 0:
                change_len, i, _ = read_uleb128(raw, i)
                for _ in range(nchanges):
                    delta, i, _ = read_uleb128(raw, i)
                data_bytes = nchanges * change_len
                i += data_bytes
            else:
                data_bytes = 0
            meta_size = (i - op_start) - data_bytes
            stats['PATCH_COMPACT']['count'] += 1
            stats['PATCH_COMPACT']['meta_bytes'] += meta_size
            stats['PATCH_COMPACT']['data_bytes'] += data_bytes
            stats['PATCH_COMPACT']['lengths'].append(length)
            stats['PATCH_COMPACT']['changes'].append(nchanges)
            total_output += length

        elif op == OP_FILL:
            byte_val, i, _ = read_uleb128(raw, i)
            length, i, _ = read_uleb128(raw, i)
            meta_size = i - op_start
            stats['FILL']['count'] += 1
            stats['FILL']['meta_bytes'] += meta_size
            stats['FILL']['lengths'].append(length)
            total_output += length

        elif op == OP_PATCH_DIFF:
            # 与 PATCH_FROM_OLD 格式相同，但变更数据是差分编码
            old_off, i, _ = read_uleb128(raw, i)
            length, i, _ = read_uleb128(raw, i)
            nchanges, i, _ = read_uleb128(raw, i)
            meta_start = i
            data_bytes = 0
            diff_data_all = bytearray()
            for _ in range(nchanges):
                delta, i, _ = read_uleb128(raw, i)
                clen, i, _ = read_uleb128(raw, i)
                diff_data_all.extend(raw[i:i + clen])
                i += clen
                data_bytes += clen
            meta_size = (i - op_start) - data_bytes
            # 计算零字节比例
            zero_count = diff_data_all.count(0)
            zero_ratio = zero_count / data_bytes if data_bytes > 0 else 0
            stats['PATCH_DIFF']['count'] += 1
            stats['PATCH_DIFF']['meta_bytes'] += meta_size
            stats['PATCH_DIFF']['data_bytes'] += data_bytes
            stats['PATCH_DIFF']['lengths'].append(length)
            stats['PATCH_DIFF']['changes'].append(nchanges)
            stats['PATCH_DIFF']['zero_ratios'].append(zero_ratio)
            total_output += length

        else:
            print(f"未知操作码: 0x{op:02X} at offset {op_start}")
            break

    # 打印统计
    print(f"\n指令统计 (解压后):")
    print(f"{'指令':<15} {'数量':>8} {'元数据':>12} {'数据':>12} {'总计':>12} {'占比':>8}")
    print("-" * 70)

    total_meta = HEADER_SIZE + 1  # header + END
    total_data = 0

    for name in ['COPY', 'ADD', 'DIFF', 'PATCH', 'PATCH_COMPACT', 'PATCH_DIFF', 'FILL']:
        s = stats[name]
        total = s['meta_bytes'] + s['data_bytes']
        total_meta += s['meta_bytes']
        total_data += s['data_bytes']
        if s['count'] > 0:
            pct = total / len(raw) * 100
            print(f"{name:<15} {s['count']:>8} {s['meta_bytes']:>12} {s['data_bytes']:>12} {total:>12} {pct:>7.2f}%")

    print("-" * 70)
    print(f"{'总计':<15} {'':<8} {total_meta:>12} {total_data:>12} {total_meta+total_data:>12} {(total_meta+total_data)/len(raw)*100:>7.2f}%")
    print(f"{'头部+END':<15} {'':<8} {HEADER_SIZE+1:>12}")

    print(f"\n输出统计:")
    print(f"  目标大小: {target_size} bytes")
    print(f"  实际输出: {total_output} bytes")

    # 详细分析
    print(f"\n详细分析:")

    if stats['COPY']['lengths']:
        lengths = stats['COPY']['lengths']
        print(f"  COPY: 平均长度={sum(lengths)/len(lengths):.1f}, "
              f"最大={max(lengths)}, 最小={min(lengths)}")

    if stats['ADD']['lengths']:
        lengths = stats['ADD']['lengths']
        print(f"  ADD: 平均长度={sum(lengths)/len(lengths):.1f}, "
              f"最大={max(lengths)}, 最小={min(lengths)}")
        # ADD 数据的压缩潜力
        print(f"  ADD 数据总量: {stats['ADD']['data_bytes']} bytes")

    if stats['DIFF']['lengths']:
        lengths = stats['DIFF']['lengths']
        zero_ratios = stats['DIFF']['zero_ratios']
        avg_zero = sum(zero_ratios) / len(zero_ratios) if zero_ratios else 0
        print(f"  DIFF: 平均长度={sum(lengths)/len(lengths):.1f}, "
              f"最大={max(lengths)}, 最小={min(lengths)}")
        print(f"  DIFF 数据总量: {stats['DIFF']['data_bytes']} bytes, "
              f"平均零字节比例: {avg_zero*100:.1f}%")

    if stats['PATCH']['lengths']:
        lengths = stats['PATCH']['lengths']
        changes = stats['PATCH']['changes']
        print(f"  PATCH: 平均区域长度={sum(lengths)/len(lengths):.1f}, "
              f"平均变更点={sum(changes)/len(changes):.1f}")
        # 计算变更密度
        total_patch_len = sum(lengths)
        total_change_data = stats['PATCH']['data_bytes']
        if total_patch_len > 0:
            density = total_change_data / total_patch_len * 100
            print(f"  PATCH 变更密度: {density:.2f}% ({total_change_data}/{total_patch_len})")

    if stats['PATCH_COMPACT']['lengths']:
        lengths = stats['PATCH_COMPACT']['lengths']
        changes = stats['PATCH_COMPACT']['changes']
        print(f"  PATCH_COMPACT: 平均区域长度={sum(lengths)/len(lengths):.1f}, "
              f"平均变更点={sum(changes)/len(changes):.1f}")

    # 压缩效率分析
    print(f"\n压缩效率分析:")
    print(f"  解压后补丁大小: {len(raw)} bytes")
    print(f"  压缩后补丁大小: {len(compressed)} bytes")
    print(f"  元数据占比: {total_meta/len(raw)*100:.2f}%")
    print(f"  数据占比: {total_data/len(raw)*100:.2f}%")

    # 与 BSDIFF 对比的理论分析
    print(f"\n理论分析:")
    # 如果全部用 ADD，需要多大
    add_only_size = target_size + target_size // 127 + 10  # 粗略估计
    print(f"  纯 ADD 模式估计: ~{add_only_size} bytes (未压缩)")
    print(f"  当前方案节省: {(1 - len(raw)/add_only_size)*100:.1f}% (未压缩)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <patch_file>")
        sys.exit(1)

    analyze_patch(sys.argv[1])
