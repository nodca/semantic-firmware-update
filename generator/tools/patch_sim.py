#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_sim.py - 用于离线模拟补丁应用开销的工具。

该工具会：
  * 读取旧固件镜像和补丁文件；
  * 在需要时对补丁进行解压；
  * 解析补丁流以估算：
      - PATCH / PATCH_COMPACT 区块的最大长度；
      - 在流式 MCU 实现下的峰值 RAM 近似值；
  * 调用一次 apply_patch_in_memory，测量在 PC 上的实际耗时。

使用示例：

  python -m generator.tools.patch_sim \\
      --old QLS01CDHS224.bin \\
      --patch QLS01CDHSpatch.bin \\
      --payload 502 \\
      --scale 50

参数 --scale 大致表示“MCU 比当前 PC 慢多少倍”，
估计的 MCU 应用时间 ~= scale * PC_apply_time。
"""

from __future__ import annotations

import argparse
import os
import struct
import time
from typing import Optional

import zlib

from generator.tools.apply_patch import (
    MAGIC,
    HEADER_FMT,
    HEADER_SIZE,
    OP_END,
    OP_COPY,
    OP_ADD,
    OP_PATCH_FROM_OLD,
    OP_ADD_LZ4,
    OP_FILL,
    OP_PATCH_COMPACT,
    Stream,
    apply_patch_in_memory,
)


def analyze_patch_stream(patch_data: bytes) -> dict:
    """
    解析已解压的补丁字节流，收集一些用于资源建模的基础统计信息。
    """
    s = Stream(patch_data)

    hdr = s.read_exact(HEADER_SIZE)
    magic, flags, target_size, _reserved = struct.unpack(HEADER_FMT, hdr)
    if magic != MAGIC:
        raise ValueError("bad patch magic in stream analysis")

    max_add_len = 0
    max_copy_len = 0
    max_patch_len = 0
    max_pc_len = 0
    max_fill_len = 0

    while True:
        op = s.read_u8()
        if op == OP_END:
            break

        if op == OP_COPY:
            old_off = s.read_uleb128()
            length = s.read_uleb128()
            max_copy_len = max(max_copy_len, length)

        elif op == OP_ADD:
            lit_len = s.read_uleb128()
            max_add_len = max(max_add_len, lit_len)
            _ = s.read_exact(lit_len)

        elif op == OP_FILL:
            _byte_val = s.read_uleb128()
            length = s.read_uleb128()
            max_fill_len = max(max_fill_len, length)

        elif op == OP_PATCH_FROM_OLD:
            old_off = s.read_uleb128()
            length = s.read_uleb128()
            nchanges = s.read_uleb128()
            max_patch_len = max(max_patch_len, length)
            last_off = 0
            for _ in range(nchanges):
                delta = s.read_uleb128()
                off_in_block = last_off + delta
                clen = s.read_uleb128()
                _ = s.read_exact(clen)
                last_off = off_in_block

        elif op == OP_PATCH_COMPACT:
            old_off = s.read_uleb128()
            length = s.read_uleb128()
            nchanges = s.read_uleb128()
            max_pc_len = max(max_pc_len, length)
            if nchanges > 0:
                change_len = s.read_uleb128()
                # deltas：每个改动块在块内的偏移
                for _ in range(nchanges):
                    _ = s.read_uleb128()
                # all data：紧跟着存放所有改动块的数据
                _ = s.read_exact(nchanges * change_len)

        elif op == OP_ADD_LZ4:
            # 目前设备端不会使用该指令，在这里仅跳过其数据。
            ulen = s.read_uleb128()
            clen = s.read_uleb128()
            _ = s.read_exact(clen)

        else:
            raise ValueError(f"unknown opcode 0x{op:02X} in patch stream")

    return {
        "target_size": target_size,
        "max_add_len": max_add_len,
        "max_copy_len": max_copy_len,
        "max_patch_len": max_patch_len,
        "max_pc_len": max_pc_len,
        "max_fill_len": max_fill_len,
    }


def simulate(
    old_path: str,
    patch_path: str,
    *,
    payload: int = 502,
    new_path: Optional[str] = None,
    scale: float = 1.0,
) -> None:
    # 读取旧固件镜像
    with open(old_path, "rb") as f:
        old_bytes = f.read()

    # 读取补丁文件（可能已压缩，也可能未压缩）
    with open(patch_path, "rb") as f:
        patch_file = f.read()

    compressed = False
    try:
        patch_data = zlib.decompress(patch_file)
        compressed = True
    except zlib.error:
        patch_data = patch_file

    print(f"[SIM] Patch file: {patch_path}")
    print(f"      compressed_size={len(patch_file)} bytes, "
          f"decompressed_size={len(patch_data)} bytes, "
          f"compressed={compressed}")

    # 分析补丁流，统计各类块的大小
    stats = analyze_patch_stream(patch_data)
    max_patch_block = max(stats["max_patch_len"], stats["max_pc_len"])

    print("[SIM] Patch stream stats:")
    print(f"      target_size (new firmware) = {stats['target_size']} bytes")
    print(f"      max COPY length            = {stats['max_copy_len']} bytes")
    print(f"      max ADD length             = {stats['max_add_len']} bytes")
    print(f"      max FILL length            = {stats['max_fill_len']} bytes")
    print(f"      max PATCH_FROM_OLD length  = {stats['max_patch_len']} bytes")
    print(f"      max PATCH_COMPACT length   = {stats['max_pc_len']} bytes")

    # 对 MCU 所需峰值 RAM 做一个非常粗略的估算：
    #   - 一帧接收缓冲区（frame buffer）
    #   - 如果补丁被压缩，还需要 zlib 窗口缓冲
    #   - 最大补丁块（PATCH / PATCH_COMPACT）的缓存
    zlib_window_est = 32 * 1024 if compressed else 0
    frame_buf = payload
    patch_block_buf = max_patch_block
    peak_ram_est = zlib_window_est + frame_buf + patch_block_buf

    print("[SIM] Rough MCU RAM estimate (patch-related):")
    print(f"      frame_buffer      ≈ {frame_buf} bytes "
          f"(payload={payload})")
    print(f"      zlib_window_est   ≈ {zlib_window_est} bytes "
          f"({'enabled' if compressed else 'not used'})")
    print(f"      patch_block_buf   ≈ {patch_block_buf} bytes "
          f"(max PATCH/PATCH_COMPACT length)")
    print(f"      peak_ram_est      ≈ {peak_ram_est} bytes "
          f"(frame + zlib + patch_block)")

    # 在当前机器上测量一次补丁应用的耗时
    t0 = time.perf_counter()
    new_bytes = apply_patch_in_memory(old_bytes, patch_data)
    t1 = time.perf_counter()
    pc_apply_time = t1 - t0
    print(f"[SIM] apply_patch_in_memory time on this PC: "
          f"{pc_apply_time:.3f} s")

    if scale and scale != 1.0:
        est_mcu_time = pc_apply_time * scale
        print(f"[SIM] Estimated MCU apply time with scale={scale:g}: "
              f"{est_mcu_time:.3f} s (rough)")

    # （可选）与期望的新固件进行一次正确性校验
    if new_path:
        with open(new_path, "rb") as f:
            expect = f.read()
        ok = (new_bytes == expect)
        print(f"[SIM] Verification against {new_path}: "
              f"{'OK' if ok else 'MISMATCH'}")
        if not ok:
            print(f"      reconstructed={len(new_bytes)} "
                  f"expected={len(expect)}")


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Simulate patch application to estimate RAM usage and time.",
    )
    ap.add_argument("--old", required=True, help="Old firmware .bin")
    ap.add_argument("--patch", required=True, help="Patch file (compressed or raw)")
    ap.add_argument("--new", help="Optional new firmware .bin for verification")
    ap.add_argument(
        "--payload",
        type=int,
        default=502,
        help="Frame payload size for reception (default: 502)",
    )
    ap.add_argument(
        "--scale",
        type=float,
        default=1.0,
        help="Rough MCU/PC speed factor; MCU_time ≈ scale * PC_time (default: 1.0)",
    )
    return ap


def main(argv: Optional[list] = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    simulate(
        old_path=args.old,
        patch_path=args.patch,
        payload=args.payload,
        new_path=args.new,
        scale=args.scale,
    )


if __name__ == "__main__":
    main()
