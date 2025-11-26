#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# apply_patch.py - 低RAM流式补丁应用器（兼容 generate.py 调用）

import argparse
import os
import struct
import sys
import zlib
import tempfile
import math

MAGIC = b'DPT1'
HEADER_FMT = '<4sHII'
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# 操作码定义
OP_END  = 0x00
OP_COPY = 0x01          # old_off,varint ; length,varint（旧偏移、长度）
OP_ADD  = 0x02          # literal_len,varint ; literal bytes（字面量长度及其数据）
OP_PATCH_FROM_OLD = 0x04# old_off,varint ; length,varint ; nchanges,varint ; [delta_off,varint ; clen,varint ; data]...（从旧固件复制并在局部打补丁）
OP_ADD_LZ4 = 0x05       # ulen,varint ; clen,varint ; cdata (不支持)
OP_FILL = 0x06          # byte,varint ; length,varint（重复某个字节）
OP_PATCH_COMPACT = 0x07 # old_off,varint ; length,varint ; nchanges,varint ; change_len,varint ; [delta]... ; [data]...（压缩表示的补丁）

class Stream:
    """流式读取器，最小内存占用"""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.len = len(data)
    
    def read_exact(self, n: int) -> bytes:
        if self.pos + n > self.len:
            raise EOFError("unexpected end of stream")
        out = self.data[self.pos:self.pos+n]
        self.pos += n
        return out
    
    def read_u8(self) -> int:
        if self.pos >= self.len:
            raise EOFError("unexpected end of stream (u8)")
        b = self.data[self.pos]
        self.pos += 1
        return b
    
    def read_uleb128(self) -> int:
        """读取ULEB128，最小内存占用"""
        shift = 0
        result = 0
        while True:
            if self.pos >= self.len:
                raise EOFError("unexpected end of stream (uleb128)")
            b = self.data[self.pos]
            self.pos += 1
            result |= ((b & 0x7F) << shift)
            if (b & 0x80) == 0:
                break
            shift += 7
            if shift > 35:
                raise ValueError("uleb128 too large or malformed")
        return result

def apply_patch_in_memory(old_bytes: bytes, patch_data: bytes):
    """内存中应用补丁"""
    s = Stream(patch_data)
    
    # 1) 解析补丁头部
    hdr = s.read_exact(HEADER_SIZE)
    magic, flags, target_size, _reserved = struct.unpack(HEADER_FMT, hdr)
    if magic != MAGIC:
        raise ValueError("bad patch magic")
    out = bytearray(target_size)
    pos = 0
    old_len = len(old_bytes)

    # 2) 指令循环
    while True:
        op = s.read_u8()
        if op == OP_END:
            break

        elif op == OP_COPY:
            old_off = s.read_uleb128()
            length  = s.read_uleb128()
            if old_off + length > old_len or pos + length > target_size:
                raise ValueError("COPY out of range")
            out[pos:pos+length] = old_bytes[old_off:old_off+length]
            pos += length

        elif op == OP_ADD:
            lit_len = s.read_uleb128()
            if pos + lit_len > target_size:
                raise ValueError("ADD out of range")
            lit = s.read_exact(lit_len)
            out[pos:pos+lit_len] = lit
            pos += lit_len

        elif op == OP_FILL:
            byte_val = s.read_uleb128() & 0xFF
            length   = s.read_uleb128()
            if pos + length > target_size:
                raise ValueError("FILL out of range")
            out[pos:pos+length] = bytes([byte_val]) * length
            pos += length

        elif op == OP_PATCH_FROM_OLD:
            old_off = s.read_uleb128()
            length  = s.read_uleb128()
            nchanges = s.read_uleb128()
            if old_off + length > old_len or pos + length > target_size:
                raise ValueError("PATCH_FROM_OLD out of range")
            block = bytearray(old_bytes[old_off:old_off+length])
            last_off = 0
            for _ in range(nchanges):
                delta = s.read_uleb128()
                off_in_block = last_off + delta
                clen = s.read_uleb128()
                if off_in_block + clen > length:
                    raise ValueError("PATCH chunk out of range")
                data = s.read_exact(clen)
                block[off_in_block:off_in_block+clen] = data
                last_off = off_in_block
            out[pos:pos+length] = block
            pos += length

        elif op == OP_PATCH_COMPACT:
            old_off = s.read_uleb128()
            length = s.read_uleb128()
            nchanges = s.read_uleb128()
            if old_off + length > old_len or pos + length > target_size:
                raise ValueError("PATCH_COMPACT out of range")

            block = bytearray(old_bytes[old_off:old_off+length])
            if nchanges > 0:
                change_len = s.read_uleb128()
                deltas = [s.read_uleb128() for _ in range(nchanges)]
                all_data = s.read_exact(nchanges * change_len)
                
                last_off = 0
                data_ptr = 0
                for delta in deltas:
                    off_in_block = last_off + delta
                    if off_in_block + change_len > length:
                        raise ValueError("PATCH_COMPACT chunk out of range")
                    
                    chunk = all_data[data_ptr : data_ptr + change_len]
                    block[off_in_block:off_in_block+change_len] = chunk
                    
                    data_ptr += change_len
                    last_off = off_in_block
            
            out[pos:pos+length] = block
            pos += length

        elif op == OP_ADD_LZ4:
            raise NotImplementedError("LZ4 not supported on device")

        else:
            raise ValueError(f"unknown opcode: 0x{op:02X}")

    if pos != target_size:
        raise ValueError(f"incomplete output: wrote {pos} / {target_size} bytes")
    return bytes(out)

def file_chunker(path: str, payload: int = 502):
    """按 502B 有效载荷分片读取补丁（模拟设备端流式接收）。"""
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(payload)
            if not chunk:
                break
            yield chunk

def main():
    ap = argparse.ArgumentParser("apply_patch (stream, no decompression)")
    ap.add_argument('--old', required=True, help='旧固件 bin')
    ap.add_argument('--patch', required=True, help='补丁文件')
    ap.add_argument('--out', required=False, help='输出新固件路径（可选，不给则只校验）')
    ap.add_argument('--expect', required=False, help='用于比对的期望新固件（可选）')
    ap.add_argument('--payload', type=int, default=502, help='每片有效载荷，默认 502')
    args = ap.parse_args()

    with open(args.old, 'rb') as f:
        old_bytes = f.read()

    # 读取完整补丁文件
    with open(args.patch, 'rb') as f:
        patch_compressed = f.read()
    
    # 解压补丁
    try:
        patch_data = zlib.decompress(patch_compressed)
    except zlib.error:
        # 可能是未压缩格式
        patch_data = patch_compressed

    # 应用补丁
    new_bytes = apply_patch_in_memory(old_bytes, patch_data)

    # 验证
    if args.expect:
        with open(args.expect, 'rb') as f:
            expect = f.read()
        if new_bytes == expect:
            print("[OK] 重建结果与期望固件一致")
        else:
            print("[FAIL] 重建结果与期望固件不一致")
            print(f"  new_bytes={len(new_bytes)} expect={len(expect)}")
            # 打印首个不一致位置
            i = 0
            m = min(len(new_bytes), len(expect))
            while i < m and new_bytes[i] == expect[i]:
                i += 1
            if i < m:
                print(f"  首个差异偏移: 0x{i:08X} (new=0x{new_bytes[i]:02X}, expect=0x{expect[i]:02X})")
            elif len(new_bytes) != len(expect):
                print(f"  长度不同，较长部分从 0x{m:08X} 起")
            sys.exit(2)

    # 输出
    if args.out:
        with open(args.out, 'wb') as f:
            f.write(new_bytes)
        print(f"[OK] 已写出新固件: {args.out} ({len(new_bytes)} bytes)")
    else:
        print("[OK] 重建成功（未写文件）")

if __name__ == '__main__':
    main()
