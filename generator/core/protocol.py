import struct
import zlib
from typing import List, Tuple, Union
from .utils import uleb128_encode, uleb128_len

# 指令格式
OP_END = 0x00
OP_COPY = 0x01
OP_ADD = 0x02
OP_PATCH_FROM_OLD = 0x04
OP_FILL = 0x06
OP_PATCH_COMPACT = 0x07
OP_COPY_RELOC = 0x08

MAGIC = b'DPT1'
HEADER_FMT = '<4sHII'
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# 指令中间表示
class CopyOp:
    def __init__(self, old_off: int, length: int, new_off: int):
        self.old_off = old_off
        self.length = length
        self.new_off = new_off
        self.type = 'COPY'

class AddOp:
    def __init__(self, data: bytes, new_off: int):
        self.data = data
        self.new_off = new_off
        self.type = 'ADD'

class FillOp:
    def __init__(self, byte_val: int, length: int, new_off: int):
        self.byte_val = byte_val & 0xFF
        self.length = length
        self.new_off = new_off
        self.type = 'FILL'

class PatchOp:
    def __init__(self, old_off: int, length: int, changes: List[Tuple[int, bytes]], new_off: int):
        self.old_off = old_off
        self.length = length
        self.changes = changes
        self.new_off = new_off
        self.type = 'PATCH'

class PatchCompactOp:
    def __init__(self, old_off: int, length: int, changes: List[Tuple[int, bytes]], new_off: int):
        self.old_off = old_off
        self.length = length
        self.changes = changes
        self.new_off = new_off
        self.type = 'PATCH_COMPACT'

class CopyRelocOp:
    def __init__(self, old_off: int, length: int, relocs: List[Tuple[int, bytes]], new_off: int):
        self.old_off = old_off
        self.length = length
        self.relocs = relocs
        self.new_off = new_off
        self.type = 'COPY_RELOC'

class PatchBuilder:
    def __init__(self, target_size: int):
        self.target_size = target_size
        self.stats = {'COPY':0, 'COPY_RELOC':0, 'ADD':0, 'PATCH':0, 'FILL':0, 'PATCH_COMPACT':0}
        self._pending_add = bytearray()
        self.instructions = []  # 存储中间表示的指令
        self._meta_bytes = HEADER_SIZE  # 预先包含头部
        self._data_bytes = 0
        self._terminal_overhead = 1  # OP_END
        self._new_pos = 0
        
    def header(self):
        # 头部信息暂不处理，在最终编码时添加
        pass

    def current_size(self):
        """返回当前补丁已编码的字节数（未压缩）"""
        return self._meta_bytes + self._data_bytes + self._terminal_overhead

    def flush_add(self):
        if self._pending_add:
            data = bytes(self._pending_add)
            self._append_add(data)
            self.stats['ADD'] += 1
            self._pending_add.clear()

    def add_literal(self, data: bytes):
        if data:
            self._pending_add += data

    def op_copy(self, old_off: int, length: int):
        self.flush_add()
        self._append_copy(old_off, length)
        self.stats['COPY'] += 1

    def op_copy_reloc(self, old_off: int, length: int, relocs: List[Tuple[int, int]]):
        self.flush_add()
        self._append_copy_reloc(old_off, length, relocs)
        self.stats['COPY_RELOC'] += 1

    def op_add(self, data: bytes):
        self._emit_add_raw(data)

    def op_fill(self, byte_val: int, length: int):
        self.flush_add()
        self._append_fill(byte_val, length)
        self.stats['FILL'] += 1

    def op_patch_from_old(self, old_off: int, length: int, changes: List[Tuple[int, bytes]]):
        self.flush_add()
        self._append_patch(old_off, length, changes)
        self.stats['PATCH'] += 1

    def op_patch_compact(self, old_off: int, length: int, changes: List[Tuple[int, bytes]]):
        self.flush_add()
        self._append_patch_compact(old_off, length, changes)
        self.stats['PATCH_COMPACT'] += 1

    def end(self):
        self.flush_add()
        # 在最终编码时添加OP_END

    def _emit_add_raw(self, data: bytes):
        """直接发射一条 ADD 指令，绕过当前挂起的 ADD 缓冲。"""
        self.flush_add()
        if not data:
            return
        self._append_add(bytes(data))
        self.stats['ADD'] += 1

    def _optimize_instructions(self):
        """优化指令序列，减少碎片"""
        if not self.instructions:
            return
            
        optimized = []
        i = 0
        
        while i < len(self.instructions):
            current = self.instructions[i]
            
            # 合并连续的COPY指令
            if isinstance(current, CopyOp):
                copies_to_merge = [current]
                j = i + 1
                
                while j < len(self.instructions) and isinstance(self.instructions[j], CopyOp):
                    next_copy = self.instructions[j]
                    expected_new = copies_to_merge[-1].new_off + copies_to_merge[-1].length
                    expected_old = copies_to_merge[-1].old_off + copies_to_merge[-1].length
                    if next_copy.old_off == expected_old and next_copy.new_off == expected_new:
                        copies_to_merge.append(next_copy)
                        j += 1
                    else:
                        break
                
                if len(copies_to_merge) > 1:
                    # 合并所有连续的COPY
                    total_length = sum(copy.length for copy in copies_to_merge)
                    optimized.append(CopyOp(current.old_off, total_length, current.new_off))
                    i = j
                else:
                    # 检查是否需要将短COPY转为ADD
                    if current.length <= 8:  # 如果COPY很短，可能ADD更节省
                        # 这里需要旧固件数据，暂时跳过
                        optimized.append(current)
                        i += 1
                    else:
                        optimized.append(current)
                        i += 1
            
            # 合并连续的ADD指令
            elif isinstance(current, AddOp):
                adds_to_merge = [current]
                j = i + 1
                
                while j < len(self.instructions) and isinstance(self.instructions[j], AddOp):
                    adds_to_merge.append(self.instructions[j])
                    j += 1
                
                if len(adds_to_merge) > 1:
                    # 合并所有连续的ADD
                    merged_data = b''.join(add.data for add in adds_to_merge)
                    optimized.append(AddOp(merged_data, current.new_off))
                    i = j
                else:
                    optimized.append(current)
                    i += 1
            
            # 其他指令保持不变
            else:
                optimized.append(current)
                i += 1
        
        self.instructions = optimized
        # 重新统计指令数量
        self._recount_stats()
    
    def _recount_stats(self):
        """重新统计指令数量"""
        self.stats = {'COPY':0, 'COPY_RELOC':0, 'ADD':0, 'PATCH':0, 'FILL':0, 'PATCH_COMPACT':0}
        for instr in self.instructions:
            if isinstance(instr, CopyOp):
                self.stats['COPY'] += 1
            elif isinstance(instr, AddOp):
                self.stats['ADD'] += 1
            elif isinstance(instr, FillOp):
                self.stats['FILL'] += 1
            elif isinstance(instr, PatchOp):
                self.stats['PATCH'] += 1
            elif isinstance(instr, PatchCompactOp):
                self.stats['PATCH_COMPACT'] += 1
            elif isinstance(instr, CopyRelocOp):
                self.stats['COPY_RELOC'] += 1
    
    def _encode_instructions(self):
        """将中间表示的指令编码为二进制"""
        buf = bytearray()
        
        # 添加头部
        buf += struct.pack(HEADER_FMT, MAGIC, 0, self.target_size, 0)
        
        # 编码所有指令
        for instr in self.instructions:
            if isinstance(instr, CopyOp):
                buf.append(OP_COPY)
                buf += uleb128_encode(instr.old_off)
                buf += uleb128_encode(instr.length)
            elif isinstance(instr, AddOp):
                buf.append(OP_ADD)
                buf += uleb128_encode(len(instr.data))
                buf += instr.data
            elif isinstance(instr, FillOp):
                buf.append(OP_FILL)
                buf += uleb128_encode(instr.byte_val & 0xFF)
                buf += uleb128_encode(instr.length)
            elif isinstance(instr, PatchOp):
                buf.append(OP_PATCH_FROM_OLD)
                buf += uleb128_encode(instr.old_off)
                buf += uleb128_encode(instr.length)
                buf += uleb128_encode(len(instr.changes))
                last = 0
                for off, chunk in instr.changes:
                    delta = off - last
                    buf += uleb128_encode(delta)
                    buf += uleb128_encode(len(chunk))
                    buf += chunk
                    last = off
            elif isinstance(instr, PatchCompactOp):
                buf.append(OP_PATCH_COMPACT)
                buf += uleb128_encode(instr.old_off)
                buf += uleb128_encode(instr.length)
                nchanges = len(instr.changes)
                buf += uleb128_encode(nchanges)
                
                if nchanges > 0:
                    change_len = len(instr.changes[0][1])
                    buf += uleb128_encode(change_len)
                    
                    last = 0
                    for off, _ in instr.changes:
                        delta = off - last
                        buf += uleb128_encode(delta)
                        last = off

                    for _, chunk in instr.changes:
                        buf += chunk
            elif isinstance(instr, CopyRelocOp):
                buf.append(OP_COPY_RELOC)
                buf += uleb128_encode(instr.old_off)
                buf += uleb128_encode(instr.length)
                buf += uleb128_encode(len(instr.relocs))
                last = 0
                for off, data in instr.relocs:
                    buf += uleb128_encode(off - last)
                    buf += data
                    last = off
        
        # 添加结束指令
        buf.append(OP_END)
        
        return bytes(buf)
    
    def bytes(self, compress: bool = False) -> bytes:
        # 先优化指令
        self._optimize_instructions()
        
        # 编码为二进制
        raw = self._encode_instructions()
        
        if compress:
            return zlib.compress(raw, level=9)
        return raw

    # ---------- Internal helpers for size tracking ----------
    def _advance_new_cursor(self, length: int):
        self._new_pos += length

    def _record_size(self, meta: int, data: int = 0):
        self._meta_bytes += meta
        self._data_bytes += data

    def _append_copy(self, old_off: int, length: int):
        self.instructions.append(CopyOp(old_off, length, self._new_pos))
        self._record_size(1 + uleb128_len(old_off) + uleb128_len(length))
        self._advance_new_cursor(length)

    def _append_add(self, data: bytes):
        literal_len = len(data)
        self.instructions.append(AddOp(data, self._new_pos))
        self._record_size(1 + uleb128_len(literal_len), literal_len)
        self._advance_new_cursor(literal_len)

    def _append_fill(self, byte_val: int, length: int):
        self.instructions.append(FillOp(byte_val, length, self._new_pos))
        self._record_size(1 + uleb128_len(byte_val & 0xFF) + uleb128_len(length))
        self._advance_new_cursor(length)

    def _append_patch(self, old_off: int, length: int, changes: List[Tuple[int, bytes]]):
        self.instructions.append(PatchOp(old_off, length, changes, self._new_pos))
        meta = 1 + uleb128_len(old_off) + uleb128_len(length) + uleb128_len(len(changes))
        data_bytes = 0
        last = 0
        for off, chunk in changes:
            delta = off - last
            meta += uleb128_len(delta) + uleb128_len(len(chunk))
            data_bytes += len(chunk)
            last = off
        self._record_size(meta, data_bytes)
        self._advance_new_cursor(length)

    def _append_patch_compact(self, old_off: int, length: int, changes: List[Tuple[int, bytes]]):
        self.instructions.append(PatchCompactOp(old_off, length, changes, self._new_pos))
        meta = 1 + uleb128_len(old_off) + uleb128_len(length) + uleb128_len(len(changes))
        data_bytes = 0
        if changes:
            change_len = len(changes[0][1])
            meta += uleb128_len(change_len)
            last = 0
            for off, _chunk in changes:
                delta = off - last
                meta += uleb128_len(delta)
                last = off
            data_bytes = change_len * len(changes)
        self._record_size(meta, data_bytes)
        self._advance_new_cursor(length)

    def _append_copy_reloc(self, old_off: int, length: int, relocs: List[Tuple[int, bytes]]):
        self.instructions.append(CopyRelocOp(old_off, length, relocs, self._new_pos))
        meta = 1 + uleb128_len(old_off) + uleb128_len(length) + uleb128_len(len(relocs))
        last = 0
        for off, _ in relocs:
            meta += uleb128_len(off - last) + 4
            last = off
        self._record_size(meta, 0)
        self._advance_new_cursor(length)


def estimate_copy_bytes(old_off: int, length: int) -> int:
    """
    估算一条 COPY 指令的补丁占用（仅元数据字节）。
    与 PatchBuilder 内部统计保持一致。
    """
    return 1 + uleb128_len(old_off) + uleb128_len(length)


def estimate_add_bytes(length: int) -> int:
    """
    估算一条 ADD 指令的总补丁大小（元数据 + literal 数据）。
    """
    return 1 + uleb128_len(length) + length
