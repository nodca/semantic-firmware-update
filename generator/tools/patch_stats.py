import zlib
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from generator.core.protocol import (
    OP_COPY,
    OP_ADD,
    OP_DIFF,
    OP_PATCH_FROM_OLD,
    OP_FILL,
    OP_PATCH_COMPACT,
    OP_PATCH_DIFF,
    OP_END,
    HEADER_SIZE,
)


def _raw_bytes(patch_bytes: bytes) -> bytes:
    try:
        return zlib.decompress(patch_bytes)
    except Exception:
        return patch_bytes


def _read_uleb128(buf: bytes, idx: int) -> Tuple[int, int, int]:
    val = 0
    shift = 0
    start = idx
    while True:
        b = buf[idx]
        val |= (b & 0x7F) << shift
        shift += 7
        idx += 1
        if not (b & 0x80):
            break
    return val, idx, idx - start


def count_opcode_bytes(patch_bytes: bytes) -> Counter:
    """Return total bytes consumed per opcode (metadata + data)."""
    raw = _raw_bytes(patch_bytes)
    op_bytes = Counter()
    i = HEADER_SIZE
    while i < len(raw):
        op = raw[i]
        name = _op_name(op)
        start = i
        i += 1
        if op == OP_COPY:
            for _ in range(2):
                _, i, _ = _read_uleb128(raw, i)
        elif op == OP_ADD:
            lit_len, i2, _ = _read_uleb128(raw, i)
            i = i2 + lit_len
        elif op == OP_DIFF:
            # old_off, length, diff_data
            _, i, _ = _read_uleb128(raw, i)  # old_off
            length, i, _ = _read_uleb128(raw, i)  # length
            i += length  # diff_data
        elif op == OP_PATCH_FROM_OLD:
            # old_off, length, nchanges, [delta, clen, data]...
            _, i, _ = _read_uleb128(raw, i)  # old_off
            _, i, _ = _read_uleb128(raw, i)  # length
            nchanges, i, _ = _read_uleb128(raw, i)  # nchanges
            for _ in range(nchanges):
                _, i, _ = _read_uleb128(raw, i)  # delta
                clen, i, _ = _read_uleb128(raw, i)  # clen
                i += clen  # data
        elif op == OP_PATCH_COMPACT:
            # old_off, length, nchanges, [change_len, deltas..., data...]
            _, i, _ = _read_uleb128(raw, i)  # old_off
            _, i, _ = _read_uleb128(raw, i)  # length
            nchanges, i, _ = _read_uleb128(raw, i)  # nchanges
            if nchanges > 0:
                change_len, i, _ = _read_uleb128(raw, i)
                for _ in range(nchanges):
                    _, i, _ = _read_uleb128(raw, i)
                i += nchanges * change_len
        elif op == OP_PATCH_DIFF:
            # 与 PATCH_FROM_OLD 格式相同
            _, i, _ = _read_uleb128(raw, i)  # old_off
            _, i, _ = _read_uleb128(raw, i)  # length
            nchanges, i, _ = _read_uleb128(raw, i)  # nchanges
            for _ in range(nchanges):
                _, i, _ = _read_uleb128(raw, i)  # delta
                clen, i, _ = _read_uleb128(raw, i)  # clen
                i += clen  # data
        elif op == OP_FILL:
            for _ in range(2):
                _, i, _ = _read_uleb128(raw, i)
        elif op == OP_END:
            break
        else:
            break
        op_bytes[name] += (i - start)
    other = len(raw) - sum(op_bytes.values())
    if other > 0:
        op_bytes["OTHER"] += other
    return op_bytes


def count_meta_data_bytes(patch_bytes: bytes) -> Tuple[Counter, Counter]:
    """Return (meta_bytes, data_bytes) counters per opcode."""
    raw = _raw_bytes(patch_bytes)
    meta = Counter()
    data = Counter()
    i = HEADER_SIZE
    while i < len(raw):
        op = raw[i]
        name = _op_name(op)
        i += 1
        meta_len = 1
        if op == OP_COPY:
            for _ in range(2):
                _, i2, l = _read_uleb128(raw, i)
                meta_len += l
                i = i2
        elif op == OP_ADD:
            l, i2, llen = _read_uleb128(raw, i)
            meta_len += llen
            i = i2
            data[name] += l
            i += l
        elif op == OP_DIFF:
            # old_off, length, diff_data
            _, i2, l1 = _read_uleb128(raw, i)  # old_off
            meta_len += l1
            i = i2
            length, i2, l2 = _read_uleb128(raw, i)  # length
            meta_len += l2
            i = i2
            data[name] += length
            i += length
        elif op == OP_PATCH_FROM_OLD:
            # old_off, length, nchanges, [delta, clen, data]...
            _, i2, l = _read_uleb128(raw, i)  # old_off
            meta_len += l
            i = i2
            _, i2, l = _read_uleb128(raw, i)  # length
            meta_len += l
            i = i2
            nchanges, i2, l0 = _read_uleb128(raw, i)  # nchanges
            meta_len += l0
            i = i2
            for _ in range(nchanges):
                _, i2, l1 = _read_uleb128(raw, i)  # delta
                meta_len += l1
                i = i2
                clen, i2, l2 = _read_uleb128(raw, i)  # clen
                meta_len += l2
                i = i2
                data[name] += clen
                i += clen
        elif op == OP_PATCH_COMPACT:
            # old_off, length, nchanges, [change_len, deltas..., data...]
            _, i2, l = _read_uleb128(raw, i)  # old_off
            meta_len += l
            i = i2
            _, i2, l = _read_uleb128(raw, i)  # length
            meta_len += l
            i = i2
            nchanges, i2, l0 = _read_uleb128(raw, i)  # nchanges
            meta_len += l0
            i = i2
            if nchanges > 0:
                change_len, i2, llen = _read_uleb128(raw, i)
                meta_len += llen
                i = i2
                for _ in range(nchanges):
                    _, i2, l = _read_uleb128(raw, i)
                    meta_len += l
                    i = i2
                data[name] += nchanges * change_len
                i += nchanges * change_len
        elif op == OP_PATCH_DIFF:
            # 与 PATCH_FROM_OLD 格式相同
            _, i2, l = _read_uleb128(raw, i)  # old_off
            meta_len += l
            i = i2
            _, i2, l = _read_uleb128(raw, i)  # length
            meta_len += l
            i = i2
            nchanges, i2, l0 = _read_uleb128(raw, i)  # nchanges
            meta_len += l0
            i = i2
            for _ in range(nchanges):
                _, i2, l1 = _read_uleb128(raw, i)  # delta
                meta_len += l1
                i = i2
                clen, i2, l2 = _read_uleb128(raw, i)  # clen
                meta_len += l2
                i = i2
                data[name] += clen
                i += clen
        elif op == OP_FILL:
            for _ in range(2):
                _, i2, l = _read_uleb128(raw, i)
                meta_len += l
                i = i2
        elif op == OP_END:
            meta["END"] += 1
            break
        else:
            break
        meta[name] += meta_len
    return meta, data


def collect_op_stats(patch_bytes: bytes) -> Dict[str, List[int]]:
    raw = _raw_bytes(patch_bytes)
    stats = defaultdict(list)
    i = HEADER_SIZE
    while i < len(raw):
        op = raw[i]
        start = i
        i += 1
        if op == OP_COPY:
            for _ in range(2):
                _, i, _ = _read_uleb128(raw, i)
            stats["COPY"].append(i - start)
        elif op == OP_ADD:
            l, i2, _ = _read_uleb128(raw, i)
            i = i2 + l
            stats["ADD"].append(l)
        elif op == OP_DIFF:
            _, i, _ = _read_uleb128(raw, i)  # old_off
            length, i, _ = _read_uleb128(raw, i)  # length
            i += length
            stats["DIFF"].append(length)
        elif op == OP_PATCH_FROM_OLD:
            _, i, _ = _read_uleb128(raw, i)
            plen, i, _ = _read_uleb128(raw, i)
            nchanges, i, _ = _read_uleb128(raw, i)
            for _ in range(nchanges):
                _, i, _ = _read_uleb128(raw, i)
                clen, i, _ = _read_uleb128(raw, i)
                i += clen
            stats["PATCH"].append(i - start)
        elif op == OP_PATCH_COMPACT:
            _, i, _ = _read_uleb128(raw, i)
            plen, i, _ = _read_uleb128(raw, i)
            nchanges, i, _ = _read_uleb128(raw, i)
            if nchanges > 0:
                change_len, i, _ = _read_uleb128(raw, i)
                for _ in range(nchanges):
                    _, i, _ = _read_uleb128(raw, i)
                i += nchanges * change_len
            stats["PATCH_COMPACT"].append(i - start)
        elif op == OP_PATCH_DIFF:
            _, i, _ = _read_uleb128(raw, i)
            plen, i, _ = _read_uleb128(raw, i)
            nchanges, i, _ = _read_uleb128(raw, i)
            for _ in range(nchanges):
                _, i, _ = _read_uleb128(raw, i)
                clen, i, _ = _read_uleb128(raw, i)
                i += clen
            stats["PATCH_DIFF"].append(i - start)
        elif op == OP_FILL:
            for _ in range(2):
                _, i, _ = _read_uleb128(raw, i)
            stats["FILL"].append(i - start)
        elif op == OP_END:
            break
        else:
            break
    return stats


def _op_name(op: int) -> str:
    return {
        OP_COPY: "COPY",
        OP_ADD: "ADD",
        OP_DIFF: "DIFF",
        OP_PATCH_FROM_OLD: "PATCH",
        OP_FILL: "FILL",
        OP_PATCH_COMPACT: "PATCH_COMPACT",
        OP_PATCH_DIFF: "PATCH_DIFF",
        OP_END: "END",
    }.get(op, "OTHER")
