from typing import Tuple


def uleb128_encode(n: int) -> bytes:
    if n < 0:
        raise ValueError("uleb128 only supports non-negative integers")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def uleb128_len(n: int) -> int:
    if n < 0:
        raise ValueError("uleb128 only supports non-negative integers")
    if n == 0:
        return 1
    l = 0
    while n:
        l += 1
        n >>= 7
    return l


def uleb128_decode(buf: bytes, i: int) -> Tuple[int, int, int]:
    """Decode uleb128; return (value, new_index, length)."""
    val = 0
    shift = 0
    start = i
    while True:
        b = buf[i]
        val |= (b & 0x7F) << shift
        shift += 7
        i += 1
        if not (b & 0x80):
            break
    return val, i, i - start
