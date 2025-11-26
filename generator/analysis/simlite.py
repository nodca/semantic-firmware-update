from typing import Set, Tuple
import struct
import inspect
import zlib

SRAM_DEFAULT = (0x20000000, 0x20080000)  # 常见 Cortex-M SRAM 范围，可按需调整

def _le16(b: bytes, i: int) -> int:
    return b[i] | (b[i+1] << 8)

def _le32(b: bytes, i: int) -> int:
    return b[i] | (b[i+1] << 8) | (b[i+2] << 16) | (b[i+3] << 24)

def _read_u16(bs: bytes, i: int, endian: str) -> int:
    if i + 2 > len(bs):
        return -1
    return struct.unpack(">H" if endian == "be" else "<H", bs[i:i+2])[0]

def _read_u32(bs: bytes, i: int, endian: str) -> int:
    if i + 4 > len(bs):
        return -1
    return struct.unpack(">I" if endian == "be" else "<I", bs[i:i+4])[0]

# ---------------- Thumb 分支粗判 ----------------
def _is_thumb16_branch(h: int) -> bool:
    # B<cond> 分支指令: 1101 cccc iiii iiii (cond != 1111)
    if (h & 0xF000) == 0xD000 and ((h >> 8) & 0xF) != 0xF:
        return True
    # 无条件 B 分支: 11100 iiiiiiiiii
    if (h & 0xF800) == 0xE000:
        return True
    # CBZ/CBNZ（粗略）
    if (h & 0xFF00) in (0xB100, 0xB900):
        return True
    return False

def _is_thumb32_branch(h1: int, h2: int) -> bool:
    # Thumb-2 BL/BLX/JAL（非常粗略）：两个半字的高 5 位类似 1111x
    if (h1 & 0xF800) in (0xF000, 0xF800) and (h2 & 0xF800) in (0xF000, 0xF800):
        return True
    return False

def find_thumb_branch_sites(code: bytes, endian: str = "le") -> Set[int]:
    sites: Set[int] = set()
    n = len(code)
    for i in range(0, n - 1, 2):  # 半字对齐
        h1 = _read_u16(code, i, endian)
        if h1 < 0:
            break
        if _is_thumb16_branch(h1):
            sites.add(i)
        if i + 3 < n:
            h2 = _read_u16(code, i + 2, endian)
            if _is_thumb32_branch(h1, h2):
                sites.add(i)
    return sites

# ---------------- ARM 分支粗判 ----------------
def _is_arm_b_bl(w: int) -> bool:
    # ARM 状态下的 B/BL: cond (31:28), 101 (27:25), L (24), imm24 (23:0)
    return ((w >> 25) & 0b111) == 0b101

def _is_arm_bx_blx_reg(w: int) -> bool:
    # BX 寄存器间接跳转: 0001 0010 1111 1111 1111 0001 xxxx -> 0x012FFF10
    if (w & 0x0FFFFFF0) == 0x012FFF10:
        return True
    # BLX 寄存器间接跳转: 0001 0010 1111 1111 1111 0011 xxxx -> 0x012FFF30
    if (w & 0x0FFFFFF0) == 0x012FFF30:
        return True
    return False

def find_arm_branch_sites(code: bytes, endian: str = "le") -> Set[int]:
    sites: Set[int] = set()
    n = len(code)
    for i in range(0, n - 3, 4):  # 4 字节对齐
        w = _read_u32(code, i, endian)
        if w < 0:
            break
        if _is_arm_b_bl(w) or _is_arm_bx_blx_reg(w):
            sites.add(i)
    return sites

# ---------------- 指针样点与掩蔽 ----------------
def find_ptr_sites(code: bytes, flash_lo: int, flash_hi: int,
                   sram: Tuple[int, int] = SRAM_DEFAULT, endian: str = "le") -> Set[int]:
    sites: Set[int] = set()
    n = len(code)
    for i in range(0, n - 3, 4):  # 4 字节对齐
        w = _read_u32(code, i, endian)
        if flash_lo <= w < flash_hi or (sram[0] <= w < sram[1]):
            sites.add(i)
    return sites

def mask_ptr_like(code: bytes, ptr_sites: Set[int]) -> bytes:
    if not ptr_sites:
        return code
    b = bytearray(code)
    for i in ptr_sites:
        if i + 3 < len(b):
            b[i:i+4] = b"\x00\x00\x00\x00"
    return bytes(b)

# ---------------- k-gram 结构相似度（稳定哈希） ----------------
def kgram_hashes(data: bytes, k: int, step: int) -> Set[int]:
    if k <= 0 or len(data) < k:
        return set()
    s: Set[int] = set()
    for i in range(0, len(data) - k + 1, step):
        h = zlib.crc32(data[i:i+k]) & 0xFFFFFFFF
        s.add(h)
    return s

def _jaccard(a: Set[int], b: Set[int]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0

# ---------------- 模式判别与相似度融合 ----------------
def guess_arch_mode(code: bytes, flash_lo: int, flash_hi: int) -> str:
    # 简单向量表启发：SP 初值在 SRAM，Reset 向量落在 FLASH 且 LSB=1 => Thumb
    if len(code) >= 8:
        sp0 = _le32(code, 0)
        rv = _le32(code, 4)
        if (SRAM_DEFAULT[0] <= sp0 < SRAM_DEFAULT[1]) and (flash_lo <= (rv & ~1) < flash_hi) and (rv & 1) == 1:
            return "thumb"
    # 统计前 4KB 的分支命中率，择优
    window = code[:min(len(code), 4096)]
    thumb_hits = len(find_thumb_branch_sites(window))
    arm_hits = len(find_arm_branch_sites(window))
    # 归一化到各自的“指令数”（半字/字）
    thumb_den = max(1, len(window) // 2)
    arm_den = max(1, len(window) // 4)
    if (thumb_hits / thumb_den) > (arm_hits / arm_den) * 1.2:
        return "thumb"
    if (arm_hits / arm_den) > (thumb_hits / thumb_den) * 1.2:
        return "arm"
    return "thumb"  # 默认 Thumb

# 融合权重（更偏向结构），可按需微调
_W_KGRAM = 0.60
_W_SITES = 0.25
_W_DENS  = 0.15

def reloc_aware_similarity_lite_breakdown(a: bytes, b: bytes, *, flash_lo: int, flash_hi: int,
                                          mode: str = "auto", endian: str = "le"):
    if not a or not b:
        return {"sim": 0.0, "s_kgram": 0.0, "s_sites": 0.0, "s_bd": 0.0, "mode": mode}

    if mode == "thumb":
        br_o = find_thumb_branch_sites(a, endian=endian); br_n = find_thumb_branch_sites(b, endian=endian)
        k, step = 16, 2
        dens_base_o = max(1, len(a)//2); dens_base_n = max(1, len(b)//2)
    elif mode == "arm":
        br_o = find_arm_branch_sites(a, endian=endian); br_n = find_arm_branch_sites(b, endian=endian)
        k, step = 16, 4
        dens_base_o = max(1, len(a)//4); dens_base_n = max(1, len(b)//4)
    else:
        br_o = set(); br_n = set()
        k, step = 16, 4
        dens_base_o = max(1, len(a)); dens_base_n = max(1, len(b))

    ptr_o = find_ptr_sites(a, flash_lo, flash_hi, endian=endian)
    ptr_n = find_ptr_sites(b, flash_lo, flash_hi, endian=endian)
    s_sites = _jaccard(br_o | ptr_o, br_n | ptr_n)

    old_m = mask_ptr_like(a, ptr_o)
    new_m = mask_ptr_like(b, ptr_n)
    kg_o = kgram_hashes(old_m, k=k, step=step)
    kg_n = kgram_hashes(new_m, k=k, step=step)
    s_kgram = _jaccard(kg_o, kg_n)

    bd_o = len(br_o) / dens_base_o
    bd_n = len(br_n) / dens_base_n
    s_bd = 1.0 - min(1.0, abs(bd_o - bd_n))

    i = 0
    step = 2 if mode.startswith("thumb") else 4
    sites = hits = 0
    while i + 4 <= len(a) and i + 4 <= len(b):
        wa = _read_u32(a, i, endian)
        wb = _read_u32(b, i, endian)
        if flash_lo <= wa < flash_hi: sites += 1
        if flash_lo <= wb < flash_hi: sites += 1
        if (flash_lo <= wa < flash_hi) and (flash_lo <= wb < flash_hi):
            hits += 1
        i += step

    sim = _W_KGRAM * s_kgram + _W_SITES * s_sites + _W_DENS * s_bd
    return {"mode": mode, "sim": sim, "s_kgram": s_kgram, "s_sites": s_sites, "s_bd": s_bd}

def reloc_aware_similarity_lite(old: bytes,
                                new: bytes,
                                old_addr: int = None,
                                new_addr: int = None,
                                mode: str = "auto",
                                endian: str = "le"):
    """
    兼容不同版本的 breakdown 签名：
    - breakdown(old, new)
    - breakdown(old, new, flash_lo=None, flash_hi=None, mode='auto', endian='le')
    """
    flash_lo = flash_hi = None
    if old_addr is not None and new_addr is not None:
        lo = min(old_addr, new_addr)
        hi = max(old_addr + len(old), new_addr + len(new))
        flash_lo, flash_hi = lo, hi

    brk = reloc_aware_similarity_lite_breakdown
    try:
        sig = inspect.signature(brk)
        if len(sig.parameters) <= 2:
            br = brk(old, new)
        else:
            br = brk(old, new, flash_lo=flash_lo, flash_hi=flash_hi, mode=mode, endian=endian)
    except TypeError:
        # 兜底：尝试旧的按位置参数调用，再退回最简调用
        try:
            br = brk(old, new, flash_lo, flash_hi, mode)
        except TypeError:
            br = brk(old, new)

    return br["sim"] if isinstance(br, dict) and "sim" in br else float(br)
