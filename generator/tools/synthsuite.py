#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, random, struct, argparse
from typing import List, Tuple

def le16(x): return struct.pack("<H", x & 0xFFFF)
def le32(x): return struct.pack("<I", x & 0xFFFFFFFF)

def _align(x: int, a: int) -> int:
    return (x + (a - 1)) // a * a

def _make_func_sizes_for_target(arch: str, target_bytes: int, seed: int,
                                func_min: int, func_max: int) -> List[int]:
    rnd = random.Random(seed)
    sizes: List[int] = []
    # 估算固定前缀：Thumb 向量表约 256B；ARM 简单前缀约 64B
    prefix = 256 if arch == "thumb" else 64
    # 预留一点杂项空隙
    budget = max(0, target_bytes - prefix - 1024)
    used = 0
    # 为了更可控，尽量用较均匀的尺寸填满，再用一个“压尾”块补齐
    while used < budget:
        sz = rnd.randint(func_min, func_max)
        # 指令对齐：Thumb 至少 2B，对齐到 4B；ARM 4B
        sz = _align(max(2, sz), 4 if arch != "thumb" else 2)
        if used + sz > budget and (budget - used) > 0:
            # 压尾：用剩余预算对齐后填充
            tail = _align(budget - used, 4 if arch != "thumb" else 2)
            if tail >= 2:
                sizes.append(tail)
            break
        sizes.append(sz)
        used += sz
    # 防止过小或为空
    if not sizes:
        sizes = [_align(max(2, func_min), 4 if arch != "thumb" else 2)]
    return sizes

def gen_thumb_func(size: int, flash_lo: int, flash_hi: int, ptr_stride: int = 16, br_stride: int = 8, seed: int = 0) -> bytes:
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        i = len(out)
        if (i % ptr_stride == 0) and (i % 4 == 0) and (i + 4 <= size):
            addr = rnd.randrange(flash_lo, flash_hi, 2) | 1
            out += le32(addr); continue
        if (i % br_stride == 0) and (i + 2 <= size):
            choice = rnd.randint(0, 2)
            if choice == 0:
                imm11 = rnd.randint(0, 0x7FF); out += le16(0xE000 | imm11)
            elif choice == 1:
                cond = rnd.randint(0, 0xE); imm8 = rnd.randint(0, 0xFF); out += le16(0xD000 | (cond << 8) | imm8)
            else:
                out += le16(0xBF00)
            continue
        if i + 2 <= size:
            hw = rnd.randint(1, 0xFFFE); out += le16(hw)
        else:
            out += b"\x00"
    return bytes(out[:size])

def gen_arm_func(size: int, flash_lo: int, flash_hi: int, ptr_stride: int = 16, br_stride: int = 8, seed: int = 0) -> bytes:
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        i = len(out)
        if (i % ptr_stride == 0) and (i + 4 <= size):
            addr = rnd.randrange(flash_lo, flash_hi, 4); out += le32(addr); continue
        if (i % (br_stride*2) == 0) and (i + 4 <= size):
            cond = rnd.randint(0, 0xF) << 28; L = rnd.randint(0, 1) << 24; imm24 = rnd.randint(0, (1<<24)-1)
            out += le32(cond | (0b101 << 25) | L | imm24); continue
        if i + 4 <= size:
            w = rnd.getrandbits(32) or 0xA5A5A5A5; out += le32(w)
        else:
            out += b"\x00" * (size - i)
    return bytes(out[:size])

def build_image(func_sizes: List[int], arch: str, flash_base: int, filler: int = 0, seed: int = 0,
                ptr_stride: int = 16, br_stride: int = 8) -> Tuple[bytes, List[dict]]:
    rnd = random.Random(seed)
    flash_lo = flash_base
    total_est = 256 + sum((s + 16) for s in func_sizes) + 1024
    flash_hi = flash_base + total_est
    image = bytearray()
    symbols = []
    if arch == "thumb":
        sp0 = 0x20020000; rv = flash_base + 256 | 1
        image += le32(sp0) + le32(rv)
        while len(image) < 256: image += le32(0xFFFFFFFF)
    else:
        image += b"\x00" * 64
    for idx, sz in enumerate(func_sizes):
        while (len(image) % 4) != 0: image += b"\x00"
        start = len(image); name = f"func_{idx:04d}"
        seed_i = (seed * 131 + idx * 31337) & 0xFFFFFFFF
        if arch == "thumb":
            body = gen_thumb_func(sz, flash_lo, flash_hi, ptr_stride=ptr_stride, br_stride=br_stride, seed=seed_i)
        else:
            body = gen_arm_func(sz, flash_lo, flash_hi, ptr_stride=ptr_stride, br_stride=br_stride, seed=seed_i)
        image += body
        symbols.append({"name": name, "addr": flash_base + start, "size": sz})
        gap = rnd.randint(0, 16); image += bytes([filler]) * gap
    return bytes(image), symbols

def mutate_small(data: bytes, ratio: float, seed: int = 0) -> bytes:
    rnd = random.Random(seed); b = bytearray(data); n = max(1, int(len(b)*ratio))
    for _ in range(n): i = rnd.randrange(0, len(b)); b[i] ^= rnd.randrange(1, 255)
    return bytes(b)

def reorder_symbols(data: bytes, symbols: List[dict], flash_base: int, seed: int = 0) -> Tuple[bytes, List[dict]]:
    # 依据符号计算“函数区起始偏移”，保留该偏移之前的前缀（如向量表）
    if not symbols:
        return data, symbols
    rnd = random.Random(seed)
    # 以最小地址为函数区起点（Thumb 架构下通常是 flash_base+256）
    min_addr = min(s["addr"] for s in symbols)
    func_base_off = max(0, min_addr - flash_base)
    prefix = data[:func_base_off]

    order = list(range(len(symbols)))
    rnd.shuffle(order)

    out = bytearray(prefix)
    new_syms: List[dict] = []

    for idx, old_i in enumerate(order):
        s = symbols[old_i]
        off = s["addr"] - flash_base
        body = data[off: off + s["size"]]
        # 4B 对齐
        while (len(out) % 4) != 0:
            out += b"\x00"
        start = len(out)
        out += body
        new_syms.append({"name": s["name"], "addr": flash_base + start, "size": s["size"]})
        # 插入少量随机间隙
        out += b"\x00" * rnd.randint(0, 8)

    return bytes(out), new_syms

def save_pair(out_dir: str,
              old_bin: bytes, new_bin: bytes,
              old_syms: List[dict], new_syms: List[dict],
              flash_base_old: int, flash_base_new: int):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "old.bin"), "wb") as f: f.write(old_bin)
    with open(os.path.join(out_dir, "new.bin"), "wb") as f: f.write(new_bin)
    with open(os.path.join(out_dir, "old.json"), "w", encoding="utf-8") as f:
        json.dump({"flash_base": flash_base_old, "symbols": old_syms}, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "new.json"), "w", encoding="utf-8") as f:
        json.dump({"flash_base": flash_base_new, "symbols": new_syms}, f, ensure_ascii=False, indent=2)

def scenario_make(args):
    rnd = random.Random(args.seed)
    # 新：按目标大小或按数量生成函数尺寸
    if args.target_bytes and args.target_bytes > 0:
        func_sizes = _make_func_sizes_for_target(args.arch, args.target_bytes, args.seed,
                                                 args.func_min, args.func_max)
    else:
        func_sizes = [ _align(rnd.randint(args.func_min, args.func_max), 4 if args.arch != "thumb" else 2)
                       for _ in range(args.funcs) ]
    old_base = args.flash_base

    if args.scenario == "small":
        old_bin, old_syms = build_image(func_sizes, args.arch, old_base, seed=args.seed,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)
        new_bin = mutate_small(old_bin, ratio=0.01, seed=args.seed+1)
        new_syms = old_syms
        new_base = old_base

    elif args.scenario == "base":
        old_bin, old_syms = build_image(func_sizes, args.arch, old_base, seed=args.seed,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)
        new_base = old_base + args.base_delta
        new_bin, new_syms = build_image(func_sizes, args.arch, new_base, seed=args.seed,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)

    elif args.scenario == "reorder":
        old_bin, old_syms = build_image(func_sizes, args.arch, old_base, seed=args.seed,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)
        # 传入 flash_base，重排时保留前缀并对齐新符号地址
        new_bin, new_syms = reorder_symbols(old_bin, old_syms, flash_base=old_base, seed=args.seed+2)
        new_base = old_base

    elif args.scenario == "churn":
        old_bin, old_syms = build_image(func_sizes, args.arch, old_base, seed=args.seed,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)
        add = [rnd.randint(64, 256) * 2 for _ in range(max(1, args.funcs//10))]
        func_sizes2 = func_sizes + add
        new_bin, new_syms = build_image(func_sizes2, args.arch, old_base, seed=args.seed+3,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)
        new_base = old_base

    elif args.scenario == "mix":
        old_bin, old_syms = build_image(func_sizes, args.arch, old_base, seed=args.seed,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)
        tmp_base = old_base + args.base_delta
        # 对 func_sizes 做微小扰动
        func_sizes2 = [max(2, s + random.randint(-16, 16)) for s in func_sizes]
        tmp_bin, tmp_syms = build_image(func_sizes2, args.arch, tmp_base, seed=args.seed,
                                        ptr_stride=args.ptr_stride, br_stride=args.br_stride)
        new_bin, new_syms = reorder_symbols(tmp_bin, tmp_syms, flash_base=tmp_base, seed=args.seed+4)
        new_bin = mutate_small(new_bin, ratio=0.01, seed=args.seed+5)
        new_base = tmp_base

    else:
        raise SystemExit(f"unknown scenario: {args.scenario}")

    save_pair(args.out, old_bin, new_bin, old_syms, new_syms,
              flash_base_old=old_base, flash_base_new=new_base)

def main():
    ap = argparse.ArgumentParser(description="合成固件测试集（零依赖）")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--arch", default="thumb", choices=["thumb","arm"], help="架构")
    ap.add_argument("--flash-base", type=lambda x:int(x,0), default=0x08000000, help="FLASH 基址")
    # 新：目标总大小与函数尺寸范围
    ap.add_argument("--target-bytes", type=lambda x:int(x,0), default=0, help="目标镜像总大小（字节，支持 0x 前缀；>0 则忽略 --funcs）")
    ap.add_argument("--funcs", type=int, default=64, help="函数数量（当未指定 --target-bytes 时生效）")
    ap.add_argument("--func-min", type=int, default=256, help="单个函数最小字节数")
    ap.add_argument("--func-max", type=int, default=2048, help="单个函数最大字节数")
    ap.add_argument("--seed", type=int, default=1, help="随机种子")
    ap.add_argument("--scenario", default="small", choices=["small","base","reorder","churn","mix"], help="场景")
    ap.add_argument("--base-delta", type=lambda x:int(x,0), default=0x2000, help="基址迁移偏移（S2/S5）")
    ap.add_argument("--ptr-stride", type=int, default=16, help="指针字面量步距（越小重定位越强）")
    ap.add_argument("--br-stride", type=int, default=8, help="分支半字步距")
    args = ap.parse_args()
    scenario_make(args)

if __name__ == "__main__":
    main()